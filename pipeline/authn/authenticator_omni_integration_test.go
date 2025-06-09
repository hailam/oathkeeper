package authn_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/sjson"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/oathkeeper/internal"
	. "github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"
)

func TestOmniAuthenticatorIntegration(t *testing.T) {
	conf := internal.NewConfigurationWithDefaults(configx.SkipValidation())
	logger := logrusx.New("test", "1")
	authenticator := NewAuthenticatorOmni(conf, logger, trace.NewNoopTracerProvider())

	// Mock services
	kratosServer := createMockKratosServer()
	defer kratosServer.Close()

	hydraServer := createMockHydraServer()
	defer hydraServer.Close()

	baseConfig := fmt.Sprintf(`{
		"kratos": {
			"check_session_url": "%s/sessions/whoami"
		},
		"hydra": {
			"introspection_url": "%s/oauth2/introspect",
			"scope_strategy": "exact"
		},
		"cache": {
			"enabled": true,
			"ttl": "1s"
		}
	}`, kratosServer.URL, hydraServer.URL)

	t.Run("scenario=kratos_session_workflow", func(t *testing.T) {
		t.Run("case=valid_session_cookie", func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.AddCookie(&http.Cookie{
				Name:  "ory_kratos_session",
				Value: "valid_session_123",
			})

			session := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session, []byte(baseConfig), nil)

			require.NoError(t, err)
			assert.Equal(t, "user-123", session.Subject)
			assert.Equal(t, "kratos_cookie", session.Extra["auth_method"])
			assert.Equal(t, "user@example.com", session.Extra["traits"].(map[string]interface{})["email"])
		})

		t.Run("case=valid_session_token", func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.Header.Set("Authorization", "Bearer ory_st_valid_token_456")

			session := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session, []byte(baseConfig), nil)

			require.NoError(t, err)
			assert.Equal(t, "user-456", session.Subject)
			assert.Equal(t, "kratos_token", session.Extra["auth_method"])
		})

		t.Run("case=invalid_session", func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.AddCookie(&http.Cookie{
				Name:  "ory_kratos_session",
				Value: "invalid_session",
			})

			session := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session, []byte(baseConfig), nil)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "Authenticator not responsible")
		})
	})

	t.Run("scenario=hydra_token_workflow", func(t *testing.T) {
		t.Run("case=valid_access_token", func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.Header.Set("Authorization", "Bearer ory_at_valid_access_token")

			session := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session, []byte(baseConfig), nil)

			require.NoError(t, err)
			assert.Equal(t, "client-123", session.Subject)
			assert.Equal(t, "hydra_token", session.Extra["auth_method"])
			assert.Equal(t, "test-client", session.Extra["client_id"])
		})

		t.Run("case=token_with_required_scope", func(t *testing.T) {
			configWithScope, _ := sjson.Set(baseConfig, "hydra.required_scope", []string{"read"})

			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.Header.Set("Authorization", "Bearer ory_at_token_with_read_scope")

			session := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session, []byte(configWithScope), nil)

			require.NoError(t, err)
			assert.Equal(t, "user-with-scope", session.Subject)
		})

		t.Run("case=token_missing_required_scope", func(t *testing.T) {
			configWithScope, _ := sjson.Set(baseConfig, "hydra.required_scope", []string{"admin"})

			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.Header.Set("Authorization", "Bearer ory_at_token_with_read_scope")

			session := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session, []byte(configWithScope), nil)

			require.Error(t, err)
		})

		t.Run("case=inactive_token", func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.Header.Set("Authorization", "Bearer ory_at_inactive_token")

			session := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session, []byte(baseConfig), nil)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "Authenticator not responsible")
		})
	})

	t.Run("scenario=caching_behavior", func(t *testing.T) {
		// Track call counts to mock services
		kratosCallCount := 0
		hydraCallCount := 0

		// Create servers that track calls
		kratosTrackingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			kratosCallCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":     "cached-session",
				"active": true,
				"identity": map[string]interface{}{
					"id": "cached-user",
					"traits": map[string]interface{}{
						"email": "cached@example.com",
					},
				},
			})
		}))
		defer kratosTrackingServer.Close()

		hydraTrackingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hydraCallCount++
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active":    true,
				"client_id": "cached-client",
				"sub":       "cached-token-user",
				"scope":     "read",
				"exp":       time.Now().Add(time.Hour).Unix(),
			})
		}))
		defer hydraTrackingServer.Close()

		cachingConfig := fmt.Sprintf(`{
			"kratos": {
				"check_session_url": "%s/sessions/whoami"
			},
			"hydra": {
				"introspection_url": "%s/oauth2/introspect"
			},
			"cache": {
				"enabled": true,
				"ttl": "500ms"
			}
		}`, kratosTrackingServer.URL, hydraTrackingServer.URL)

		t.Run("case=kratos_session_cached", func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.AddCookie(&http.Cookie{
				Name:  "ory_kratos_session",
				Value: "cache_test_session",
			})

			// First request should hit Kratos
			session1 := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session1, []byte(cachingConfig), nil)
			require.NoError(t, err)
			initialKratosCount := kratosCallCount

			// Second request should use cache
			session2 := &AuthenticationSession{}
			err = authenticator.Authenticate(req, session2, []byte(cachingConfig), nil)
			require.NoError(t, err)

			assert.Equal(t, initialKratosCount, kratosCallCount, "Second request should not call Kratos (cached)")
			assert.Equal(t, session1.Subject, session2.Subject)
		})

		t.Run("case=hydra_token_cached", func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.Header.Set("Authorization", "Bearer ory_at_cache_test_token")

			// First request should hit Hydra
			session1 := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session1, []byte(cachingConfig), nil)
			require.NoError(t, err)
			initialHydraCount := hydraCallCount

			// Second request should use cache
			session2 := &AuthenticationSession{}
			err = authenticator.Authenticate(req, session2, []byte(cachingConfig), nil)
			require.NoError(t, err)

			assert.Equal(t, initialHydraCount, hydraCallCount, "Second request should not call Hydra (cached)")
			assert.Equal(t, session1.Subject, session2.Subject)
		})

		t.Run("case=cache_expiry", func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.Header.Set("Authorization", "Bearer ory_at_expiry_test_token")

			// First request
			session1 := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session1, []byte(cachingConfig), nil)
			require.NoError(t, err)
			countAfterFirst := hydraCallCount

			// Wait for cache to expire
			time.Sleep(600 * time.Millisecond)

			// Second request after expiry should hit service again
			session2 := &AuthenticationSession{}
			err = authenticator.Authenticate(req, session2, []byte(cachingConfig), nil)
			require.NoError(t, err)

			assert.Greater(t, hydraCallCount, countAfterFirst, "Request after cache expiry should call Hydra again")
		})
	})

	t.Run("scenario=error_handling", func(t *testing.T) {
		t.Run("case=kratos_service_unavailable", func(t *testing.T) {
			unavailableConfig := `{
				"kratos": {
					"check_session_url": "http://localhost:99999/sessions/whoami"
				},
				"hydra": {
					"introspection_url": "http://localhost:8080/oauth2/introspect"
				}
			}`

			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.AddCookie(&http.Cookie{
				Name:  "ory_kratos_session",
				Value: "test_session",
			})

			session := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session, []byte(unavailableConfig), nil)

			require.Error(t, err)
		})

		t.Run("case=hydra_service_unavailable", func(t *testing.T) {
			unavailableConfig := `{
				"kratos": {
					"check_session_url": "http://localhost:8080/sessions/whoami"
				},
				"hydra": {
					"introspection_url": "http://localhost:99999/oauth2/introspect"
				}
			}`

			req := httptest.NewRequest("GET", "http://example.com/api", nil)
			req.Header.Set("Authorization", "Bearer ory_at_test_token")

			session := &AuthenticationSession{}
			err := authenticator.Authenticate(req, session, []byte(unavailableConfig), nil)

			require.Error(t, err)
		})
	})
}

func createMockKratosServer() *httptest.Server {
	router := httprouter.New()

	router.GET("/sessions/whoami", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("Content-Type", "application/json")

		// Check cookie or authorization header
		var sessionValue string
		if cookie := r.Header.Get("Cookie"); cookie != "" && strings.Contains(cookie, "ory_kratos_session=") {
			// Extract session value from cookie
			parts := strings.Split(cookie, "ory_kratos_session=")
			if len(parts) > 1 {
				sessionValue = strings.Split(parts[1], ";")[0]
			}
		} else if auth := r.Header.Get("Authorization"); auth != "" {
			sessionValue = strings.TrimPrefix(auth, "Bearer ")
		}

		switch sessionValue {
		case "valid_session_123":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":     "session-123",
				"active": true,
				"identity": map[string]interface{}{
					"id":        "user-123",
					"schema_id": "default",
					"traits": map[string]interface{}{
						"email": "user@example.com",
					},
				},
			})
		case "ory_st_valid_token_456":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":     "session-456",
				"active": true,
				"identity": map[string]interface{}{
					"id":        "user-456",
					"schema_id": "backoffice",
					"traits": map[string]interface{}{
						"email": "admin@example.com",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "unauthorized",
			})
		}
	})

	return httptest.NewServer(router)
}

func createMockHydraServer() *httptest.Server {
	router := httprouter.New()

	router.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		w.Header().Set("Content-Type", "application/json")

		r.ParseForm()
		token := r.Form.Get("token")

		switch token {
		case "ory_at_valid_access_token":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active":    true,
				"client_id": "test-client",
				"sub":       "client-123",
				"scope":     "read write",
				"aud":       []string{"api"},
				"exp":       time.Now().Add(time.Hour).Unix(),
			})
		case "ory_at_token_with_read_scope":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active":    true,
				"client_id": "scope-client",
				"sub":       "user-with-scope",
				"scope":     "read",
				"exp":       time.Now().Add(time.Hour).Unix(),
			})
		case "ory_at_inactive_token":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active": false,
			})
		default:
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active": false,
			})
		}
	})

	return httptest.NewServer(router)
}
