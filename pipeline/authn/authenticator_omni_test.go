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
	"github.com/ory/x/assertx"
	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"
)

func TestAuthenticatorOmni(t *testing.T) {
	conf := internal.NewConfigurationWithDefaults(configx.SkipValidation())
	reg := internal.NewRegistry(conf)

	a, err := reg.PipelineAuthenticator("omni")
	require.NoError(t, err)
	assert.Equal(t, "omni", a.GetID())

	t.Run("method=authenticate", func(t *testing.T) {
		for k, tc := range []struct {
			d              string
			setup          func(*testing.T, *httprouter.Router)
			r              *http.Request
			config         json.RawMessage
			expectErr      bool
			expectExactErr error
			expectSess     *AuthenticationSession
		}{
			{
				d:         "should fail because no payloads",
				r:         &http.Request{Header: http.Header{}},
				expectErr: true,
			},
			{
				d:      "should pass with valid kratos session cookie",
				r:      &http.Request{Header: http.Header{"Cookie": {"ory_kratos_session=valid_session_token"}}},
				config: []byte(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect"}}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.GET("/sessions/whoami", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						cookie := r.Header.Get("Cookie")
						require.Contains(t, cookie, "ory_kratos_session=valid_session_token")

						require.NoError(t, json.NewEncoder(w).Encode(&map[string]interface{}{
							"id":     "session-123",
							"active": true,
							"identity": map[string]interface{}{
								"id":        "user-123",
								"schema_id": "default",
								"traits": map[string]interface{}{
									"email": "user@example.com",
								},
							},
						}))
					})
				},
				expectErr: false,
				expectSess: &AuthenticationSession{
					Subject: "user-123",
					Extra: map[string]interface{}{
						"identity_id": "user-123",
						"schema_id":   "default",
						"traits": map[string]interface{}{
							"email": "user@example.com",
						},
						"session_id":  "session-123",
						"auth_method": "kratos_cookie",
					},
				},
			},
			{
				d:      "should pass with valid kratos session token",
				r:      &http.Request{Header: http.Header{"Authorization": {"Bearer ory_st_valid_session_token"}}},
				config: []byte(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect"}}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.GET("/sessions/whoami", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						auth := r.Header.Get("Authorization")
						require.Equal(t, "Bearer ory_st_valid_session_token", auth)

						require.NoError(t, json.NewEncoder(w).Encode(&map[string]interface{}{
							"id":     "session-456",
							"active": true,
							"identity": map[string]interface{}{
								"id":        "user-456",
								"schema_id": "backoffice",
								"traits": map[string]interface{}{
									"email": "admin@example.com",
								},
							},
						}))
					})
				},
				expectErr: false,
				expectSess: &AuthenticationSession{
					Subject: "user-456",
					Extra: map[string]interface{}{
						"identity_id": "user-456",
						"schema_id":   "backoffice",
						"traits": map[string]interface{}{
							"email": "admin@example.com",
						},
						"session_id":  "session-456",
						"auth_method": "kratos_token",
					},
				},
			},
			{
				d:      "should pass with valid hydra access token",
				r:      &http.Request{Header: http.Header{"Authorization": {"Bearer ory_at_valid_access_token"}}},
				config: []byte(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect", "required_scope": ["read"], "scope_strategy": "exact"}}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "ory_at_valid_access_token", r.Form.Get("token"))

						require.NoError(t, json.NewEncoder(w).Encode(&map[string]interface{}{
							"active":    true,
							"client_id": "client-123",
							"scope":     "read write",
							"sub":       "user-789",
							"aud":       []string{"api"},
							"iss":       "https://auth.example.com",
							"exp":       time.Now().Add(time.Hour).Unix(),
						}))
					})
				},
				expectErr: false,
				expectSess: &AuthenticationSession{
					Subject: "user-789",
					Extra: map[string]interface{}{
						"username":    "",
						"client_id":   "client-123",
						"scope":       "read write",
						"auth_method": "hydra_token",
						"aud":         []string{"api"},
					},
				},
			},
			{
				d:      "should fail with invalid kratos session",
				r:      &http.Request{Header: http.Header{"Cookie": {"ory_kratos_session=invalid_session_token"}}},
				config: []byte(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect"}}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.GET("/sessions/whoami", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						w.WriteHeader(http.StatusUnauthorized)
					})
				},
				expectErr:      true,
				expectExactErr: ErrAuthenticatorNotResponsible,
			},
			{
				d:      "should fail with inactive hydra token",
				r:      &http.Request{Header: http.Header{"Authorization": {"Bearer ory_at_inactive_token"}}},
				config: []byte(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect"}}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "ory_at_inactive_token", r.Form.Get("token"))

						require.NoError(t, json.NewEncoder(w).Encode(&map[string]interface{}{
							"active": false,
						}))
					})
				},
				expectErr:      true,
				expectExactErr: ErrAuthenticatorNotResponsible,
			},
			{
				d:      "should fail with insufficient scope",
				r:      &http.Request{Header: http.Header{"Authorization": {"Bearer ory_at_insufficient_scope"}}},
				config: []byte(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect", "required_scope": ["admin"], "scope_strategy": "exact"}}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "ory_at_insufficient_scope", r.Form.Get("token"))

						require.NoError(t, json.NewEncoder(w).Encode(&map[string]interface{}{
							"active":    true,
							"client_id": "client-123",
							"scope":     "read write",
							"sub":       "user-789",
							"exp":       time.Now().Add(time.Hour).Unix(),
						}))
					})
				},
				expectErr:      true,
				expectExactErr: ErrAuthenticatorNotResponsible,
			},
			{
				d:              "should return error saying that authenticator is not responsible for validating the request, as no token was provided",
				r:              &http.Request{Header: http.Header{}},
				config:         []byte(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect"}}`),
				expectErr:      true,
				expectExactErr: ErrAuthenticatorNotResponsible,
			},
			{
				d:      "should pass with pre-authorization enabled",
				r:      &http.Request{Header: http.Header{"Authorization": {"Bearer ory_at_preauth_token"}}},
				config: []byte(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect", "pre_authorization": {"enabled": true, "client_id": "introspect_client", "client_secret": "secret", "token_url": "http://localhost/oauth2/token"}}}`),
				setup: func(t *testing.T, m *httprouter.Router) {
					m.POST("/oauth2/token", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "client_credentials", r.Form.Get("grant_type"))
						w.Header().Set("Content-Type", "application/json")
						require.NoError(t, json.NewEncoder(w).Encode(&map[string]interface{}{
							"access_token": "introspect_access_token",
							"token_type":   "Bearer",
							"expires_in":   3600,
						}))
					})
					m.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
						require.NoError(t, r.ParseForm())
						require.Equal(t, "ory_at_preauth_token", r.Form.Get("token"))

						require.NoError(t, json.NewEncoder(w).Encode(&map[string]interface{}{
							"active":    true,
							"client_id": "client-456",
							"scope":     "api",
							"sub":       "service-account",
							"exp":       time.Now().Add(time.Hour).Unix(),
						}))
					})
				},
				expectErr: false,
				expectSess: &AuthenticationSession{
					Subject: "service-account",
					Extra: map[string]interface{}{
						"username":    "",
						"client_id":   "client-456",
						"scope":       "api",
						"auth_method": "hydra_token",
					},
				},
			},
		} {
			t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
				router := httprouter.New()
				if tc.setup != nil {
					tc.setup(t, router)
				}
				ts := httptest.NewServer(router)
				defer ts.Close()

				if tc.config != nil {
					tc.config, _ = sjson.SetBytes(tc.config, "kratos.check_session_url", ts.URL+"/sessions/whoami")
					tc.config, _ = sjson.SetBytes(tc.config, "hydra.introspection_url", ts.URL+"/oauth2/introspect")
					if strings.Contains(string(tc.config), "pre_authorization") {
						tc.config, _ = sjson.SetBytes(tc.config, "hydra.pre_authorization.token_url", ts.URL+"/oauth2/token")
					}
				}

				sess := new(AuthenticationSession)
				err = a.Authenticate(tc.r, sess, tc.config, nil)
				if tc.expectErr {
					require.Error(t, err)
					if tc.expectExactErr != nil {
						assert.EqualError(t, err, tc.expectExactErr.Error(), "%+v", err)
					}
				} else {
					require.NoError(t, err)
				}

				if tc.expectSess != nil {
					assertx.EqualAsJSON(t, tc.expectSess, sess)
				}
			})
		}
	})

	t.Run("method=authenticate-with-cache", func(t *testing.T) {
		conf.SetForTest(t, "authenticators.omni.config.cache.enabled", true)
		conf.SetForTest(t, "authenticators.omni.config.cache.ttl", "1s")

		var handlerWasCalled bool
		assertHandlerWasCalled := func(t *testing.T) {
			assert.True(t, handlerWasCalled, "expected the handler to have been called")
			handlerWasCalled = false
		}
		assertCacheWasUsed := func(t *testing.T) {
			assert.False(t, handlerWasCalled, "expected the cache to have been used")
			handlerWasCalled = false
		}

		setup := func(t *testing.T, config string) []byte {
			router := httprouter.New()
			router.GET("/sessions/whoami", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
				handlerWasCalled = true
				require.NoError(t, json.NewEncoder(w).Encode(&map[string]interface{}{
					"id":     "session-cached",
					"active": true,
					"identity": map[string]interface{}{
						"id":        "user-cached",
						"schema_id": "default",
						"traits": map[string]interface{}{
							"email": "cached@example.com",
						},
					},
				}))
			})
			router.POST("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
				handlerWasCalled = true
				require.NoError(t, r.ParseForm())
				require.NoError(t, json.NewEncoder(w).Encode(&map[string]interface{}{
					"active":    true,
					"client_id": "cached-client",
					"scope":     "read",
					"sub":       "cached-user",
					"exp":       time.Now().Add(time.Hour).Unix(),
				}))
			})
			ts := httptest.NewServer(router)
			t.Cleanup(ts.Close)

			config, err := sjson.Set(config, "kratos.check_session_url", ts.URL+"/sessions/whoami")
			require.NoError(t, err)
			config, err = sjson.Set(config, "hydra.introspection_url", ts.URL+"/oauth2/introspect")
			require.NoError(t, err)

			return []byte(config)
		}

		t.Run("case=kratos session caching", func(t *testing.T) {
			r := &http.Request{Header: http.Header{"Cookie": {"ory_kratos_session=cached_session_token"}}}
			expected := new(AuthenticationSession)

			t.Run("case=initial request succeeds and caches", func(t *testing.T) {
				config := setup(t, `{"cache": {"enabled": true, "ttl": "1s"}}`)

				err = a.Authenticate(r, expected, config, nil)
				require.NoError(t, err)
				assertHandlerWasCalled(t)
			})

			t.Run("case=second request uses cache", func(t *testing.T) {
				config := setup(t, `{"cache": {"enabled": true, "ttl": "1s"}}`)
				sess := new(AuthenticationSession)

				err = a.Authenticate(r, sess, config, nil)
				require.NoError(t, err)
				assertCacheWasUsed(t)
				assertx.EqualAsJSON(t, expected, sess)
			})

			t.Run("case=cache expires after TTL", func(t *testing.T) {
				config := setup(t, `{"cache": {"enabled": true, "ttl": "100ms"}}`)

				require.NoError(t, a.Authenticate(r, expected, config, nil))
				assertHandlerWasCalled(t)

				// Wait for cache to expire
				time.Sleep(150 * time.Millisecond)

				require.NoError(t, a.Authenticate(r, new(AuthenticationSession), config, nil))
				assertHandlerWasCalled(t)
			})
		})

		t.Run("case=hydra token caching", func(t *testing.T) {
			r := &http.Request{Header: http.Header{"Authorization": {"Bearer ory_at_cached_token"}}}
			expected := new(AuthenticationSession)

			t.Run("case=initial request succeeds and caches", func(t *testing.T) {
				config := setup(t, `{"cache": {"enabled": true, "ttl": "1s"}}`)

				err = a.Authenticate(r, expected, config, nil)
				require.NoError(t, err)
				assertHandlerWasCalled(t)
			})

			t.Run("case=second request uses cache", func(t *testing.T) {
				config := setup(t, `{"cache": {"enabled": true, "ttl": "1s"}}`)
				sess := new(AuthenticationSession)

				err = a.Authenticate(r, sess, config, nil)
				require.NoError(t, err)
				assertCacheWasUsed(t)
				assertx.EqualAsJSON(t, expected, sess)
			})
		})
	})

	t.Run("method=validate", func(t *testing.T) {
		conf.SetForTest(t, "authenticators.omni.enabled", false)
		require.Error(t, a.Validate(json.RawMessage(`{"kratos": {"check_session_url": "http://localhost"}, "hydra": {"introspection_url": "http://localhost"}}`)))

		conf.SetForTest(t, "authenticators.omni.enabled", true)
		require.Error(t, a.Validate(json.RawMessage(`{"kratos": {"check_session_url": ""}, "hydra": {"introspection_url": ""}}`)))

		conf.SetForTest(t, "authenticators.omni.enabled", true)
		require.NoError(t, a.Validate(json.RawMessage(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect"}}`)))
	})

	t.Run("method=config", func(t *testing.T) {
		logger := logrusx.New("test", "1")
		authenticator := NewAuthenticatorOmni(conf, logger, trace.NewNoopTracerProvider())

		baseConfig := []byte(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect"}}`)
		preAuthConfig := []byte(`{"kratos": {"check_session_url": "http://localhost/sessions/whoami"}, "hydra": {"introspection_url": "http://localhost/oauth2/introspect", "pre_authorization": {"enabled": true, "client_id": "test_id", "client_secret": "test_secret", "token_url": "http://localhost/oauth2/token"}}}`)

		_, baseClient, err := authenticator.Config(baseConfig)
		require.NoError(t, err)

		_, preAuthClient, err := authenticator.Config(preAuthConfig)
		require.NoError(t, err)

		require.NotEqual(t, baseClient, preAuthClient)

		_, baseClient2, err := authenticator.Config(baseConfig)
		require.NoError(t, err)
		require.Equal(t, baseClient2, baseClient)

		_, preAuthClient2, err := authenticator.Config(preAuthConfig)
		require.NoError(t, err)
		require.Equal(t, preAuthClient2, preAuthClient)
	})
}
