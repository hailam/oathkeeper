package authn

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/x/configx"
	"github.com/ory/x/logrusx"
)

func TestOmniCache(t *testing.T) {
	t.Parallel()
	logger := logrusx.New("", "")
	c, err := configuration.NewKoanfProvider(
		context.Background(),
		nil,
		logger,
		configx.WithValues(map[string]interface{}{
			"authenticators.omni.config.cache.enabled":            true,
			"authenticators.omni.config.kratos.check_session_url": "http://localhost:8080/",
			"authenticators.omni.config.hydra.introspection_url":  "http://localhost:8080/",
		}))
	require.NoError(t, err)

	a := NewAuthenticatorOmni(c, logger, trace.NewNoopTracerProvider())
	assert.Equal(t, "omni", a.GetID())

	config, _, err := a.Config(nil)
	require.NoError(t, err)

	t.Run("method=cache-operations", func(t *testing.T) {
		t.Run("case=cache session successfully", func(t *testing.T) {
			session := &AuthenticationSession{
				Subject: "user-123",
				Extra: map[string]interface{}{
					"identity_id": "user-123",
					"auth_method": "kratos_cookie",
				},
			}

			cacheKey := a.generateCacheKey("cookie", "test_token", config)
			a.setCache(cacheKey, session, config)

			// Wait for cache to save value
			time.Sleep(time.Millisecond * 10)

			// Modify original struct should not affect cached value
			session.Subject = "modified-user"

			cached := a.getFromCache(cacheKey)
			require.NotNil(t, cached)
			require.Equal(t, "user-123", cached.Subject)
			require.Equal(t, "kratos_cookie", cached.Extra["auth_method"])
		})

		t.Run("case=cache key generation consistency", func(t *testing.T) {
			key1 := a.generateCacheKey("token", "same_token", config)
			key2 := a.generateCacheKey("token", "same_token", config)
			key3 := a.generateCacheKey("token", "different_token", config)
			key4 := a.generateCacheKey("cookie", "same_token", config)

			assert.Equal(t, key1, key2, "Same inputs should generate same cache key")
			assert.NotEqual(t, key1, key3, "Different tokens should generate different cache keys")
			assert.NotEqual(t, key1, key4, "Different token types should generate different cache keys")
		})

		t.Run("case=cache miss returns nil", func(t *testing.T) {
			nonExistentKey := a.generateCacheKey("token", "non_existent_token", config)
			cached := a.getFromCache(nonExistentKey)
			require.Nil(t, cached)
		})

		t.Run("case=cache disabled does not store", func(t *testing.T) {
			disabledConfig := &AuthenticatorOmniConfiguration{
				Cache: OmniCacheConfig{
					Enabled: false,
				},
			}

			session := &AuthenticationSession{
				Subject: "user-456",
				Extra: map[string]interface{}{
					"auth_method": "hydra_token",
				},
			}

			cacheKey := a.generateCacheKey("token", "disabled_cache_token", disabledConfig)
			a.setCache(cacheKey, session, disabledConfig)

			// Wait for potential cache operation
			time.Sleep(time.Millisecond * 10)

			cached := a.getFromCache(cacheKey)
			require.Nil(t, cached, "Cache should be empty when disabled")
		})

		t.Run("case=invalid json value should not work", func(t *testing.T) {
			// Manually set invalid JSON in cache
			invalidKey := "omni:invalid_json"
			ok := a.tokenCache.Set(invalidKey, []byte("invalid-json-string"), 1)
			require.True(t, ok)

			// Wait for cache to save value
			time.Sleep(time.Millisecond * 10)

			cached := a.getFromCache(invalidKey)
			require.Nil(t, cached, "Invalid JSON should return nil")
		})

		t.Run("case=cache with TTL expires", func(t *testing.T) {
			shortTTLConfig := &AuthenticatorOmniConfiguration{
				Kratos: KratosConfig{
					CheckSessionURL: "http://localhost/",
				},
				Hydra: HydraConfig{
					IntrospectionURL: "http://localhost/",
				},
				Cache: OmniCacheConfig{
					Enabled: true,
					TTL:     "100ms",
				},
			}

			// Configure authenticator with short TTL
			a.cacheTTL = func() *time.Duration { d := 100 * time.Millisecond; return &d }()

			session := &AuthenticationSession{
				Subject: "ttl-user",
				Extra: map[string]interface{}{
					"auth_method": "test",
				},
			}

			cacheKey := a.generateCacheKey("token", "ttl_token", shortTTLConfig)
			a.setCache(cacheKey, session, shortTTLConfig)

			// Wait for cache to save
			time.Sleep(10 * time.Millisecond)

			// Should be cached initially
			cached := a.getFromCache(cacheKey)
			require.NotNil(t, cached)
			assert.Equal(t, "ttl-user", cached.Subject)

			// Wait for TTL to expire
			time.Sleep(150 * time.Millisecond)

			// Should be expired now
			cached = a.getFromCache(cacheKey)
			require.Nil(t, cached, "Cache entry should have expired")
		})

		t.Run("case=concurrent cache operations", func(t *testing.T) {
			const numGoroutines = 10
			const numOperations = 100

			session := &AuthenticationSession{
				Subject: "concurrent-user",
				Extra: map[string]interface{}{
					"auth_method": "concurrent_test",
				},
			}

			// Run concurrent cache operations
			for i := 0; i < numGoroutines; i++ {
				go func(id int) {
					for j := 0; j < numOperations; j++ {
						cacheKey := a.generateCacheKey("token", fmt.Sprintf("concurrent_token_%d_%d", id, j), config)

						// Set cache
						a.setCache(cacheKey, session, config)

						// Get from cache
						cached := a.getFromCache(cacheKey)

						// Should either be nil (if not yet stored) or equal to original
						if cached != nil {
							assert.Equal(t, session.Subject, cached.Subject)
						}
					}
				}(i)
			}

			// Wait for all goroutines to complete
			time.Sleep(500 * time.Millisecond)
		})
	})

	t.Run("method=config-hash", func(t *testing.T) {
		t.Run("case=same config generates same hash", func(t *testing.T) {
			config1 := &AuthenticatorOmniConfiguration{
				Kratos: KratosConfig{
					CheckSessionURL: "http://test.com",
					SessionCookie:   "test_cookie",
				},
				Hydra: HydraConfig{
					IntrospectionURL: "http://hydra.com",
					ScopeStrategy:    "exact",
				},
			}

			config2 := &AuthenticatorOmniConfiguration{
				Kratos: KratosConfig{
					CheckSessionURL: "http://test.com",
					SessionCookie:   "test_cookie",
				},
				Hydra: HydraConfig{
					IntrospectionURL: "http://hydra.com",
					ScopeStrategy:    "exact",
				},
			}

			hash1 := config1.hashCode()
			hash2 := config2.hashCode()

			assert.Equal(t, hash1, hash2, "Identical configs should generate same hash")
		})

		t.Run("case=different config generates different hash", func(t *testing.T) {
			config1 := &AuthenticatorOmniConfiguration{
				Kratos: KratosConfig{
					CheckSessionURL: "http://test1.com",
				},
			}

			config2 := &AuthenticatorOmniConfiguration{
				Kratos: KratosConfig{
					CheckSessionURL: "http://test2.com",
				},
			}

			hash1 := config1.hashCode()
			hash2 := config2.hashCode()

			assert.NotEqual(t, hash1, hash2, "Different configs should generate different hashes")
		})
	})
}
