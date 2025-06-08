package authn

/**
 This is a very custom authenticator that implements the "omni" logic for a project.
 It is very specific and not to be merged into the main Oathkeeper codebase.

 - check if there is an ory Kratos session cookie
 	- if there is, validate it with Kratos' /sessions/whoami endpoint
	- if the cookie is valid, check if the user identity schema is for backoffice or normal user
		- if it is a backoffice user, check if the rule allows backoffice users
		- if it is a normal user, check if the rule allows normal users
		- depending on configuration, send session data to the next handler
 - if there is no session cookie, check for a bearer token in the Authorization header
 	- if a token is found and starts with ory_st
		- call Kratos' /sessions/whoami endpoint to validate the token
		- if the token is valid, check if user identity schema is for backoffice or normal user
			- if it is a backoffice user, check if the rule allows backoffice users
			- if it is a normal user, check if the rule allows normal users
			- depending on configuration, send session data to the next handler
	- if token starts with ory_at
		- call Hydra's /oauth2/introspect endpoint to validate the token
		- if the token is valid, and aud has machines or psp
			- send session data to the next handler
		- if the token is valid, and does not have machines or psp
			- check if subject is a kratos user
			- if it is, check if the identity schema is for backoffice or normal user
			- depending on configuration, send session data to the next handler
			- configuration tells us if a certain type of user is to be allowed or not

basically, this authenticator checks for a Kratos session cookie first,
if it exists and is valid, it checks the user identity schema to determine if the user is a backoffice or normal user.
If the session cookie is not present or invalid, it checks for a bearer token in the Authorization header.
If a token is found, it validates the token with Kratos or Hydra, and checks the user identity schema to determine if the user is a backoffice or normal user.

We should cache the results of the Kratos and Hydra calls to avoid hitting those services too often.
We should also cache the overall result by a combination of the request URL, method, and headers,
so that we can quickly return the session data without hitting Kratos or Hydra again.
*/

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/pipeline"
	"github.com/ory/x/httpx"
	"github.com/ory/x/logrusx"
	"github.com/pkg/errors"
)

type AuthenticatorOmni struct {
	c      configuration.Provider
	client *http.Client

	tokenCache *ristretto.Cache[string, []byte]
	cacheTTL   *time.Duration
	logger     *logrusx.Logger
}

type omniCacheConfig struct {
	Enabled   bool   `json:"enabled"`
	TTL       string `json:"ttl"`
	MaxTokens int    `json:"max_tokens"`
}

type AuthenticatorOmniClientCredentialsRetryConfiguration struct {
	Timeout string `json:"max_delay"`
	MaxWait string `json:"give_up_after"`
}

// Fixed configuration struct to match the actual omni authenticator needs
type AuthenticatorOmniConfiguration struct {
	// Kratos configuration
	KratosURL     string `json:"kratos_url"`     // Base URL for Kratos API
	SessionCookie string `json:"session_cookie"` // Name of the session cookie (default: ory_kratos_session)

	// Hydra configuration
	HydraURL          string `json:"hydra_url"`           // Base URL for Hydra API
	HydraClientID     string `json:"hydra_client_id"`     // Client ID for Hydra introspection
	HydraClientSecret string `json:"hydra_client_secret"` // Client secret for Hydra introspection

	// User type allowances
	AllowBackoffice bool `json:"allow_backoffice"` // Whether backoffice users are allowed
	AllowNormal     bool `json:"allow_normal"`     // Whether normal users are allowed
	AllowMachines   bool `json:"allow_machines"`   // Whether machine/service accounts are allowed
	AllowPSP        bool `json:"allow_psp"`        // Whether PSP tokens are allowed

	// Identity schema configuration
	BackofficeSchemas []string `json:"backoffice_schemas"` // List of schemas considered "backoffice"
	NormalSchemas     []string `json:"normal_schemas"`     // List of schemas considered "normal"

	// Token prefixes
	SessionTokenPrefix string `json:"session_token_prefix"` // Prefix for session tokens (default: ory_st)
	AccessTokenPrefix  string `json:"access_token_prefix"`  // Prefix for access tokens (default: ory_at)

	// Caching and retry
	Retry *AuthenticatorOmniClientCredentialsRetryConfiguration `json:"retry,omitempty"`
	Cache omniCacheConfig                                       `json:"cache"`

	// Session forwarding
	ForwardSessionData bool `json:"forward_session_data"` // Whether to forward session data to next handler
}

// Kratos session response structures
type KratosSession struct {
	ID        string         `json:"id"`
	Active    bool           `json:"active"`
	Identity  KratosIdentity `json:"identity"`
	ExpiresAt *time.Time     `json:"expires_at"`
}

type KratosIdentity struct {
	ID             string                 `json:"id"`
	SchemaID       string                 `json:"schema_id"`
	SchemaURL      string                 `json:"schema_url"`
	State          string                 `json:"state"`
	StateChangedAt *time.Time             `json:"state_changed_at"`
	Traits         map[string]interface{} `json:"traits"`
}

// Hydra introspection response structure
type HydraIntrospectionResponse struct {
	Active    bool     `json:"active"`
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	ExpiresAt int64    `json:"exp"`
	Subject   string   `json:"sub"`
	TokenType string   `json:"token_type"`
	Scope     string   `json:"scope"`
}

// NewAuthenticatorOmni creates a new instance of your authenticator.
func NewAuthenticatorOmni(c configuration.Provider, logger *logrusx.Logger) *AuthenticatorOmni {
	return &AuthenticatorOmni{
		c:      c,
		logger: logger,
	}
}

// GetID returns the unique identifier for this authenticator.
func (a *AuthenticatorOmni) GetID() string {
	return "omni"
}

// Validate checks if the authenticator is enabled and if its rule configuration is valid.
func (a *AuthenticatorOmni) Validate(config json.RawMessage) error {
	// First, check if the authenticator is globally enabled in the Oathkeeper config.
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

func (a *AuthenticatorOmni) Config(config json.RawMessage) (*AuthenticatorOmniConfiguration, error) {
	const (
		defaultTimeout = "1s"
		defaultMaxWait = "2s"
	)
	var c AuthenticatorOmniConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	// Set defaults
	if c.SessionCookie == "" {
		c.SessionCookie = "ory_kratos_session"
	}
	if c.SessionTokenPrefix == "" {
		c.SessionTokenPrefix = "ory_st"
	}
	if c.AccessTokenPrefix == "" {
		c.AccessTokenPrefix = "ory_at"
	}

	// Validate required configuration
	if c.KratosURL == "" {
		return nil, errors.New("kratos_url is required")
	}
	if c.HydraURL == "" {
		return nil, errors.New("hydra_url is required")
	}

	if c.Retry == nil {
		c.Retry = &AuthenticatorOmniClientCredentialsRetryConfiguration{Timeout: defaultTimeout, MaxWait: defaultMaxWait}
	} else {
		if c.Retry.Timeout == "" {
			c.Retry.Timeout = defaultTimeout
		}
		if c.Retry.MaxWait == "" {
			c.Retry.MaxWait = defaultMaxWait
		}
	}

	duration, err := time.ParseDuration(c.Retry.Timeout)
	if err != nil {
		return nil, err
	}

	maxWait, err := time.ParseDuration(c.Retry.MaxWait)
	if err != nil {
		return nil, err
	}

	timeout := time.Millisecond * duration
	a.client = httpx.NewResilientClient(
		httpx.ResilientClientWithMaxRetryWait(maxWait),
		httpx.ResilientClientWithConnectionTimeout(timeout),
	).StandardClient()

	if c.Cache.TTL != "" {
		cacheTTL, err := time.ParseDuration(c.Cache.TTL)
		if err != nil {
			return nil, err
		}
		a.cacheTTL = &cacheTTL
	}

	if a.tokenCache == nil {
		maxTokens := int64(c.Cache.MaxTokens)
		if maxTokens == 0 {
			maxTokens = 1000
		}
		a.logger.Debugf("Creating cache with max tokens: %d", maxTokens)
		cache, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
			// This will hold about 1000 unique mutation responses.
			NumCounters: 10 * maxTokens,
			// Allocate a maximum amount of tokens to cache
			MaxCost: maxTokens,
			// This is a best-practice value.
			BufferItems: 64,
			// Use a static cost of 1, so we can limit the amount of tokens that can be stored
			Cost: func(value []byte) int64 {
				return 1
			},
			IgnoreInternalCost: true,
		})
		if err != nil {
			return nil, err
		}

		a.tokenCache = cache
	}

	return &c, nil
}

// generateCacheKey creates a unique cache key based on request details
func (a *AuthenticatorOmni) generateCacheKey(r *http.Request, tokenOrCookie string) string {
	h := sha256.New()
	h.Write([]byte(r.Method))
	h.Write([]byte(r.URL.String()))
	h.Write([]byte(tokenOrCookie))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// checkCache attempts to retrieve cached authentication result
func (a *AuthenticatorOmni) checkCache(cacheKey string) (*AuthenticationSession, bool) {
	if a.tokenCache == nil {
		return nil, false
	}

	cached, found := a.tokenCache.Get(cacheKey)
	if !found {
		return nil, false
	}

	var session AuthenticationSession
	if err := json.Unmarshal(cached, &session); err != nil {
		a.logger.WithError(err).Debug("Failed to unmarshal cached session")
		return nil, false
	}

	return &session, true
}

// setCache stores authentication result in cache
func (a *AuthenticatorOmni) setCache(cacheKey string, session *AuthenticationSession) {
	if a.tokenCache == nil {
		return
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		a.logger.WithError(err).Debug("Failed to marshal session for caching")
		return
	}

	ttl := time.Hour // default TTL
	if a.cacheTTL != nil {
		ttl = *a.cacheTTL
	}

	a.tokenCache.SetWithTTL(cacheKey, sessionBytes, 1, ttl)
}

// validateKratosSession validates a session cookie or token with Kratos
func (a *AuthenticatorOmni) validateKratosSession(config *AuthenticatorOmniConfiguration, cookieValue string, isToken bool) (*KratosSession, error) {
	endpoint := fmt.Sprintf("%s/sessions/whoami", strings.TrimSuffix(config.KratosURL, "/"))

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Kratos request")
	}

	if isToken {
		// For session tokens, use Authorization header
		req.Header.Set("Authorization", "Bearer "+cookieValue)
	} else {
		// For session cookies, set the cookie
		req.Header.Set("Cookie", fmt.Sprintf("%s=%s", config.SessionCookie, cookieValue))
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to call Kratos")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Kratos returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read Kratos response")
	}

	var session KratosSession
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal Kratos response")
	}

	if !session.Active {
		return nil, errors.New("session is not active")
	}

	return &session, nil
}

// validateHydraToken validates an access token with Hydra
func (a *AuthenticatorOmni) validateHydraToken(config *AuthenticatorOmniConfiguration, token string) (*HydraIntrospectionResponse, error) {
	endpoint := fmt.Sprintf("%s/oauth2/introspect", strings.TrimSuffix(config.HydraURL, "/"))

	data := url.Values{}
	data.Set("token", token)

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Hydra request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.HydraClientID, config.HydraClientSecret)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to call Hydra")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read Hydra response")
	}

	var introspection HydraIntrospectionResponse
	if err := json.Unmarshal(body, &introspection); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal Hydra response")
	}

	if !introspection.Active {
		return nil, errors.New("token is not active")
	}

	return &introspection, nil
}

// isBackofficeUser checks if a user schema is considered backoffice
func (a *AuthenticatorOmni) isBackofficeUser(config *AuthenticatorOmniConfiguration, schemaID string) bool {
	for _, schema := range config.BackofficeSchemas {
		if schema == schemaID {
			return true
		}
	}
	return false
}

// isNormalUser checks if a user schema is considered normal user
func (a *AuthenticatorOmni) isNormalUser(config *AuthenticatorOmniConfiguration, schemaID string) bool {
	for _, schema := range config.NormalSchemas {
		if schema == schemaID {
			return true
		}
	}
	return false
}

// hasAllowedAudience checks if token has machine or PSP audience
func (a *AuthenticatorOmni) hasAllowedAudience(config *AuthenticatorOmniConfiguration, audiences []string) bool {
	for _, aud := range audiences {
		if strings.Contains(aud, "machines") && config.AllowMachines {
			return true
		}
		if strings.Contains(aud, "psp") && config.AllowPSP {
			return true
		}
	}
	return false
}

// Authenticate is the core of your authenticator. It contains the "omni" logic.
func (a *AuthenticatorOmni) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, rule pipeline.Rule) error {
	cfg, err := a.Config(config)
	if err != nil {
		return err
	}

	// Step 1: Check for Kratos session cookie first
	sessionCookie, err := r.Cookie(cfg.SessionCookie)
	if err == nil && sessionCookie.Value != "" {
		a.logger.Debug("Found Kratos session cookie, validating...")

		// Generate cache key for this cookie
		cacheKey := a.generateCacheKey(r, "cookie:"+sessionCookie.Value)

		// Check cache first
		if cached, found := a.checkCache(cacheKey); found {
			a.logger.Debug("Using cached session data for cookie")
			*session = *cached
			return nil
		}

		// Validate session cookie with Kratos
		kratosSession, err := a.validateKratosSession(cfg, sessionCookie.Value, false)
		if err != nil {
			a.logger.WithError(err).Debug("Failed to validate Kratos session cookie")
		} else {
			// Step 2: Check if user identity schema is allowed
			isBackofficeUser := a.isBackofficeUser(cfg, kratosSession.Identity.SchemaID)
			isNormalUser := a.isNormalUser(cfg, kratosSession.Identity.SchemaID)

			// Step 3: Verify rule permissions based on user type
			if (isBackofficeUser && cfg.AllowBackoffice) || (isNormalUser && cfg.AllowNormal) {
				a.logger.Debug("Session cookie validated and user type allowed")

				// Step 4: Populate session data
				session.Subject = kratosSession.Identity.ID
				session.Extra = map[string]interface{}{
					"identity_id":   kratosSession.Identity.ID,
					"schema_id":     kratosSession.Identity.SchemaID,
					"traits":        kratosSession.Identity.Traits,
					"session_id":    kratosSession.ID,
					"is_backoffice": isBackofficeUser,
					"auth_method":   "kratos_cookie",
				}

				// Cache the result
				a.setCache(cacheKey, session)
				return nil
			} else {
				a.logger.Debug("User type not allowed by rule configuration")
			}
		}
	}

	// Step 5: Check for bearer token in Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		a.logger.Debug("No valid authorization found")
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")

	// Generate cache key for this token
	cacheKey := a.generateCacheKey(r, "token:"+token)

	// Check cache first
	if cached, found := a.checkCache(cacheKey); found {
		a.logger.Debug("Using cached session data for token")
		*session = *cached
		return nil
	}

	// Step 6: Handle session tokens (ory_st prefix)
	if strings.HasPrefix(token, cfg.SessionTokenPrefix) {
		a.logger.Debug("Found Kratos session token, validating...")

		// Validate session token with Kratos
		kratosSession, err := a.validateKratosSession(cfg, token, true)
		if err != nil {
			a.logger.WithError(err).Debug("Failed to validate Kratos session token")
			return errors.WithStack(ErrAuthenticatorNotResponsible)
		}

		// Step 7: Check user identity schema for session token
		isBackofficeUser := a.isBackofficeUser(cfg, kratosSession.Identity.SchemaID)
		isNormalUser := a.isNormalUser(cfg, kratosSession.Identity.SchemaID)

		// Step 8: Verify rule permissions
		if (isBackofficeUser && cfg.AllowBackoffice) || (isNormalUser && cfg.AllowNormal) {
			a.logger.Debug("Session token validated and user type allowed")

			// Populate session data
			session.Subject = kratosSession.Identity.ID
			session.Extra = map[string]interface{}{
				"identity_id":   kratosSession.Identity.ID,
				"schema_id":     kratosSession.Identity.SchemaID,
				"traits":        kratosSession.Identity.Traits,
				"session_id":    kratosSession.ID,
				"is_backoffice": isBackofficeUser,
				"auth_method":   "kratos_token",
			}

			// Cache the result
			a.setCache(cacheKey, session)
			return nil
		} else {
			a.logger.Debug("User type not allowed by rule configuration")
			return errors.WithStack(ErrAuthenticatorNotResponsible)
		}
	}

	// Step 9: Handle access tokens (ory_at prefix)
	if strings.HasPrefix(token, cfg.AccessTokenPrefix) {
		a.logger.Debug("Found Hydra access token, validating...")

		// Validate access token with Hydra
		hydraResponse, err := a.validateHydraToken(cfg, token)
		if err != nil {
			a.logger.WithError(err).Debug("Failed to validate Hydra access token")
			return errors.WithStack(ErrAuthenticatorNotResponsible)
		}

		// Step 10: Check if token has machine or PSP audience
		if a.hasAllowedAudience(cfg, hydraResponse.Audience) {
			a.logger.Debug("Access token has allowed audience (machines/psp)")

			// Populate session data for machine/service tokens
			session.Subject = hydraResponse.Subject
			session.Extra = map[string]interface{}{
				"client_id":   hydraResponse.ClientID,
				"audience":    hydraResponse.Audience,
				"scope":       hydraResponse.Scope,
				"token_type":  hydraResponse.TokenType,
				"auth_method": "hydra_token",
				"is_machine":  true,
			}

			// Cache the result
			a.setCache(cacheKey, session)
			return nil
		}

		// Step 11: Check if subject is a Kratos user (for user access tokens)
		if hydraResponse.Subject != "" {
			a.logger.Debug("Access token subject found, checking if it's a Kratos user...")

			// Try to get user identity from Kratos using subject as identity ID
			// This is a simplified approach - you might need to adjust based on your setup
			kratosEndpoint := fmt.Sprintf("%s/admin/identities/%s", strings.TrimSuffix(cfg.KratosURL, "/"), hydraResponse.Subject)
			req, err := http.NewRequest("GET", kratosEndpoint, nil)
			if err == nil {
				resp, err := a.client.Do(req)
				if err == nil && resp.StatusCode == http.StatusOK {
					defer resp.Body.Close()
					body, err := io.ReadAll(resp.Body)
					if err == nil {
						var identity KratosIdentity
						if json.Unmarshal(body, &identity) == nil {
							// Step 12: Check user type for access token subject
							isBackofficeUser := a.isBackofficeUser(cfg, identity.SchemaID)
							isNormalUser := a.isNormalUser(cfg, identity.SchemaID)

							if (isBackofficeUser && cfg.AllowBackoffice) || (isNormalUser && cfg.AllowNormal) {
								a.logger.Debug("Access token subject is allowed Kratos user")

								// Populate session data
								session.Subject = identity.ID
								session.Extra = map[string]interface{}{
									"identity_id":   identity.ID,
									"schema_id":     identity.SchemaID,
									"traits":        identity.Traits,
									"client_id":     hydraResponse.ClientID,
									"audience":      hydraResponse.Audience,
									"scope":         hydraResponse.Scope,
									"is_backoffice": isBackofficeUser,
									"auth_method":   "hydra_kratos_token",
								}

								// Cache the result
								a.setCache(cacheKey, session)
								return nil
							}
						}
					}
				}
			}
		}
	}

	// Step 13: No valid authentication found
	a.logger.Debug("No valid authentication method found or user not allowed")
	return errors.WithStack(ErrAuthenticatorNotResponsible)
}
