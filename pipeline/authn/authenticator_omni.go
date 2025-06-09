package authn

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/helper"
	"github.com/ory/oathkeeper/pipeline"
	"github.com/ory/x/httpx"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/otelx"
	"github.com/ory/x/stringslice"
)

/**
NOT TO BE MERGED WITH THE OATHKEEPER CODEBASE.
This is a very custom authenticator that implements an "omni" auth logic for a project.

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

// Configuration structures following Oathkeeper patterns
type AuthenticatorOmniConfiguration struct {
	Kratos KratosConfig    `json:"kratos"`
	Hydra  HydraConfig     `json:"hydra"`
	Cache  OmniCacheConfig `json:"cache"`
	Retry  OmniRetryConfig `json:"retry"`
}

type KratosConfig struct {
	CheckSessionURL string `json:"check_session_url"`
	SessionCookie   string `json:"session_cookie"`
	PreservePath    bool   `json:"preserve_path"`
	PreserveQuery   bool   `json:"preserve_query"`
	PreserveHost    bool   `json:"preserve_host"`
	ExtraFrom       string `json:"extra_from"`
	SubjectFrom     string `json:"subject_from"`
}

type HydraConfig struct {
	IntrospectionURL string        `json:"introspection_url"`
	ScopeStrategy    string        `json:"scope_strategy"`
	RequiredScope    []string      `json:"required_scope"`
	TargetAudience   []string      `json:"target_audience"`
	TrustedIssuers   []string      `json:"trusted_issuers"`
	PreAuthorization PreAuthConfig `json:"pre_authorization"`
}

type PreAuthConfig struct {
	Enabled      bool     `json:"enabled"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	TokenURL     string   `json:"token_url"`
	Audience     string   `json:"audience"`
	Scope        []string `json:"scope"`
}

type OmniCacheConfig struct {
	Enabled bool   `json:"enabled"`
	TTL     string `json:"ttl"`
	MaxCost int64  `json:"max_cost"`
}

type OmniRetryConfig struct {
	GiveUpAfter string `json:"give_up_after"`
	MaxDelay    string `json:"max_delay"`
}

// Response structures
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

type OmniIntrospectionResult struct {
	Active    bool                   `json:"active"`
	Extra     map[string]interface{} `json:"ext"`
	Subject   string                 `json:"sub,omitempty"`
	Username  string                 `json:"username"`
	Audience  []string               `json:"aud,omitempty"`
	TokenType string                 `json:"token_type"`
	Issuer    string                 `json:"iss"`
	ClientID  string                 `json:"client_id,omitempty"`
	Scope     string                 `json:"scope,omitempty"`
	Expires   int64                  `json:"exp"`
	TokenUse  string                 `json:"token_use"`
}

// Main authenticator struct
type AuthenticatorOmni struct {
	c         configuration.Provider
	clientMap map[string]*http.Client
	mu        sync.RWMutex

	tokenCache *ristretto.Cache[string, []byte]
	cacheTTL   *time.Duration
	logger     *logrusx.Logger
	provider   trace.TracerProvider
}

// Constructor following Oathkeeper patterns
func NewAuthenticatorOmni(c configuration.Provider, logger *logrusx.Logger, p trace.TracerProvider) *AuthenticatorOmni {
	return &AuthenticatorOmni{
		c:         c,
		logger:    logger,
		provider:  p,
		clientMap: make(map[string]*http.Client),
	}
}

func (a *AuthenticatorOmni) GetID() string {
	return "omni"
}

func (a *AuthenticatorOmni) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, _, err := a.Config(config)
	return err
}

func (a *AuthenticatorOmni) Config(config json.RawMessage) (*AuthenticatorOmniConfiguration, *http.Client, error) {
	var c AuthenticatorOmniConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	// Set defaults following Oathkeeper patterns
	if c.Kratos.SessionCookie == "" {
		c.Kratos.SessionCookie = "ory_kratos_session"
	}
	if c.Kratos.ExtraFrom == "" {
		c.Kratos.ExtraFrom = "@this"
	}
	if c.Kratos.SubjectFrom == "" {
		c.Kratos.SubjectFrom = "identity.id"
	}
	if c.Hydra.ScopeStrategy == "" {
		c.Hydra.ScopeStrategy = "exact"
	}
	if c.Retry.GiveUpAfter == "" {
		c.Retry.GiveUpAfter = "1s"
	}
	if c.Retry.MaxDelay == "" {
		c.Retry.MaxDelay = "100ms"
	}

	// Validate required configuration
	if c.Kratos.CheckSessionURL == "" {
		return nil, nil, errors.New("kratos.check_session_url is required")
	}
	if c.Hydra.IntrospectionURL == "" {
		return nil, nil, errors.New("hydra.introspection_url is required")
	}

	// Create HTTP client with proper configuration
	rawKey, err := json.Marshal(&c)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	clientKey := fmt.Sprintf("%x", md5.Sum(rawKey))
	a.mu.RLock()
	client, ok := a.clientMap[clientKey]
	a.mu.RUnlock()

	if !ok || client == nil {
		a.logger.Debug("Initializing HTTP client for omni authenticator")

		var rt http.RoundTripper
		if c.Hydra.PreAuthorization.Enabled {
			var ep url.Values
			if c.Hydra.PreAuthorization.Audience != "" {
				ep = url.Values{"audience": {c.Hydra.PreAuthorization.Audience}}
			}

			rt = (&clientcredentials.Config{
				ClientID:       c.Hydra.PreAuthorization.ClientID,
				ClientSecret:   c.Hydra.PreAuthorization.ClientSecret,
				Scopes:         c.Hydra.PreAuthorization.Scope,
				EndpointParams: ep,
				TokenURL:       c.Hydra.PreAuthorization.TokenURL,
			}).Client(context.Background()).Transport
		}

		// Parse retry configuration
		maxDelay, err := time.ParseDuration(c.Retry.MaxDelay)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}

		giveUpAfter, err := time.ParseDuration(c.Retry.GiveUpAfter)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}

		client = httpx.NewResilientClient(
			httpx.ResilientClientWithMaxRetryWait(giveUpAfter),
			httpx.ResilientClientWithConnectionTimeout(maxDelay),
		).StandardClient()

		if rt != nil {
			client.Transport = otelhttp.NewTransport(rt, otelhttp.WithTracerProvider(a.provider))
		} else {
			client.Transport = otelhttp.NewTransport(client.Transport, otelhttp.WithTracerProvider(a.provider))
		}

		a.mu.Lock()
		a.clientMap[clientKey] = client
		a.mu.Unlock()
	}

	// Configure cache
	if c.Cache.TTL != "" {
		cacheTTL, err := time.ParseDuration(c.Cache.TTL)
		if err != nil {
			return nil, nil, err
		}
		a.cacheTTL = &cacheTTL
	}

	if a.tokenCache == nil {
		maxCost := c.Cache.MaxCost
		if maxCost == 0 {
			maxCost = 100000000
		}

		a.logger.Debugf("Creating cache with max cost: %d", maxCost)
		cache, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
			NumCounters: maxCost * 10,
			MaxCost:     maxCost,
			BufferItems: 64,
			Cost: func(value []byte) int64 {
				return 1
			},
			IgnoreInternalCost: true,
		})
		if err != nil {
			return nil, nil, err
		}
		a.tokenCache = cache
	}

	return &c, client, nil
}

func (a *AuthenticatorOmni) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, rule pipeline.Rule) (err error) {
	tp := trace.SpanFromContext(r.Context()).TracerProvider()
	ctx, span := tp.Tracer("oauthkeeper/pipeline/authn").Start(r.Context(), "pipeline.authn.AuthenticatorOmni.Authenticate")
	defer otelx.End(span, &err)
	r = r.WithContext(ctx)

	cfg, client, err := a.Config(config)
	if err != nil {
		return err
	}

	// Try session cookie first
	if sessionCookie, err := r.Cookie(cfg.Kratos.SessionCookie); err == nil && sessionCookie.Value != "" {
		a.logger.Debug("Found Kratos session cookie, validating...")

		cacheKey := a.generateCacheKey("cookie", sessionCookie.Value, cfg)
		if cached := a.getFromCache(cacheKey); cached != nil {
			a.logger.Debug("Using cached session data for cookie")
			*session = *cached
			return nil
		}

		if kratosSession, err := a.validateKratosSession(client, cfg, sessionCookie.Value, false); err == nil {
			if err := a.populateSessionFromKratos(session, kratosSession, "kratos_cookie"); err == nil {
				a.setCache(cacheKey, session, cfg)
				return nil
			}
		}
		a.logger.WithError(err).Debug("Failed to validate Kratos session cookie")
	}

	// Check for bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		a.logger.Debug("No valid authorization found")
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")

	cacheKey := a.generateCacheKey("token", token, cfg)
	if cached := a.getFromCache(cacheKey); cached != nil {
		a.logger.Debug("Using cached session data for token")
		*session = *cached
		return nil
	}

	// Handle Kratos session tokens (ory_st prefix)
	if strings.HasPrefix(token, "ory_st") {
		a.logger.Debug("Found Kratos session token, validating...")

		kratosSession, err := a.validateKratosSession(client, cfg, token, true)
		if err != nil {
			a.logger.WithError(err).Debug("Failed to validate Kratos session token")
			return errors.WithStack(ErrAuthenticatorNotResponsible)
		}

		if err := a.populateSessionFromKratos(session, kratosSession, "kratos_token"); err != nil {
			return err
		}

		a.setCache(cacheKey, session, cfg)
		return nil
	}

	// Handle Hydra access tokens (ory_at prefix)
	if strings.HasPrefix(token, "ory_at") {
		a.logger.Debug("Found Hydra access token, validating...")

		introspectionResult, err := a.validateHydraToken(client, cfg, token)
		if err != nil {
			a.logger.WithError(err).Debug("Failed to validate Hydra access token")
			return errors.WithStack(ErrAuthenticatorNotResponsible)
		}

		if err := a.populateSessionFromHydra(session, introspectionResult, "hydra_token"); err != nil {
			return err
		}

		a.setCache(cacheKey, session, cfg)
		return nil
	}

	a.logger.Debug("No valid authentication method found")
	return errors.WithStack(ErrAuthenticatorNotResponsible)
}

// Helper methods following Oathkeeper patterns
func (a *AuthenticatorOmni) validateKratosSession(client *http.Client, config *AuthenticatorOmniConfiguration, cookieOrToken string, isToken bool) (*KratosSession, error) {
	req, err := http.NewRequest("GET", config.Kratos.CheckSessionURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Kratos request")
	}

	if isToken {
		req.Header.Set("Authorization", "Bearer "+cookieOrToken)
	} else {
		req.Header.Set("Cookie", fmt.Sprintf("%s=%s", config.Kratos.SessionCookie, cookieOrToken))
	}

	if config.Kratos.PreserveHost {
		req.Header.Set("X-Forwarded-Host", req.Host)
	}

	resp, err := client.Do(req)
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

func (a *AuthenticatorOmni) validateHydraToken(client *http.Client, config *AuthenticatorOmniConfiguration, token string) (*OmniIntrospectionResult, error) {
	data := url.Values{}
	data.Set("token", token)

	req, err := http.NewRequest("POST", config.Hydra.IntrospectionURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Hydra request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to call Hydra")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Hydra returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read Hydra response")
	}

	var result OmniIntrospectionResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal Hydra response")
	}

	// Validate introspection response following RFC 7662
	if err := a.validateIntrospectionResult(&result, config); err != nil {
		return nil, err
	}

	return &result, nil
}

func (a *AuthenticatorOmni) validateIntrospectionResult(result *OmniIntrospectionResult, config *AuthenticatorOmniConfiguration) error {
	if !result.Active {
		return errors.WithStack(helper.ErrUnauthorized.WithReason("Access token is not active"))
	}

	if result.Expires > 0 && time.Unix(result.Expires, 0).Before(time.Now()) {
		return errors.WithStack(helper.ErrUnauthorized.WithReason("Access token expired"))
	}

	// Validate audience
	for _, audience := range config.Hydra.TargetAudience {
		if !stringslice.Has(result.Audience, audience) {
			return errors.WithStack(helper.ErrForbidden.WithReason(fmt.Sprintf("Token audience is not intended for target audience %s", audience)))
		}
	}

	// Validate issuer
	if len(config.Hydra.TrustedIssuers) > 0 {
		if !stringslice.Has(config.Hydra.TrustedIssuers, result.Issuer) {
			return errors.WithStack(helper.ErrForbidden.WithReason("Token issuer does not match any trusted issuer"))
		}
	}

	// Validate scopes using scope strategy
	ss := a.c.ToScopeStrategy(config.Hydra.ScopeStrategy, "authenticators.omni.config.scope_strategy")
	if ss != nil {
		for _, scope := range config.Hydra.RequiredScope {
			if !ss(strings.Split(result.Scope, " "), scope) {
				return errors.WithStack(helper.ErrForbidden.WithReason(fmt.Sprintf("Scope %s was not granted", scope)))
			}
		}
	}

	// Validate token use
	if len(result.TokenUse) > 0 && result.TokenUse != "access_token" {
		return errors.WithStack(helper.ErrForbidden.WithReason(fmt.Sprintf("Use of introspected token is not an access token but \"%s\"", result.TokenUse)))
	}

	return nil
}

func (a *AuthenticatorOmni) populateSessionFromKratos(session *AuthenticationSession, kratosSession *KratosSession, authMethod string) error {
	session.Subject = kratosSession.Identity.ID
	session.Extra = map[string]interface{}{
		"identity_id": kratosSession.Identity.ID,
		"schema_id":   kratosSession.Identity.SchemaID,
		"traits":      kratosSession.Identity.Traits,
		"session_id":  kratosSession.ID,
		"auth_method": authMethod,
	}

	return nil
}

func (a *AuthenticatorOmni) populateSessionFromHydra(session *AuthenticationSession, result *OmniIntrospectionResult, authMethod string) error {
	session.Subject = result.Subject

	if len(result.Extra) == 0 {
		result.Extra = map[string]interface{}{}
	}

	result.Extra["username"] = result.Username
	result.Extra["client_id"] = result.ClientID
	result.Extra["scope"] = result.Scope
	result.Extra["auth_method"] = authMethod

	if len(result.Audience) != 0 {
		result.Extra["aud"] = result.Audience
	}

	session.Extra = result.Extra
	return nil
}

// Cache management following Oathkeeper patterns
func (a *AuthenticatorOmni) generateCacheKey(tokenType, token string, config *AuthenticatorOmniConfiguration) string {
	hasher := md5.New()
	hasher.Write([]byte(fmt.Sprintf("%s|%s|%d", tokenType, token, config.hashCode())))
	return fmt.Sprintf("omni:%x", hasher.Sum(nil))
}

func (c *AuthenticatorOmniConfiguration) hashCode() uint64 {
	// Simple hash implementation for cache key generation
	data, _ := json.Marshal(c)
	hasher := md5.New()
	hasher.Write(data)
	result := hasher.Sum(nil)

	var hash uint64
	for i := 0; i < 8 && i < len(result); i++ {
		hash = hash<<8 + uint64(result[i])
	}
	return hash
}

func (a *AuthenticatorOmni) getFromCache(cacheKey string) *AuthenticationSession {
	if a.tokenCache == nil {
		return nil
	}

	cached, found := a.tokenCache.Get(cacheKey)
	if !found {
		return nil
	}

	var session AuthenticationSession
	if err := json.Unmarshal(cached, &session); err != nil {
		a.logger.WithError(err).Debug("Failed to unmarshal cached session")
		return nil
	}

	return &session
}

func (a *AuthenticatorOmni) setCache(cacheKey string, session *AuthenticationSession, config *AuthenticatorOmniConfiguration) {
	if a.tokenCache == nil || !config.Cache.Enabled {
		return
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		a.logger.WithError(err).Debug("Failed to marshal session for caching")
		return
	}

	ttl := 5 * time.Minute // default TTL
	if a.cacheTTL != nil {
		ttl = *a.cacheTTL
	}

	a.tokenCache.SetWithTTL(cacheKey, sessionBytes, 1, ttl)
}
