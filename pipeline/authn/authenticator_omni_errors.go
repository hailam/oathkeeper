package authn

import (
	"net/http"

	"github.com/ory/herodot"
)

var (
	ErrOmniTokenInactive = &herodot.DefaultError{
		ErrorField:  "omni_token_inactive",
		CodeField:   http.StatusUnauthorized,
		StatusField: http.StatusText(http.StatusUnauthorized),
		ReasonField: "The OAuth 2.0 token is not active",
	}

	ErrOmniInsufficientScope = &herodot.DefaultError{
		ErrorField:  "omni_insufficient_scope",
		CodeField:   http.StatusForbidden,
		StatusField: http.StatusText(http.StatusForbidden),
		ReasonField: "The OAuth 2.0 token does not contain the required scope",
	}

	ErrOmniTokenExpired = &herodot.DefaultError{
		ErrorField:  "omni_token_expired",
		CodeField:   http.StatusUnauthorized,
		StatusField: http.StatusText(http.StatusUnauthorized),
		ReasonField: "The OAuth 2.0 token has expired",
	}

	ErrOmniInvalidAudience = &herodot.DefaultError{
		ErrorField:  "omni_invalid_audience",
		CodeField:   http.StatusForbidden,
		StatusField: http.StatusText(http.StatusForbidden),
		ReasonField: "The OAuth 2.0 token audience does not match the required audience",
	}

	ErrOmniUntrustedIssuer = &herodot.DefaultError{
		ErrorField:  "omni_untrusted_issuer",
		CodeField:   http.StatusForbidden,
		StatusField: http.StatusText(http.StatusForbidden),
		ReasonField: "The OAuth 2.0 token issuer is not trusted",
	}

	ErrOmniInvalidTokenUse = &herodot.DefaultError{
		ErrorField:  "omni_invalid_token_use",
		CodeField:   http.StatusForbidden,
		StatusField: http.StatusText(http.StatusForbidden),
		ReasonField: "The OAuth 2.0 token use is not valid for this request",
	}

	ErrOmniKratosSessionInactive = &herodot.DefaultError{
		ErrorField:  "omni_kratos_session_inactive",
		CodeField:   http.StatusUnauthorized,
		StatusField: http.StatusText(http.StatusUnauthorized),
		ReasonField: "The Kratos session is not active",
	}

	ErrOmniKratosUnavailable = &herodot.DefaultError{
		ErrorField:  "omni_kratos_unavailable",
		CodeField:   http.StatusServiceUnavailable,
		StatusField: http.StatusText(http.StatusServiceUnavailable),
		ReasonField: "Kratos service is unavailable",
	}

	ErrOmniHydraUnavailable = &herodot.DefaultError{
		ErrorField:  "omni_hydra_unavailable",
		CodeField:   http.StatusServiceUnavailable,
		StatusField: http.StatusText(http.StatusServiceUnavailable),
		ReasonField: "Hydra service is unavailable",
	}
)

func NewErrOmniMisconfigured(a Authenticator, err error) *herodot.DefaultError {
	return NewErrAuthenticatorMisconfigured(a, err).
		WithReasonf(`Configuration for authenticator "%s" could not be validated: %s`, a.GetID(), err)
}

func NewErrOmniNotEnabled(a Authenticator) *herodot.DefaultError {
	return ErrAuthenticatorNotEnabled.WithReasonf(
		`Authenticator "%s" is disabled per configuration`, a.GetID(),
	)
}
