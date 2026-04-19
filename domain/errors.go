package domain

import "errors"

// Sentinel errors that the application layer can check against with errors.Is.
var (
	ErrTraefikUnreachable = errors.New("traefik API is unreachable")
	ErrTraefikBadData     = errors.New("traefik returned unexpected data")
)

// InfrastructureError wraps a low-level technical error with a domain-meaningful
// message, decoupling the domain from infrastructure specifics (HTTP status codes,
// JSON parse errors, etc.).
type InfrastructureError struct {
	Sentinel error  // one of the Err* sentinels above
	Cause    error  // the underlying technical error
}

func (e InfrastructureError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap supports errors.Is / errors.As — callers can check:
//
//	errors.Is(err, domain.ErrTraefikUnreachable)
func (e InfrastructureError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}
