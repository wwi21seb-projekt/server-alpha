package utils

// contextKey is a type used for context keys to avoid conflicts with other packages' context keys.
type contextKey struct {
	name string
}

// Returns string representation of the context key.
func (c *contextKey) String() string {
	return c.name
}

// ClaimsKey is the context key used for storing JWT claims in a request context.
// It ensures that the key is unique to avoid conflicts with other context keys.
var ClaimsKey = &contextKey{"claims"}
var TraceIdKey = &contextKey{"traceId"}
var SanitizedPayloadKey = &contextKey{"sanitizedPayload"}
