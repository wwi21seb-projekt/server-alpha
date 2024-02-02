package utils

// contextKey is a type used for context keys to avoid conflicts with other packages' context keys.
type contextKey struct {
	name string
}

// ClaimsKey is the context key used for storing JWT claims in a request context.
// It ensures that the key is unique to avoid conflicts with other context keys.
var ClaimsKey = &contextKey{"claims"}
