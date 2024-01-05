package utils

type contextKey struct {
	name string
}

var ClaimsKey = &contextKey{"claims"}
