package utils

type contextKey struct {
	name string
}

var ClaimsKey = &contextKey{"claims"}
var TraceIdKey = &contextKey{"traceId"}
