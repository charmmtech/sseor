package sseor

import "net/http"

type SSEMiddleware interface {
	AttachSSEHeaders(next http.HandlerFunc) http.HandlerFunc
	AuthMiddleware(next http.HandlerFunc) http.HandlerFunc
	NamespaceMiddleware(next http.HandlerFunc) http.HandlerFunc
}

type SseorMiddleware interface {
	//SSEMiddleware(authenticator Authenticator, logger LoggerClient, ctxHelper ContextHelper) SSEMiddleware
}
