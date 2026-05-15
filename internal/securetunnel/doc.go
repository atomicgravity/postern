// Package securetunnel implements the source side of the AWS IoT Secure
// Tunneling V3 WebSocket subprotocol. The proxy is a byte shoveler between
// a loopback TCP listener and a TLS-terminated AWS WebSocket, translating
// V3 control frames.
//
// Goroutine discipline: every goroutine joins on a sync.WaitGroup before
// Wait returns; tests assert via goleak.VerifyNone.
//
// Token discipline: the source access token rides in the "access-token"
// WebSocket request header — never URL-logged, audit-logged, or echoed.
// No log line in this package references the token by any name.
package securetunnel
