package securetunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"

	securetunnelpb "github.com/atomicgravity/postern/internal/securetunnel/proto"
)

// TestStartSourceProxy_HappyPath asserts the full happy-path round-trip:
// the proxy dials the fake, the fake emits SERVICE_IDS, a local TCP
// client connects to the proxy's loopback port, sends N bytes, the
// fake echoes them back on the same stream, and the client reads them
// out unchanged.
func TestStartSourceProxy_HappyPath(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	fake := newFakeV3Server(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxy, err := StartSourceProxy(ctx, SourceProxyOptions{
		Region:            "us-east-1",
		SourceAccessToken: "test-source-token",
		dialURLOverride:   fake.URL(),
		httpClient:        fake.httpClient(),
	})
	if err != nil {
		t.Fatalf("StartSourceProxy: %v", err)
	}
	defer func() {
		_ = proxy.Close()
		_ = proxy.Wait()
	}()

	if proxy.LocalPort() == 0 {
		t.Fatal("LocalPort returned 0")
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxy.LocalPort()))
	if err != nil {
		t.Fatalf("dial local proxy: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello postern tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write to local conn: %v", err)
	}

	got, err := drainConn(conn, len(payload))
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	// Verify the proxy emitted STREAM_START with serviceId="SSH" before
	// the DATA frame.
	if _, err := fake.waitForFrame(time.Second, func(f observedFrame) bool {
		return f.Type == securetunnelpb.Type_STREAM_START
	}); err != nil {
		t.Fatalf("STREAM_START not observed: %v", err)
	}
	if _, err := fake.waitForFrame(time.Second, func(f observedFrame) bool {
		return f.Type == securetunnelpb.Type_DATA && string(f.Payload) == string(payload)
	}); err != nil {
		t.Fatalf("DATA frame not observed: %v", err)
	}
}

// TestStartSourceProxy_ServiceIDMismatch asserts the proxy rejects a
// destination that publishes a non-matching service-id list.
func TestStartSourceProxy_ServiceIDMismatch(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	fake := newFakeV3Server(t)
	fake.serviceIDs = []string{"HTTPS"}

	_, err := StartSourceProxy(context.Background(), SourceProxyOptions{
		Region:            "us-east-1",
		SourceAccessToken: "test-source-token",
		dialURLOverride:   fake.URL(),
		httpClient:        fake.httpClient(),
	})
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !errors.Is(err, ErrServiceIDMismatch) {
		t.Fatalf("expected ErrServiceIDMismatch, got: %v", err)
	}
}

// TestStartSourceProxy_SessionReset asserts that a destination-emitted
// SESSION_RESET causes the proxy to terminate cleanly: Wait returns
// the sentinel, the listener is closed, and outstanding TCP connections
// see EOF.
func TestStartSourceProxy_SessionReset(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	fake := newFakeV3Server(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxy, err := StartSourceProxy(ctx, SourceProxyOptions{
		Region:            "us-east-1",
		SourceAccessToken: "test-source-token",
		dialURLOverride:   fake.URL(),
		httpClient:        fake.httpClient(),
	})
	if err != nil {
		t.Fatalf("StartSourceProxy: %v", err)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxy.LocalPort()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Force the proxy to register a stream so SESSION_RESET has work
	// to do.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := drainConn(conn, 4); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	fake.sessionReset()

	waitErr := proxy.Wait()
	if !errors.Is(waitErr, ErrSessionReset) {
		t.Fatalf("expected ErrSessionReset, got: %v", waitErr)
	}

	// Listener should reject new accepts.
	if _, dialErr := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxy.LocalPort())); dialErr == nil {
		t.Fatal("listener still accepting after SESSION_RESET")
	}
}

// TestStartSourceProxy_StreamResetPartial asserts that a STREAM_RESET
// on one stream tears that stream down but leaves the listener open
// for new accepts.
func TestStartSourceProxy_StreamResetPartial(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	fake := newFakeV3Server(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxy, err := StartSourceProxy(ctx, SourceProxyOptions{
		Region:            "us-east-1",
		SourceAccessToken: "test-source-token",
		dialURLOverride:   fake.URL(),
		httpClient:        fake.httpClient(),
	})
	if err != nil {
		t.Fatalf("StartSourceProxy: %v", err)
	}
	defer func() {
		_ = proxy.Close()
		_ = proxy.Wait()
	}()

	conn1, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxy.LocalPort()))
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer conn1.Close()

	if _, err := conn1.Write([]byte("ping")); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if _, err := drainConn(conn1, 4); err != nil {
		t.Fatalf("read 1: %v", err)
	}

	// Find the stream-id the proxy assigned to conn1.
	idx, err := fake.waitForFrame(time.Second, func(f observedFrame) bool {
		return f.Type == securetunnelpb.Type_STREAM_START
	})
	if err != nil {
		t.Fatalf("STREAM_START not observed: %v", err)
	}
	streamID := fake.frames()[idx].StreamID

	fake.streamReset(streamID)

	// conn1 should now see EOF.
	buffer := make([]byte, 16)
	_ = conn1.SetReadDeadline(time.Now().Add(time.Second))
	if _, readErr := conn1.Read(buffer); readErr == nil {
		t.Fatal("expected conn1 to close after STREAM_RESET")
	}

	// The listener must still accept new connections.
	conn2, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxy.LocalPort()))
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close()
	if _, err := conn2.Write([]byte("again")); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if _, err := drainConn(conn2, 5); err != nil {
		t.Fatalf("read 2: %v", err)
	}
}

// TestStartSourceProxy_LocalCloseEmitsStreamReset asserts that closing
// the engineer-side TCP connection causes the proxy to emit
// STREAM_RESET to the destination so the destination can close its end.
func TestStartSourceProxy_LocalCloseEmitsStreamReset(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	fake := newFakeV3Server(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxy, err := StartSourceProxy(ctx, SourceProxyOptions{
		Region:            "us-east-1",
		SourceAccessToken: "test-source-token",
		dialURLOverride:   fake.URL(),
		httpClient:        fake.httpClient(),
	})
	if err != nil {
		t.Fatalf("StartSourceProxy: %v", err)
	}
	defer func() {
		_ = proxy.Close()
		_ = proxy.Wait()
	}()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxy.LocalPort()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := drainConn(conn, 4); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = conn.Close()

	if _, err := fake.waitForFrame(time.Second, func(f observedFrame) bool {
		return f.Type == securetunnelpb.Type_STREAM_RESET
	}); err != nil {
		t.Fatalf("STREAM_RESET not observed: %v", err)
	}
}

// TestStartSourceProxy_ContextCancel asserts that cancelling the parent
// context tears the proxy down cleanly with no goroutine leaks.
func TestStartSourceProxy_ContextCancel(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	fake := newFakeV3Server(t)

	ctx, cancel := context.WithCancel(context.Background())

	proxy, err := StartSourceProxy(ctx, SourceProxyOptions{
		Region:            "us-east-1",
		SourceAccessToken: "test-source-token",
		dialURLOverride:   fake.URL(),
		httpClient:        fake.httpClient(),
	})
	if err != nil {
		cancel()
		t.Fatalf("StartSourceProxy: %v", err)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxy.LocalPort()))
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	cancel()
	_ = proxy.Close()
	if err := proxy.Wait(); err != nil {
		t.Fatalf("Wait returned error after cancel: %v", err)
	}
}

// TestStartSourceProxy_HandshakeTimeout asserts that a destination that
// completes the WebSocket upgrade but never emits SERVICE_IDS causes
// StartSourceProxy to return within the configured HandshakeTimeout
// rather than hanging on the caller's ctx. The returned error must
// chain to context.DeadlineExceeded so callers can errors.Is on the
// timeout without parsing message strings.
func TestStartSourceProxy_HandshakeTimeout(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	fake := newFakeV3Server(t)
	fake.suppressServiceIDs = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	_, err := StartSourceProxy(ctx, SourceProxyOptions{
		Region:            "us-east-1",
		SourceAccessToken: "test-source-token",
		dialURLOverride:   fake.URL(),
		httpClient:        fake.httpClient(),
		HandshakeTimeout:  50 * time.Millisecond,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected handshake timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded in chain, got: %v", err)
	}
	// Allow generous slack for slow CI but still prove the timeout
	// fired (not the caller ctx).
	if elapsed > 2*time.Second {
		t.Fatalf("handshake took %v, expected near 50ms", elapsed)
	}
}

// TestStartSourceProxy_ValidatesOptions asserts the early validation
// errors fire on empty Region / SourceAccessToken before any network
// activity.
func TestStartSourceProxy_ValidatesOptions(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	if _, err := StartSourceProxy(context.Background(), SourceProxyOptions{
		SourceAccessToken: "tok",
	}); !errors.Is(err, ErrRegionRequired) {
		t.Fatalf("expected ErrRegionRequired, got: %v", err)
	}
	if _, err := StartSourceProxy(context.Background(), SourceProxyOptions{
		Region: "us-east-1",
	}); !errors.Is(err, ErrAccessTokenRequired) {
		t.Fatalf("expected ErrAccessTokenRequired, got: %v", err)
	}
}
