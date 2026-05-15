package securetunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// defaultHandshakeTimeout bounds the wait for SERVICE_IDS after the
// WebSocket upgrade. A peer that opens the socket but never sends the
// handshake frame would otherwise pin the caller until its ctx deadline.
const defaultHandshakeTimeout = 10 * time.Second

// DefaultServiceID is the single service the v1 source proxy supports.
const DefaultServiceID = "SSH"

const wsSubprotocol = "aws.iot.securetunneling-3.0"

// local-proxy-mode=source identifies us to AWS; the access token in the
// request header binds the connection to a specific tunnel.
const dataPlaneURLTemplate = "wss://data.tunneling.iot.%s.amazonaws.com/tunnel?local-proxy-mode=source"

var (
	ErrRegionRequired        = errors.New("securetunnel: region is required")
	ErrAccessTokenRequired   = errors.New("securetunnel: source access token is required")
	ErrServiceIDMismatch     = errors.New("securetunnel: destination did not advertise expected service id")
	ErrSessionReset          = errors.New("securetunnel: destination sent SESSION_RESET")
	ErrFrameTooLarge         = errors.New("securetunnel: incoming frame exceeds protocol maximum")
	ErrUnexpectedClose       = errors.New("securetunnel: websocket closed unexpectedly")
	ErrServiceIDsNotReceived = errors.New("securetunnel: destination did not publish SERVICE_IDS before timeout")
)

// SourceProxyOptions configures StartSourceProxy. Region and
// SourceAccessToken are required.
type SourceProxyOptions struct {
	// Region is the AWS region whose data-tunneling endpoint to dial.
	Region string

	// SourceAccessToken is the AWS-minted token authorizing this
	// WebSocket. Sent only in the "access-token" request header; never
	// logged, never written to disk.
	SourceAccessToken string

	// ServiceID names the destination service. Empty -> DefaultServiceID.
	ServiceID string

	// Logger receives DEBUG-level diagnostic events; nil discards. No
	// event in this package carries the access token or payload bytes.
	Logger *slog.Logger

	// HandshakeTimeout bounds the wait for SERVICE_IDS after the upgrade;
	// <= 0 resolves to defaultHandshakeTimeout. The caller-supplied ctx is
	// honored — whichever fires first tears the handshake down.
	HandshakeTimeout time.Duration

	// Test seams.
	httpClient      *http.Client
	dialURLOverride string
}

// SourceProxy is the running proxy returned by StartSourceProxy. Lifecycle:
// LocalPort returns the loopback port to pass to ssh; Wait blocks until
// the proxy terminates; Close drives a clean teardown (STREAM_RESET on
// open streams + WebSocket close + listener close + goroutine drain).
type SourceProxy struct {
	options   SourceProxyOptions
	conn      *websocket.Conn
	listener  net.Listener
	logger    *slog.Logger
	serviceID string

	rootCtx    context.Context
	cancelRoot context.CancelFunc

	wg sync.WaitGroup

	streamsMu sync.Mutex
	streams   map[int32]*stream

	// V3 reserves stream id 0 for unset; new streams start at 1.
	nextStreamID atomic.Int32

	// writeMu serializes WebSocket writes. coder/websocket's Write is
	// per-message concurrency-safe, but a single-writer model keeps the
	// stream-id allocation interlocked cleanly.
	writeMu sync.Mutex

	// terminate is set once; subsequent termination errors are slog'd.
	terminateOnce sync.Once
	terminateErr  error

	// preReader carries any frames awaitServiceIDs buffered behind
	// SERVICE_IDS into the read loop.
	preReader *framedReader
}

// stream is one accepted TCP connection. closeOnce ensures STREAM_RESET +
// TCP close fire at most once per stream — both local close and inbound
// STREAM_RESET can drive teardown.
type stream struct {
	id        int32
	conn      net.Conn
	closeOnce sync.Once
}

// StartSourceProxy dials the AWS data-plane endpoint, performs the V3
// handshake, validates SERVICE_IDS, opens a loopback listener, and returns.
// The proxy continues until Close or until the WebSocket / context
// terminates; Wait blocks until that termination completes.
func StartSourceProxy(ctx context.Context, options SourceProxyOptions) (*SourceProxy, error) {
	options.Region = strings.TrimSpace(options.Region)
	options.ServiceID = strings.TrimSpace(options.ServiceID)
	options.SourceAccessToken = strings.TrimSpace(options.SourceAccessToken)
	if options.Region == "" {
		return nil, ErrRegionRequired
	}
	if options.SourceAccessToken == "" {
		return nil, ErrAccessTokenRequired
	}
	if options.ServiceID == "" {
		options.ServiceID = DefaultServiceID
	}

	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	dialURL := options.dialURLOverride
	if dialURL == "" {
		dialURL = fmt.Sprintf(dataPlaneURLTemplate, options.Region)
	}

	headers := http.Header{}
	headers.Set("access-token", options.SourceAccessToken)
	dialOptions := &websocket.DialOptions{
		HTTPHeader:   headers,
		Subprotocols: []string{wsSubprotocol},
	}
	if options.httpClient != nil {
		dialOptions.HTTPClient = options.httpClient
	}

	conn, _, err := websocket.Dial(ctx, dialURL, dialOptions)
	if err != nil {
		return nil, fmt.Errorf("securetunnel: dial websocket: %w", err)
	}
	if conn.Subprotocol() != wsSubprotocol {
		_ = conn.Close(websocket.StatusPolicyViolation, "subprotocol mismatch")
		return nil, fmt.Errorf("securetunnel: server did not select subprotocol %q (got %q)", wsSubprotocol, conn.Subprotocol())
	}

	// V3 caps messages at 131,076 bytes; arm the read limit so oversized
	// frames are rejected before they fill memory.
	conn.SetReadLimit(maxFramePayload + 8)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, "listener bind failed")
		return nil, fmt.Errorf("securetunnel: bind loopback listener: %w", err)
	}

	rootCtx, cancelRoot := context.WithCancel(ctx)
	proxy := &SourceProxy{
		options:    options,
		conn:       conn,
		listener:   listener,
		logger:     logger,
		serviceID:  options.ServiceID,
		rootCtx:    rootCtx,
		cancelRoot: cancelRoot,
		streams:    make(map[int32]*stream),
	}
	proxy.nextStreamID.Store(1)

	// Wait for SERVICE_IDS up front so callers see a clear handshake
	// failure rather than a deferred runtime error. Bound by
	// HandshakeTimeout against peers that upgrade but never publish.
	handshakeTimeout := options.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, handshakeTimeout)
	err = proxy.awaitServiceIDs(handshakeCtx)
	cancelHandshake()
	if err != nil {
		_ = listener.Close()
		_ = conn.Close(websocket.StatusPolicyViolation, "service-id mismatch")
		cancelRoot()
		return nil, err
	}

	proxy.wg.Add(2)
	go proxy.runReadLoop()
	go proxy.runAcceptLoop()

	logger.Debug("source proxy started", slog.String("local_port", listener.Addr().String()), slog.String("service_id", proxy.serviceID))

	return proxy, nil
}

// LocalPort reports the loopback port the source proxy is listening on.
func (s *SourceProxy) LocalPort() int {
	addr, ok := s.listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0
	}
	return addr.Port
}

// Wait blocks until the proxy's goroutines drain and returns the termination
// reason. nil means Closed cleanly; non-nil includes ErrSessionReset,
// ErrUnexpectedClose, or any read-loop error.
func (s *SourceProxy) Wait() error {
	s.wg.Wait()
	if s.terminateErr != nil && errors.Is(s.terminateErr, context.Canceled) {
		return nil
	}
	return s.terminateErr
}

// Close initiates a clean teardown (STREAM_RESET on open streams, WebSocket
// close, listener close). Idempotent. Follow with Wait to drain goroutines.
func (s *SourceProxy) Close() error {
	// Snapshot streams under lock so STREAM_RESET emits before terminate
	// closes the WebSocket (terminate skips the emit).
	s.streamsMu.Lock()
	open := make([]*stream, 0, len(s.streams))
	for _, st := range s.streams {
		open = append(open, st)
	}
	s.streamsMu.Unlock()

	for _, st := range open {
		s.closeStream(st, true)
	}

	s.terminate(nil)
	return nil
}

// terminate records the first termination cause and tears the proxy down.
// Subsequent calls log but do not overwrite. Closes every open TCP stream
// so per-stream pumps blocked on Read wake immediately.
func (s *SourceProxy) terminate(cause error) {
	s.terminateOnce.Do(func() {
		s.terminateErr = cause
		s.cancelRoot()
		_ = s.listener.Close()

		s.streamsMu.Lock()
		open := make([]*stream, 0, len(s.streams))
		for _, st := range s.streams {
			open = append(open, st)
		}
		s.streamsMu.Unlock()

		for _, st := range open {
			// Skip STREAM_RESET emit; the WebSocket is about to close
			// anyway. Just unblock the pump.
			st.closeOnce.Do(func() {
				s.streamsMu.Lock()
				delete(s.streams, st.id)
				s.streamsMu.Unlock()
				_ = st.conn.Close()
			})
		}

		_ = s.conn.Close(websocket.StatusNormalClosure, "source proxy terminating")
	})
}
