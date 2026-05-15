package securetunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	securetunnelpb "github.com/atomicgravity/postern/internal/securetunnel/proto"
)

// fakeV3Server stands in for the AWS data-plane endpoint. It speaks the
// V3 subprotocol: validates handshake headers, emits SERVICE_IDS on
// connect, dispatches incoming frames to a test-controllable behavior
// model, and exposes hooks for tests to assert observed frames.
type fakeV3Server struct {
	t              *testing.T
	server         *httptest.Server
	serviceIDs     []string
	expectedToken  string
	emitSessionRst chan struct{}
	emitStreamRst  chan int32

	// suppressServiceIDs is read once at handler entry. When true the
	// fake completes the WebSocket upgrade but never emits the initial
	// SERVICE_IDS frame, modeling a misbehaving destination that
	// strands the source-side handshake. Used by the handshake-timeout
	// test.
	suppressServiceIDs bool

	// behaviorMu guards mutable fields below.
	behaviorMu sync.Mutex
	// echoStreams: when true, DATA frames are echoed back on the
	// same stream-id to the source.
	echoStreams bool

	// observed is the set of frames the source emitted to us, in
	// arrival order. Tests assert on it after teardown.
	observed []observedFrame
}

type observedFrame struct {
	Type     securetunnelpb.Type
	StreamID int32
	Payload  []byte
}

func newFakeV3Server(t *testing.T) *fakeV3Server {
	fake := &fakeV3Server{
		t:              t,
		serviceIDs:     []string{DefaultServiceID},
		expectedToken:  "test-source-token",
		emitSessionRst: make(chan struct{}, 1),
		emitStreamRst:  make(chan int32, 4),
		echoStreams:    true,
	}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.handle))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeV3Server) URL() string {
	// Build the source-proxy dial URL form: ws://host/tunnel?local-proxy-mode=source.
	// coder/websocket accepts ws:// for plain HTTP test servers.
	return strings.Replace(f.server.URL, "http://", "ws://", 1) + "/tunnel?local-proxy-mode=source"
}

func (f *fakeV3Server) handle(writer http.ResponseWriter, request *http.Request) {
	if got := request.Header.Get("access-token"); got != f.expectedToken {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols: []string{wsSubprotocol},
	})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(maxFramePayload + 8)

	ctx := request.Context()

	if f.suppressServiceIDs {
		// Hold the connection open so the source-side handshake
		// blocks until its own timeout fires. We must keep reading
		// to notice the source closing the WebSocket — otherwise
		// the handler goroutine would block on ctx.Done() and the
		// goleak check would flag it, since httptest.Server.Close()
		// does not interrupt hijacked WebSocket handlers.
		f.readLoop(ctx, conn)
		return
	}

	// Emit SERVICE_IDS as the first frame.
	if err := f.send(ctx, conn, &securetunnelpb.Message{
		Type:                securetunnelpb.Type_SERVICE_IDS,
		AvailableServiceIds: f.serviceIDs,
	}); err != nil {
		return
	}

	go f.driveControl(ctx, conn)
	f.readLoop(ctx, conn)
}

func (f *fakeV3Server) driveControl(ctx context.Context, conn *websocket.Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.emitSessionRst:
			_ = f.send(ctx, conn, &securetunnelpb.Message{
				Type: securetunnelpb.Type_SESSION_RESET,
			})
		case streamID := <-f.emitStreamRst:
			_ = f.send(ctx, conn, &securetunnelpb.Message{
				Type:     securetunnelpb.Type_STREAM_RESET,
				StreamId: streamID,
			})
		}
	}
}

func (f *fakeV3Server) readLoop(ctx context.Context, conn *websocket.Conn) {
	buffer := []byte{}
	for {
		messageType, chunk, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if messageType != websocket.MessageBinary {
			return
		}
		buffer = append(buffer, chunk...)
		for {
			if len(buffer) < 2 {
				break
			}
			length := int(binary.BigEndian.Uint16(buffer[:2]))
			if len(buffer) < 2+length {
				break
			}
			body := buffer[2 : 2+length]
			message := &securetunnelpb.Message{}
			if err := proto.Unmarshal(body, message); err != nil {
				return
			}
			buffer = buffer[2+length:]
			f.handleFrame(ctx, conn, message)
		}
	}
}

func (f *fakeV3Server) handleFrame(ctx context.Context, conn *websocket.Conn, message *securetunnelpb.Message) {
	f.behaviorMu.Lock()
	f.observed = append(f.observed, observedFrame{
		Type:     message.GetType(),
		StreamID: message.GetStreamId(),
		Payload:  append([]byte(nil), message.GetPayload()...),
	})
	echo := f.echoStreams
	f.behaviorMu.Unlock()

	switch message.GetType() {
	case securetunnelpb.Type_DATA:
		if echo {
			_ = f.send(ctx, conn, &securetunnelpb.Message{
				Type:      securetunnelpb.Type_DATA,
				StreamId:  message.GetStreamId(),
				ServiceId: message.GetServiceId(),
				Payload:   message.GetPayload(),
			})
		}
	}
}

func (f *fakeV3Server) send(ctx context.Context, conn *websocket.Conn, message *securetunnelpb.Message) error {
	body, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[:2], uint16(len(body)))
	copy(out[2:], body)
	return conn.Write(ctx, websocket.MessageBinary, out)
}

func (f *fakeV3Server) frames() []observedFrame {
	f.behaviorMu.Lock()
	defer f.behaviorMu.Unlock()
	out := make([]observedFrame, len(f.observed))
	copy(out, f.observed)
	return out
}

func (f *fakeV3Server) sessionReset() {
	select {
	case f.emitSessionRst <- struct{}{}:
	default:
	}
}

func (f *fakeV3Server) streamReset(streamID int32) {
	f.emitStreamRst <- streamID
}

// waitForFrame polls f.frames() until it contains a frame matching
// match. Returns the index of the first match or errors after timeout.
func (f *fakeV3Server) waitForFrame(timeout time.Duration, match func(observedFrame) bool) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		frames := f.frames()
		for i, frame := range frames {
			if match(frame) {
				return i, nil
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return -1, fmt.Errorf("timed out waiting for frame")
}

// httpClientForTesting forces the websocket Dial to reuse the
// httptest server's transport. coder/websocket's default client adds
// a deadline-aware transport; we strip TLS expectations by using the
// fake server's Client().
func (f *fakeV3Server) httpClient() *http.Client {
	return f.server.Client()
}

// drainConn reads from a net.Conn until EOF (or io.ErrClosedPipe) and
// returns the bytes seen. Used by happy-path tests to assert
// byte-level round-trip.
func drainConn(reader io.Reader, want int) ([]byte, error) {
	buffer := make([]byte, want)
	total := 0
	for total < want {
		n, err := reader.Read(buffer[total:])
		total += n
		if err != nil {
			if total == want {
				return buffer, nil
			}
			return buffer[:total], err
		}
	}
	return buffer, nil
}
