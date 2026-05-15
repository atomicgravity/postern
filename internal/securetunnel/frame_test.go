package securetunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	securetunnelpb "github.com/atomicgravity/postern/internal/securetunnel/proto"
)

// TestFramedReader_AcrossWebSocketFrames asserts the reader correctly
// reassembles tunneling envelopes that span multiple WebSocket frames.
// The V3 protocol guide is explicit: a tunneling Message may be split
// across WebSocket binary frames, and a single WebSocket frame can
// carry multiple Messages.
func TestFramedReader_AcrossWebSocketFrames(t *testing.T) {
	server, client := wsLoopback(t)

	messageA := &securetunnelpb.Message{
		Type:      securetunnelpb.Type_DATA,
		StreamId:  7,
		ServiceId: "SSH",
		Payload:   []byte("alpha"),
	}
	messageB := &securetunnelpb.Message{
		Type:      securetunnelpb.Type_DATA,
		StreamId:  7,
		ServiceId: "SSH",
		Payload:   []byte("beta"),
	}
	bytesA, _ := proto.Marshal(messageA)
	bytesB, _ := proto.Marshal(messageB)

	// Build a single byte stream with two length-prefixed envelopes
	// and ship it in pieces that intentionally don't align with
	// envelope boundaries.
	combined := make([]byte, 0, 4+len(bytesA)+len(bytesB))
	combined = appendLengthPrefixed(combined, bytesA)
	combined = appendLengthPrefixed(combined, bytesB)

	go func() {
		// First WebSocket frame carries everything except the last
		// 3 bytes of envelope B.
		split := len(combined) - 3
		_ = server.Write(context.Background(), websocket.MessageBinary, combined[:split])
		_ = server.Write(context.Background(), websocket.MessageBinary, combined[split:])
	}()

	reader := newFramedReader(client)
	gotA, err := reader.next(context.Background())
	if err != nil {
		t.Fatalf("reader.next A: %v", err)
	}
	if string(gotA.GetPayload()) != "alpha" {
		t.Fatalf("payload A: got %q want alpha", gotA.GetPayload())
	}
	gotB, err := reader.next(context.Background())
	if err != nil {
		t.Fatalf("reader.next B: %v", err)
	}
	if string(gotB.GetPayload()) != "beta" {
		t.Fatalf("payload B: got %q want beta", gotB.GetPayload())
	}
}

// TestFramedReader_TruncatedFrameSurfacesError asserts the reader
// reports a clean error when the WebSocket closes mid-envelope. The
// 2-byte length prefix can only represent up to 65535 bytes which is
// below the protocol-documented per-Message ceiling, so the
// maxFramePayload guard in framedReader.next is defensive (would only
// fire if the protocol ever widened to a 4-byte prefix); we exercise
// truncation here so a hostile or buggy peer cannot leave the reader
// blocked forever waiting for bytes that never arrive.
func TestFramedReader_TruncatedFrameSurfacesError(t *testing.T) {
	server, client := wsLoopback(t)
	client.SetReadLimit(int64(maxFramePayload + 1024))

	go func() {
		header := []byte{0, 100} // advertise 100 bytes
		_ = server.Write(context.Background(), websocket.MessageBinary, header)
		_ = server.Close(websocket.StatusNormalClosure, "")
	}()

	reader := newFramedReader(client)
	_, err := reader.next(context.Background())
	if err == nil {
		t.Fatal("expected error on truncated frame; got nil")
	}
	// Peer-close before envelope completion maps to io.EOF; if the
	// websocket library surfaces an abnormal-close status instead,
	// accept that as well.
	if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "securetunnel") {
		t.Fatalf("unexpected error class: %v", err)
	}
}

// wsLoopback returns a paired (server, client) coder/websocket pair
// connected via an in-memory httptest.Server. The caller can write
// arbitrary bytes onto server and read them off client (or vice versa)
// to exercise the framedReader / writeMessage paths in isolation.
//
// The handler holds open via a per-test done channel that t.Cleanup
// closes so the goroutine exits before goleak runs.
func wsLoopback(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	serverCh := make(chan *websocket.Conn, 1)
	done := make(chan struct{})
	httpServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
			Subprotocols: []string{wsSubprotocol},
		})
		if err != nil {
			t.Errorf("websocket accept: %v", err)
			return
		}
		serverCh <- conn
		// Hold the handler open until the test signals shutdown so
		// the underlying TCP connection stays alive for reads.
		select {
		case <-done:
		case <-request.Context().Done():
		}
	}))

	url := strings.Replace(httpServer.URL, "http://", "ws://", 1)
	client, _, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{
		HTTPClient:   httpServer.Client(),
		Subprotocols: []string{wsSubprotocol},
	})
	if err != nil {
		httpServer.Close()
		t.Fatalf("websocket dial: %v", err)
	}

	server := <-serverCh
	t.Cleanup(func() {
		close(done)
		_ = client.Close(websocket.StatusNormalClosure, "")
		_ = server.Close(websocket.StatusNormalClosure, "")
		httpServer.Close()
	})
	return server, client
}

func appendLengthPrefixed(buffer, payload []byte) []byte {
	prefix := []byte{0, 0}
	binary.BigEndian.PutUint16(prefix, uint16(len(payload)))
	buffer = append(buffer, prefix...)
	buffer = append(buffer, payload...)
	return buffer
}
