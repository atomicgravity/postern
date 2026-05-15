package securetunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	securetunnelpb "github.com/atomicgravity/postern/internal/securetunnel/proto"
)

// maxFramePayload is the V3 per-Message ceiling.
const maxFramePayload = 131076

// maxDataChunk is the SSH→WebSocket copy buffer size (AWS recommendation).
const maxDataChunk = 16 * 1024

// framedReader pulls 2-byte-length-prefixed protobuf envelopes off a
// WebSocket. The WebSocket binary-frame boundary is independent of the
// envelope, so we treat the connection as a byte stream and parse out
// of an internal buffer.
type framedReader struct {
	conn *websocket.Conn
	buf  []byte
}

func newFramedReader(conn *websocket.Conn) *framedReader {
	return &framedReader{conn: conn}
}

// next blocks until one full V3 Message has been read. Normal-closure
// errors map to io.EOF so callers treat the close as end-of-stream.
func (r *framedReader) next(ctx context.Context) (*securetunnelpb.Message, error) {
	for {
		if len(r.buf) >= 2 {
			length := int(binary.BigEndian.Uint16(r.buf[:2]))
			if length > maxFramePayload {
				return nil, ErrFrameTooLarge
			}
			if len(r.buf) >= 2+length {
				payload := r.buf[2 : 2+length]
				message := &securetunnelpb.Message{}
				if err := proto.Unmarshal(payload, message); err != nil {
					return nil, fmt.Errorf("securetunnel: decode message: %w", err)
				}
				// Trim the consumed bytes off the buffer head.
				r.buf = append(r.buf[:0], r.buf[2+length:]...)
				return message, nil
			}
		}

		messageType, chunk, err := r.conn.Read(ctx)
		if err != nil {
			if isNormalClosure(err) {
				return nil, io.EOF
			}
			return nil, err
		}
		if messageType != websocket.MessageBinary {
			return nil, fmt.Errorf("securetunnel: unexpected websocket message type %v", messageType)
		}
		r.buf = append(r.buf, chunk...)
	}
}

// writeMessage encodes a Message and writes it as a single binary frame.
// The caller serializes access (SourceProxy holds writeMu).
func writeMessage(ctx context.Context, conn *websocket.Conn, message *securetunnelpb.Message) error {
	body, err := proto.Marshal(message)
	if err != nil {
		return fmt.Errorf("securetunnel: marshal message: %w", err)
	}
	if len(body) > maxFramePayload {
		return fmt.Errorf("securetunnel: outgoing message %d bytes exceeds %d max", len(body), maxFramePayload)
	}
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[:2], uint16(len(body)))
	copy(out[2:], body)

	return conn.Write(ctx, websocket.MessageBinary, out)
}

// isNormalClosure recognizes peer-initiated teardown — CloseNormalClosure
// (1000), CloseGoingAway (1001), io.EOF, and context.Canceled.
func isNormalClosure(err error) bool {
	if err == nil {
		return false
	}
	status := websocket.CloseStatus(err)
	switch status {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	return false
}
