package securetunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"

	securetunnelpb "github.com/atomicgravity/postern/internal/securetunnel/proto"
)

// awaitServiceIDs blocks for the V3 destination's first frame and validates
// that our serviceID appears in its published list. The reader is preserved
// on s.preReader so the read loop inherits any trailing buffered frames.
func (s *SourceProxy) awaitServiceIDs(ctx context.Context) error {
	reader := newFramedReader(s.conn)
	s.preReader = reader

	message, err := reader.next(ctx)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return ErrServiceIDsNotReceived
		}
		return fmt.Errorf("securetunnel: read SERVICE_IDS: %w", err)
	}

	if message.GetType() != securetunnelpb.Type_SERVICE_IDS {
		return fmt.Errorf("securetunnel: first frame %s, expected SERVICE_IDS", message.GetType())
	}

	published := message.GetAvailableServiceIds()
	for _, name := range published {
		if name == s.serviceID {
			s.logger.Debug("service-ids received", slog.Any("published", published), slog.String("expected", s.serviceID))
			return nil
		}
	}

	return fmt.Errorf("%w: expected %q in %v", ErrServiceIDMismatch, s.serviceID, published)
}

// runReadLoop owns the WebSocket read side. Returns (and terminates the
// proxy) on context cancel, peer close, or unrecoverable protocol error.
func (s *SourceProxy) runReadLoop() {
	defer s.wg.Done()

	reader := s.preReader
	if reader == nil {
		reader = newFramedReader(s.conn)
	}

	for {
		message, err := reader.next(s.rootCtx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.terminate(nil)
				return
			}
			if errors.Is(err, context.Canceled) {
				s.terminate(nil)
				return
			}
			if errors.Is(err, ErrFrameTooLarge) {
				s.terminate(err)
				return
			}
			s.terminate(fmt.Errorf("%w: %v", ErrUnexpectedClose, err))
			return
		}
		s.dispatchMessage(message)
	}
}

// dispatchMessage routes one incoming Message to its handler.
func (s *SourceProxy) dispatchMessage(message *securetunnelpb.Message) {
	switch message.GetType() {
	case securetunnelpb.Type_DATA:
		s.handleData(message)

	case securetunnelpb.Type_STREAM_RESET:
		s.logger.Debug("stream-reset received", slog.Int("stream_id", int(message.GetStreamId())))
		st, ok := s.lookupStream(message.GetStreamId())
		if ok {
			s.closeStream(st, false)
		}

	case securetunnelpb.Type_CONNECTION_RESET:
		s.logger.Debug("connection-reset received", slog.Int("stream_id", int(message.GetStreamId())))
		// v1 is single-connection-per-stream: CONNECTION_RESET is
		// equivalent to STREAM_RESET. The listener stays alive for the
		// next accept.
		st, ok := s.lookupStream(message.GetStreamId())
		if ok {
			s.closeStream(st, false)
		}

	case securetunnelpb.Type_SESSION_RESET:
		s.logger.Debug("session-reset received")
		s.terminate(ErrSessionReset)

	case securetunnelpb.Type_SERVICE_IDS:
		// V3 allows republishing; validate again so a mid-session change
		// closes the tunnel.
		if !slices.Contains(message.GetAvailableServiceIds(), s.serviceID) {
			s.terminate(fmt.Errorf("%w: mid-session service-ids dropped %q", ErrServiceIDMismatch, s.serviceID))
		}

	case securetunnelpb.Type_STREAM_START, securetunnelpb.Type_CONNECTION_START:
		// Only the source initiates streams in V3; receiving these is
		// benign in v1. Honor the ignorable bit.
		if !message.GetIgnorable() {
			s.logger.Debug("unexpected source-side control frame", slog.String("type", message.GetType().String()))
		}

	default:
		if !message.GetIgnorable() {
			s.logger.Debug("unknown frame type", slog.String("type", message.GetType().String()))
		}
	}
}

// handleData routes a DATA frame to the matching local conn. Unknown
// stream-ids drop silently (V3 treats this as benign — the stream may have
// closed between send and dispatch).
func (s *SourceProxy) handleData(message *securetunnelpb.Message) {
	st, ok := s.lookupStream(message.GetStreamId())
	if !ok {
		return
	}
	if len(message.GetPayload()) == 0 {
		return
	}
	if _, err := st.conn.Write(message.GetPayload()); err != nil {
		s.logger.Debug("local tcp write failed", slog.Int("stream_id", int(st.id)), slog.String("err", err.Error()))
		s.closeStream(st, true)
	}
}

// runAcceptLoop owns the loopback listener.
func (s *SourceProxy) runAcceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.handleAccept(conn)
	}
}

// handleAccept registers a new stream, emits STREAM_START, and spawns the
// TCP→WebSocket pump.
//
// V1 destination is single-active-stream: any prior stream still in the map
// is stale (previous client hung, or a destination STREAM_RESET wasn't
// processed before a fresh accept). Evict before allocating so engineers
// always get the newest connection.
func (s *SourceProxy) handleAccept(conn net.Conn) {
	s.evictExistingStreams()

	streamID := s.allocateStreamID()
	st := &stream{id: streamID, conn: conn}

	s.streamsMu.Lock()
	s.streams[streamID] = st
	s.streamsMu.Unlock()

	s.logger.Debug("stream-start emit", slog.Int("stream_id", int(streamID)))
	if err := s.emitFrame(&securetunnelpb.Message{
		Type:     securetunnelpb.Type_STREAM_START,
		StreamId: streamID,
	}); err != nil {
		s.logger.Debug("stream-start emit failed", slog.Int("stream_id", int(streamID)), slog.String("err", err.Error()))
		s.closeStream(st, false)
		return
	}

	s.wg.Add(1)
	go s.runStreamPump(st)
}

// runStreamPump bridges local TCP bytes to outbound DATA frames. Returns on
// EOF / read error / root cancel and tears the stream down (emits
// STREAM_RESET so the destination closes its end).
func (s *SourceProxy) runStreamPump(st *stream) {
	defer s.wg.Done()

	buffer := make([]byte, maxDataChunk)
	for {
		// closeStream closes st.conn on root cancel, unblocking this Read.
		n, err := st.conn.Read(buffer)
		if n > 0 {
			emit := &securetunnelpb.Message{
				Type:     securetunnelpb.Type_DATA,
				StreamId: st.id,
				Payload:  append([]byte(nil), buffer[:n]...),
			}
			if writeErr := s.emitFrame(emit); writeErr != nil {
				s.logger.Debug("data emit failed", slog.Int("stream_id", int(st.id)), slog.String("err", writeErr.Error()))
				s.closeStream(st, true)
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				s.closeStream(st, true)
				return
			}
			s.logger.Debug("local tcp read failed", slog.Int("stream_id", int(st.id)), slog.String("err", err.Error()))
			s.closeStream(st, true)
			return
		}
	}
}

// emitFrame writes one Message to the WebSocket under writeMu.
func (s *SourceProxy) emitFrame(message *securetunnelpb.Message) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeMessage(s.rootCtx, s.conn, message)
}

// evictExistingStreams force-closes any stream still in the map, emitting
// STREAM_RESET so the destination tears its end down too. Called before
// allocating a new stream-id to keep V1's single-active-stream invariant.
func (s *SourceProxy) evictExistingStreams() {
	s.streamsMu.Lock()
	existing := make([]*stream, 0, len(s.streams))
	for _, st := range s.streams {
		existing = append(existing, st)
	}
	s.streamsMu.Unlock()

	for _, st := range existing {
		s.logger.Debug("evicting prior stream for new accept", slog.Int("stream_id", int(st.id)))
		s.closeStream(st, true)
	}
}

// closeStream removes one stream and closes its conn. emitReset = true when
// the source initiated the close (sends STREAM_RESET so the destination
// closes too); false when the destination's inbound STREAM_RESET drove the
// teardown (echoing would loop).
func (s *SourceProxy) closeStream(st *stream, emitReset bool) {
	st.closeOnce.Do(func() {
		s.streamsMu.Lock()
		delete(s.streams, st.id)
		s.streamsMu.Unlock()

		if emitReset {
			_ = s.emitFrame(&securetunnelpb.Message{
				Type:     securetunnelpb.Type_STREAM_RESET,
				StreamId: st.id,
			})
			s.logger.Debug("stream-reset emit", slog.Int("stream_id", int(st.id)))
		}
		_ = st.conn.Close()
	})
}

// lookupStream resolves a stream-id; (nil, false) when unknown.
func (s *SourceProxy) lookupStream(id int32) (*stream, bool) {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	st, ok := s.streams[id]
	return st, ok
}

// allocateStreamID returns a fresh non-zero stream-id via monotonic
// counter — readable logs, no teardown reuse races. Wraparound at 2^31 is
// not a concern for any realistic session length.
func (s *SourceProxy) allocateStreamID() int32 {
	for {
		current := s.nextStreamID.Load()
		next := current + 1
		if s.nextStreamID.CompareAndSwap(current, next) {
			return current
		}
	}
}
