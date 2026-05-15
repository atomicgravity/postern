package broker

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"github.com/google/uuid"
)

// ID is a freshly minted certificate identifier. UUID is the canonical
// string form for logs and the SSH cert KeyId; Serial is an independently
// generated 64-bit random used as the SSH cert serial number — full 64 bits
// of entropy keeps SSH revocation-list collision risk negligible.
type ID struct {
	UUID   string
	Serial uint64
}

// UUIDv7Generator is the default IDGenerator. It produces UUIDv7 values via
// google/uuid plus an independent crypto/rand-derived 64-bit Serial. Rand
// may be nil to use crypto/rand directly; it's consulted only for Serial.
type UUIDv7Generator struct {
	Rand io.Reader
}

func (g UUIDv7Generator) NewID(_ time.Time) (ID, error) {
	v7, err := uuid.NewV7()
	if err != nil {
		return ID{}, err
	}

	// Generate Serial independently of the UUID for a full 64 bits of
	// entropy. UUIDv7's first 6 bytes are timestamp + version, leaving
	// only ~12 random bits per millisecond — concurrent mints would
	// risk KRL-revocation collisions.
	random := g.Rand
	if random == nil {
		random = rand.Reader
	}

	var serial [8]byte
	if _, err := io.ReadFull(random, serial[:]); err != nil {
		return ID{}, err
	}

	return ID{
		UUID:   v7.String(),
		Serial: binary.BigEndian.Uint64(serial[:]),
	}, nil
}
