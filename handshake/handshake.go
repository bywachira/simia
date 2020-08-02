package handshake

import (
	"fmt"
	"io"
)

// A Handshake is a special message that a peer uses to identify itself
type Handshake struct {
	Pstr     string
	InfoHash [20]byte
	PeerID   [20]byte
}

// New creates new handshake connection with the standard pstr
func New(infoHash, peerID [20]byte) *Handshake {
	return &Handshake{
		Pstr:     "BitTorrent protocol",
		InfoHash: infoHash,
		PeerID:   peerID,
	}
}

// Serialize serializes the handshake to a buffer
func (h *Handshake) Serialize() []byte {
	pstrlen := len(h.Pstr)
	buflen := 49 + pstrlen

	buf := make([]byte, buflen)

	buf[0] = byte(pstrlen)

	copy(buf[1:], h.Pstr)

	copy(buf[1+pstrlen+8:], h.InfoHash[:])
	copy(buf[1+pstrlen+8+20:], h.PeerID[:])

	return buf
}

// Read parses a handshake from a stream
func Read(r io.Reader) (*Handshake, error) {
	lengthBuf := make([]byte, 1)

	_, err := io.ReadFull(r, lengthBuf)

	if err != nil {
		return nil, err
	}

	pstrlen := int(lengthBuf[0])

	if pstrlen == 0 {
		err := fmt.Errorf("pstrlen cannot be 0")

		return nil, err
	}

	handshakeBuf := make([]byte, 48+pstrlen)

	_, err = io.ReadFull(r, handshakeBuf)

	if err != nil {
		return nil, err
	}

	var infoHash, peerID [20]byte

	copy(infoHash[:], handshakeBuf[pstrlen+8:pstrlen+8+20])
	copy(peerID[:], handshakeBuf[pstrlen+8+20:])

	h := Handshake{
		Pstr:     string(handshakeBuf[0:pstrlen]),
		InfoHash: infoHash,
		PeerID:   peerID,
	}

	return &h, nil
}
