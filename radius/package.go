package radius

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// MaxPacketLength is the maximum wire length of a RADIUS packet.
const MaxPacketLength = 4096

// Code defines the RADIUS packet type.
type Code int

// Standard RADIUS packet codes.
const (
	CodeAccessRequest      Code = 1
	CodeAccessAccept       Code = 2
	CodeAccessReject       Code = 3
	CodeAccountingRequest  Code = 4
	CodeAccountingResponse Code = 5
	CodeAccessChallenge    Code = 11
	CodeStatusServer       Code = 12
	CodeStatusClient       Code = 13
	CodeDisconnectRequest  Code = 40
	CodeDisconnectACK      Code = 41
	CodeDisconnectNAK      Code = 42
	CodeCoARequest         Code = 43
	CodeCoAACK             Code = 44
	CodeCoANAK             Code = 45
	CodeReserved           Code = 255
)

type Packet struct {
	Code          Code
	Identifier    byte
	Authenticator [16]byte
	Attributes
}

// New creates a new packet
func New() *Packet {
	packet := &Packet{
		Code:       CodeAccessRequest,
		Identifier: 0,
	}
	if _, err := rand.Read(packet.Authenticator[:]); err != nil {
		return nil
	}
	return packet
}

func NewReply(req *Packet) *Packet {
	packet := &Packet{
		Code:       CodeAccessRequest,
		Identifier: req.Identifier + 1,
	}
	if _, err := rand.Read(packet.Authenticator[:]); err != nil {
		return nil
	}
	states, _ := req.State_Gets()
	for _, state := range states {
		packet.State_Add(state)
	}
	return packet
}

// Parse parses an encoded RADIUS packet b. An error is returned if the packet
// is malformed.
func Parse(b []byte) (*Packet, error) {
	if len(b) < 20 {
		return nil, errors.New("radius: packet not at least 20 bytes long")
	}

	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 20 || length > MaxPacketLength || len(b) < length {
		return nil, errors.New("radius: invalid packet length")
	}

	attrs, err := ParseAttributes(b[20:length])
	if err != nil {
		return nil, err
	}

	packet := &Packet{
		Code:       Code(b[0]),
		Identifier: b[1],
		Attributes: attrs,
	}
	copy(packet.Authenticator[:], b[4:20])
	return packet, nil
}

// MarshalBinary returns the packet in wire format.
//
// The authenticator in the returned data is copied from p.Authenticator
// without any hash calculation. Use Encode() if the packet is intended
// to be sent to a RADIUS client and requires the authenticator to be
// calculated.
func (p *Packet) MarshalBinary() ([]byte, error) {
	attributesLen, err := AttributesEncodedLen(p.Attributes)
	if err != nil {
		return nil, err
	}
	size := 20 + attributesLen
	if size > MaxPacketLength {
		return nil, errors.New("radius: packet is too large")
	}
	b := make([]byte, size)
	b[0] = byte(p.Code)
	b[1] = p.Identifier
	binary.BigEndian.PutUint16(b[2:4], uint16(size))
	copy(b[4:20], p.Authenticator[:])
	p.Attributes.encodeTo(b[20:])
	return b, nil
}
