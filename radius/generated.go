package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	UserName_Type        Type = 1
	NASIPAddress_Type    Type = 4
	FramedIPAddress_Type Type = 8
	ServiceType_Type     Type = 6
	FramedMTU_Type       Type = 12
	EAPMessage_Type      Type = 79
	State_Type           Type = 24

	MessageAuthenticator_Type Type = 80

	CallingStationID_Type Type = 31
	NASPortType_Type      Type = 61
	NASPortID_Type        Type = 87
)

type NASPortType uint32
type ServiceType uint32

const (
	NASPortType_Value_Ethernet NASPortType = 15
)
const (
	ServiceType_Value_FramedUser ServiceType = 2
)

var ErrNoAttribute = errors.New("radius: attribute not found")

// NewInteger creates a new Attribute from the given integer value.
func NewInteger(i uint32) Attribute {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, i)
	return v
}

// NewString returns a new Attribute from the given string. An error is returned
// if the string length is greater than 253.
func NewString(s string) (Attribute, error) {
	if len(s) > 253 {
		return nil, errors.New("string too long")
	}
	return Attribute(s), nil
}

// Bytes returns the given Attribute as a byte slice.
func Bytes(a Attribute) []byte {
	b := make([]byte, len(a))
	copy(b, a)
	return b
}

// NewBytes returns a new Attribute from the given byte slice. An error is
// returned if the slice is longer than 253.
func NewBytes(b []byte) (Attribute, error) {
	if len(b) > 253 {
		return nil, errors.New("value too long")
	}
	a := make(Attribute, len(b))
	copy(a, b)
	return a, nil
}

// NewIPAddr returns a new Attribute from the given IP address. An error is
// returned if the given address is not an IPv4 address.
func NewIPAddr(a net.IP) (Attribute, error) {
	a = a.To4()
	if a == nil {
		return nil, errors.New("invalid IPv4 address")
	}
	b := make(Attribute, len(a))
	copy(b, a)
	return b, nil
}

func (p *Packet) SetUserName(user string) {
	a, err := NewString(user)
	if err != nil {
		return
	}
	p.Attributes.Set(UserName_Type, a)
}

func (p *Packet) NASIPAddress_Add(addr string) {
	a, err := NewIPAddr(net.ParseIP(addr))
	if err != nil {
		return
	}
	p.Add(NASIPAddress_Type, a)
}

func (p *Packet) FramedIPAddress_Add(addr string) (err error) {
	a, err := NewIPAddr(net.ParseIP(addr))
	if err != nil {
		return
	}
	p.Add(FramedIPAddress_Type, a)
	return
}

func (p *Packet) FramedMTU_Add(value uint32) (err error) {
	a := NewInteger(value)
	p.Add(FramedMTU_Type, a)
	return
}

func (p *Packet) NASPortID_Add(switchPort string, vlanid uint32) {
	ID := fmt.Sprintf("slot=%d;subslot=%d;port=%d;vlanid=%d;interfaceName=%s", 0, 0, 0, vlanid, switchPort)
	a, err := NewString(ID)
	if err != nil {
		return
	}
	p.Attributes.Set(NASPortID_Type, a)
}

func (p *Packet) CallingStationID_Add(mac string) {
	a, err := NewString(mac)
	if err != nil {
		return
	}
	p.Attributes.Set(CallingStationID_Type, a)
}

func (p *Packet) NASPortType_Add(value NASPortType) (err error) {
	a := NewInteger(uint32(value))
	p.Add(NASPortType_Type, a)
	return
}

func (p *Packet) ServiceType_Add(value ServiceType) (err error) {
	a := NewInteger(uint32(value))
	p.Add(ServiceType_Type, a)
	return
}

func (p *Packet) EAPMessage_Set(value []byte) (err error) {
	const maximumChunkSize = 253
	var attrs []*AVP
	for len(value) > 0 {
		var a Attribute
		n := len(value)
		if n > maximumChunkSize {
			n = maximumChunkSize
		}
		a, err = NewBytes(value[:n])
		if err != nil {
			return
		}
		attrs = append(attrs, &AVP{
			Type:      EAPMessage_Type,
			Attribute: a,
		})
		value = value[n:]
	}
	p.Attributes = append(p.Attributes, attrs...)
	return
}

func (p *Packet) EAPMessage_Get() (value []byte, err error) {
	var i []byte
	var valid bool
	for _, avp := range p.Attributes {
		if avp.Type != EAPMessage_Type {
			continue
		}
		attr := avp.Attribute
		i = Bytes(attr)
		if err != nil {
			return
		}
		value = append(value, i...)
		valid = true
	}
	if !valid {
		err = ErrNoAttribute
	}
	return
}

func (p *Packet) State_Gets() (values [][]byte, err error) {
	var i []byte
	for _, avp := range p.Attributes {
		if avp.Type != State_Type {
			continue
		}
		attr := avp.Attribute
		i = Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func (p *Packet) State_Add(value []byte) (err error) {
	a, err := NewBytes(value)
	if err != nil {
		return
	}
	p.Add(State_Type, a)
	return
}

func (p *Packet) MessageAuthenticator_Set(secret string) (err error) {

	msgAuth := make([]byte, 16)
	a, err := NewBytes(msgAuth)
	if err != nil {
		return err
	}
	p.Set(MessageAuthenticator_Type, a)

	chunk, err := p.MarshalBinary()
	if err != nil {
		return err
	}

	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(chunk)
	result := mac.Sum(nil)
	if len(result) != 16 {
		return errors.New("hmac failed")
	}

	a, err = NewBytes(result)
	if err != nil {
		return
	}
	p.Set(MessageAuthenticator_Type, a)
	return
}
