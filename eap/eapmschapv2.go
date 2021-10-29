package eap

import (
	"crypto/des"
	"crypto/sha1"
	"encoding/binary"
	"math/rand"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

type MsChapV2OpCode uint8

const (
	MsChapV2Challenge MsChapV2OpCode = 1
	MsChapV2Response  MsChapV2OpCode = 2
	MsChapV2Success   MsChapV2OpCode = 3
	MsChapV2Failure   MsChapV2OpCode = 4
	MsChapV2ChangePwd MsChapV2OpCode = 7
)

type EapMSCHAPv2 struct {
	header  HeaderEap
	opCode  MsChapV2OpCode
	msID    uint8
	value   []byte //This is challenge for Challenge packet and response for response packet
	name    string
	message string
}

const msChapV2respLen = 49 //Fixed length for MsChapV2 response packet

func NewEapMsChapV2() *EapMSCHAPv2 {

	header := HeaderEap{
		msgType: MsChapv2,
	}

	msChapv2 := &EapMSCHAPv2{
		header: header,
	}

	return msChapv2

}

func (packet *EapMSCHAPv2) Encode() (bool, []byte) {

	buff := make([]byte, 1)

	buff[0] = byte(packet.opCode)

	if packet.GetCode() == EAPResponse && (packet.opCode == MsChapV2Success || packet.opCode == MsChapV2Failure) {
		packet.header.setLength(uint16(5 /*header*/ + 1 /*OpCode*/))
		if ok, header := packet.header.Encode(); ok {
			buff := append(header[:5], buff[0])
			return true, buff
		}
		return false, nil

	}

	buff = append(buff, packet.msID, 0, 0)

	if packet.GetCode() == EAPRequest && (packet.opCode == MsChapV2Success || packet.opCode == MsChapV2Failure) {

		buff = append(buff, []byte(packet.message)...)
		packet.header.setLength(uint16(5 /*header*/ + 1 /*OpCode*/ + 1 /*MsID*/ + 2 /*mslength*/ + len(packet.message)))

		binary.BigEndian.PutUint16(buff[2:], packet.header.GetLength()-5)

		if ok, header := packet.header.Encode(); ok {
			buff := append(header[:5], buff...)
			return true, buff
		}
		return false, nil

	}

	//Encode value and name if present
	if (packet.GetCode() == EAPRequest && packet.opCode == MsChapV2Challenge) ||
		(packet.GetCode() == EAPResponse && packet.opCode == MsChapV2Response) {
		buff = append(buff, byte(len(packet.value)))
		buff = append(buff, []byte(packet.value)...)
		buff = append(buff, []byte(packet.name)...)

		packet.header.setLength(uint16(5 /*header*/ + 1 /*OpCode*/ + 1 /*MsID*/ + 2 /*mslength*/ + 1 /*Value Size*/ +
			len(packet.value) + len(packet.name)))

		binary.BigEndian.PutUint16(buff[2:], packet.header.GetLength()-5)

		if ok, header := packet.header.Encode(); ok {
			buff := append(header[:5], buff...)
			return true, buff
		}
		return false, nil

	}

	return false, nil
}

func (packet *EapMSCHAPv2) Decode(buff []byte) bool {

	ok := packet.header.Decode(buff)

	if !ok {
		return false
	}

	packet.opCode = MsChapV2OpCode(buff[5])

	if packet.GetCode() == EAPResponse && (packet.opCode == MsChapV2Success || packet.opCode == MsChapV2Failure) {
		return true //Nothing more to decode
	}

	packet.msID = buff[6]

	msLength := binary.BigEndian.Uint16(buff[7:])

	if msLength+5 != packet.header.length {
		return false
	}

	if packet.GetCode() == EAPRequest && (packet.opCode == MsChapV2Success || packet.opCode == MsChapV2Failure) {
		packet.message = string(buff[9:])
		return true //Nothing else to decode
	}

	//Decode value and name if present
	if (packet.GetCode() == EAPRequest && packet.opCode == MsChapV2Challenge) ||
		(packet.GetCode() == EAPResponse && packet.opCode == MsChapV2Response) {
		valueSize := int(buff[9])

		if (packet.opCode == MsChapV2Challenge && valueSize != 0x10) ||
			(packet.opCode == MsChapV2Response && valueSize != 0x31) {
			return false //Length does not match according to the RFC
		}

		if len(buff[10:]) <= valueSize {
			return false //Value length mismatch or name field missing
		}

		//Value
		packet.value = make([]byte, valueSize)

		copy(packet.value, buff[10:10+valueSize])

		//Assigning the name
		packet.name = string(buff[10+valueSize:])

	}

	return true

}

func (packet *EapMSCHAPv2) GetId() uint8 {
	return packet.header.GetId()
}

func (packet *EapMSCHAPv2) GetCode() EapCode {
	return packet.header.GetCode()
}

func (packet *EapMSCHAPv2) GetType() EapType {
	return packet.header.GetType()
}

func (packet EapMSCHAPv2) GetOpCode() MsChapV2OpCode {
	return packet.opCode
}

func (packet EapMSCHAPv2) GetMsgID() uint8 {
	return packet.msID
}

func (packet EapMSCHAPv2) GetValue() []byte {
	retVal := make([]byte, len(packet.value))
	copy(retVal, packet.value)
	return retVal
}

func (packet EapMSCHAPv2) GetName() string {
	return packet.name
}

func (packet EapMSCHAPv2) GetMessage() string {
	return packet.message
}

//GetAuthChallenge returns the field auth challenge from a challenge packet
func (packet EapMSCHAPv2) GetAuthChallenge() []byte {

	if packet.GetCode() != EAPRequest || packet.opCode != MsChapV2Challenge {
		return nil //The packet does not contain an auth challenge token
	}

	retVal := make([]byte, len(packet.value))

	copy(retVal, packet.value)

	return retVal

}

//GetResponse Returns the response field from a response packet
func (packet EapMSCHAPv2) GetResponse() []byte {

	if packet.GetCode() != EAPResponse || packet.opCode != MsChapV2Response {
		return nil //The packet does not contain a response field
	}

	retVal := make([]byte, len(packet.value))

	copy(retVal, packet.value)

	return retVal

}

func (packet *EapMSCHAPv2) SetId(id uint8) {
	packet.header.SetId(id)
}

func (packet *EapMSCHAPv2) SetCode(code EapCode) {
	packet.header.SetCode(code)
}

func (packet *EapMSCHAPv2) SetOpCode(code MsChapV2OpCode) {
	packet.opCode = code
}

func (packet *EapMSCHAPv2) SetValue(val []byte) {
	if packet.GetCode() != EAPResponse || packet.opCode != MsChapV2Response {
		return
	}

	packet.value = make([]byte, len(val))
	copy(packet.value, val)
}

func (packet *EapMSCHAPv2) SetName(name string) {
	packet.name = name
}

// https://tools.ietf.org/html/rfc2759#section-8.2
func ChallengeHash(peerChallenge, authenticatorChallenge, userName []byte) []byte {
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authenticatorChallenge)
	h.Write(userName)
	return h.Sum(nil)[:8]
}

// https://tools.ietf.org/html/rfc2759#section-8.3
func NtPasswordHash(password string) []byte {
	encoded := utf16.Encode([]rune(password))
	passwordBuf := make([]byte, len(password)*2)
	for i := 0; i < len(encoded); i++ {
		binary.LittleEndian.PutUint16(passwordBuf[i*2:], encoded[i])
	}

	h := md4.New()
	h.Write(passwordBuf)
	return h.Sum(nil)
}

// https://tools.ietf.org/html/rfc2759#section-8.4
func HashNtPasswordHash(passwordHash []byte) []byte {
	h := md4.New()
	h.Write(passwordHash)
	return h.Sum(nil)
}

// https://tools.ietf.org/html/rfc2759#section-8.6
func DesEncrypt(clear, key []byte) []byte {
	keyWithParity := make([]byte, 8)

	next := byte(0)
	for i := 0; i < 7; i++ {
		keyWithParity[i] = (key[i] >> uint(i)) | next
		next = key[i] << uint(7-i)
	}
	keyWithParity[7] = next

	c, err := des.NewCipher(keyWithParity)
	if err != nil {
		panic(err)
	}
	ret := make([]byte, 8)
	c.Encrypt(ret, clear)
	return ret
}

// https://tools.ietf.org/html/rfc2759#section-8.5
func ChallengeResponse(challenge, passwordHash []byte) []byte {
	zPasswordHash := make([]byte, 21)
	copy(zPasswordHash, passwordHash)
	response := make([]byte, 24)
	copy(response, DesEncrypt(challenge, zPasswordHash[0:7]))
	copy(response[8:], DesEncrypt(challenge, zPasswordHash[7:14]))
	copy(response[16:], DesEncrypt(challenge, zPasswordHash[14:]))
	return response
}

func RandPeerChallenge() []byte {
	challenge := make([]byte, 16)
	rand.Read(challenge[:])
	return challenge
}

// https://tools.ietf.org/html/rfc2759#section-8.1
func GenerateNTResponse(userName, password string, authenticatorChallenge, peerChallenge []byte) []byte {
	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, []byte(userName))
	passwordHash := NtPasswordHash(password)
	return ChallengeResponse(challenge, passwordHash)
}

// https://tools.ietf.org/html/rfc2759#section-8.7
func GenerateAuthenticatorResponse(userName, password string, ntResponse, peerChallenge, authenticatorChallenge []byte) []byte {
	passwordHash := NtPasswordHash(password)
	passwordHashHash := HashNtPasswordHash(passwordHash)

	h := sha1.New()
	h.Write(passwordHashHash)
	h.Write(ntResponse)
	h.Write([]byte{
		0x4d, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x74, 0x6f,
		0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
		0x20, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74,
	})
	digest := h.Sum(nil)

	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, []byte(userName))

	h = sha1.New()
	h.Write(digest)
	h.Write(challenge)
	h.Write([]byte{
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x6d, 0x61, 0x6b, 0x65, 0x20, 0x69, 0x74, 0x20,
		0x64, 0x6f, 0x20, 0x6d, 0x6f, 0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x6f, 0x6e,
		0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	})
	digest = h.Sum(nil)
	return digest
}
