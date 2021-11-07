package tls

import (
	"crypto/tls"
	"log"
	"net"
)

type HandShakeStatus int

const (
	Handinit HandShakeStatus = 0
	Handing  HandShakeStatus = 1
	HandOK   HandShakeStatus = 2
)

type TLSConn struct {
	tls net.Conn
	raw net.Conn
}

type TLSCache struct {
	conn      TLSConn
	HandStaus HandShakeStatus
	writeCnt  uint32
	out       tlsBuf
	in        tlsBuf
	tls       *tls.Conn
}

func New() (t *TLSCache, err error) {
	t = &TLSCache{
		out: *newTLSBuf(),
		in:  *newTLSBuf(),
	}
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	t.tls = tls.Client(&localConn{&t.out, &t.in}, conf)
	go func() {
		err = t.tls.Handshake()
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("client ssl ok")
		t.HandStaus = HandOK
	}()

	return
}

func (t *TLSCache) Encode(value []byte) []byte {
	t.tls.Write(value)
	return t.Read()
}

func (t *TLSCache) Decode(value []byte) []byte {
	data := make([]byte, 2048)
	t.out.Write(value)
	if n, err := t.tls.Read(data); err == nil {
		return data[:n]
	} else {
		log.Println(err)
	}
	return []byte{}
}

func (t *TLSCache) Read() []byte {
	data := make([]byte, 2048)
	n, _ := t.in.Read(data)
	if n > 0 {
		return data[0:n]
	} else {
		return []byte{}
	}

}

func (t *TLSCache) HandShake(value []byte, len uint32) []byte {

	if len > 0 {
		t.writeCnt = len
	}

	n, _ := t.out.Write(value)

	if t.writeCnt == 0 {
		return []byte{}
	}

	if n > 0 {
		t.writeCnt -= uint32(n)
	}

	if t.writeCnt == 0 {
		return t.Read()
	} else {
		return []byte{}
	}
}
