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
	data      chan []byte
}

func New() (t *TLSCache, err error) {
	t = &TLSCache{
		data: make(chan []byte),
	}
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	localListener, err := net.Listen("tcp", "localhost:6666")
	if err != nil {
		log.Println(err)
	}
	go func() {
		t.conn.tls, err = tls.Dial("tcp", "localhost:6666", conf)
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("client ssl ok")
		t.HandStaus = HandOK
	}()

	t.conn.raw, err = localListener.Accept()
	if err != nil {
		log.Println(err)
		return
	}

	// go func() {
	// 	for {
	// 		data := make([]byte, 2048)
	// 		n, err := t.conn.raw.Read(data)
	// 		if err != nil {
	// 			log.Println(err)
	// 			break
	// 		}
	// 		if n > 0 {
	// 			t.data <- data[:n]
	// 		}
	// 	}
	// }()

	return
}

func (t *TLSCache) Encode(value []byte) []byte {
	t.conn.tls.Write(value)
	return t.Read()
}

func (t *TLSCache) Decode(value []byte) []byte {
	data := make([]byte, 2048)
	t.conn.raw.Write(value)
	if n, err := t.conn.tls.Read(data); err == nil {
		return data[:n]
	} else {
		log.Println(err)
	}
	return []byte{}
}

// func (t *TLSCache) Read() []byte {
// 	select {
// 	case data := <-t.data:
// 		return data
// 	default:
// 		return []byte{}
// 	}
// }

func (t *TLSCache) Read() []byte {
	data := make([]byte, 2048)
	n, _ := t.conn.raw.Read(data)
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

	n, _ := t.conn.raw.Write(value)

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
