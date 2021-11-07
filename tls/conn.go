package tls

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"
)

type tlsBuf struct {
	buf  bytes.Buffer
	cond sync.Cond
}

func newTLSBuf() *tlsBuf {
	return &tlsBuf{
		cond: *sync.NewCond(&sync.Mutex{}),
	}
}

func (b *tlsBuf) Read(p []byte) (int, error) {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()

	if b.buf.Len() == 0 {
		b.cond.Wait()
	}

	return b.buf.Read(p)
}

func (b *tlsBuf) Write(p []byte) (int, error) {

	b.buf.Write(p)
	if len(p) > 0 {
		b.cond.Broadcast()
	}
	return len(p), nil
}

type localConn struct {
	io.Reader
	io.Writer
}

func (c *localConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *localConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *localConn) Close() error { return nil }

func (c *localConn) SetDeadline(t time.Time) error { return nil }

func (c *localConn) SetReadDeadline(t time.Time) error { return nil }

func (c *localConn) SetWriteDeadline(t time.Time) error { return nil }
