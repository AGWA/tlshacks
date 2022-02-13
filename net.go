package tlshacks

import (
	"bytes"
	"io"
	"net"
)

type Conn struct {
	net.Conn
	ClientHello []byte

	reader io.Reader
}

func (conn *Conn) Read(p []byte) (int, error) { return conn.reader.Read(p) }

func NewConn(conn net.Conn) (*Conn, error) {
	clientHello, err := ReadTLSRecord(conn)
	if err != nil {
		return nil, err
	}
	return &Conn{
		Conn:        conn,
		ClientHello: clientHello,
		reader:      io.MultiReader(bytes.NewReader(clientHello), conn),
	}, nil
}

type listener struct {
	net.Listener
}

func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewConn(conn)
}

func NewListener(inner net.Listener) net.Listener {
	return &listener{
		Listener: inner,
	}
}
