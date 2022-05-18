// Copyright (C) 2022 Andrew Ayer
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

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
	peekedBytes := new(bytes.Buffer)
	clientHello, err := NewHandshakeReader(io.TeeReader(conn, peekedBytes)).ReadMessage()
	if err != nil {
		return nil, err
	}
	return &Conn{
		Conn:        conn,
		ClientHello: clientHello,
		reader:      io.MultiReader(peekedBytes, conn),
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
