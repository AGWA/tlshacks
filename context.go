package tlshacks

import (
	"context"
	"crypto/tls"
	"net"
)

type contextKeyType int

var ClientHelloKey = contextKeyType(0)

func ConnContext(ctx context.Context, conn net.Conn) context.Context {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return ctx
	}
	tlshelloConn, ok := tlsConn.NetConn().(*Conn)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, ClientHelloKey, tlshelloConn.ClientHello)
}
