package lib

import (
	"io"
	"log"
	"net"
	"time"
)

func SocksServerStart(addr string) (err error) {

	var listener net.Listener
	listener, err = net.Listen("tcp", addr)
	if err != nil {
		return
	}
	defer listener.Close()

	for {

		var iconn net.Conn
		iconn, err = listener.Accept()
		if err != nil {
			return
		}

		go func() {
			err := SocksServerHandleConn(iconn)
			if err != nil {
				log.Println(err)
			}
		}()

	}

}

func SocksServerHandleConn(iconn net.Conn) (err error) {

	log.Println("BEGIN HANDLE CONN", iconn.RemoteAddr())
	defer log.Println("END HANDLE CONN", iconn.RemoteAddr())

	defer iconn.Close()

	err = SocksServerNegotiate(iconn)
	if err != nil {
		return
	}

	var cmd byte
	var dst string
	cmd, dst, err = SocksServerSubNegotiate(iconn)

	err = SocksServerHandleCmd(iconn, cmd, dst)
	if err != nil {
		return
	}

	return

}

// ----- CMD -----

func SocksServerHandleCmd(iconn io.ReadWriter, cmd byte, dst string) (err error) {

	switch cmd {
	case 0x01 /* CONNECT */ :
		SocksServerHandleCmdConnect(iconn, dst)
	default:
		err = NewCommandNotSupportedError()
		return
	}

	return

}

func SocksServerHandleCmdConnect(iconn io.ReadWriter, dst string) (err error) {

	var oconn net.Conn
	oconn, err = net.DialTimeout("tcp", dst, 10*time.Second)
	if err != nil {
		return
	}
	defer oconn.Close()

	err = Concatenate(iconn, oconn)
	if err != nil {
		return
	}

	return

}

// ----- Negotiate -----

func SocksServerNegotiate(iconn io.ReadWriter) (err error) {

	var methods []byte
	methods, err = SocksServerNegotiateRead(iconn)
	if err != nil {
		return
	}

	method := SocksServerNegotiateResolveMethod(methods)

	err = SocksServerNegotiateWrite(iconn, method)
	if err != nil {
		return
	}

	return

}

func SocksServerNegotiateRead(iconn io.Reader) (methods []byte, err error) {

	// +-----+----------+----------+
	// | VER | NMETHODS | METHODS  |
	// +-----+----------+----------+
	// |  1  |    1     | 1 to 255 |
	// +-----+----------+----------+

	buf := make([]byte, 512)

	l := 0
	i := 0

	/* VER */
	l = 1
	_, err = io.ReadFull(iconn, buf[i:i+l])
	if err != nil {
		return
	}
	ver := buf[i]
	if ver != 0x05 /* SOCKS5 */ {
		err = NewVersionNotSupportedError()
		return
	}
	i += l

	/* NMETHODS */
	l = 1
	_, err = io.ReadFull(iconn, buf[i:i+l])
	if err != nil {
		return
	}
	nmethods := int(buf[i])
	i += l

	/* METHODS */
	l = nmethods
	_, err = io.ReadFull(iconn, buf[i:i+l])
	if err != nil {
		return
	}
	methods = buf[i : i+l]
	i += l

	return

}

func SocksServerNegotiateWrite(iconn io.Writer, method byte) (err error) {

	// +-----+--------+
	// | VER | METHOD |
	// +-----+--------+
	// |  1  |   1    |
	// +-----+--------+

	_, err = iconn.Write([]byte{0x05 /* SOCKS5 */, method})
	if err != nil {
		return
	}

	return

}

func SocksServerNegotiateResolveMethod(methods []byte) (method byte) {

	supported := []byte{
		0x00, /* NO AUTHENTICATION REQUIRED */
	}

	for _, c := range methods {
		for _, s := range supported {
			if c == s {
				return c
			}
		}
	}

	return 0xFF

}

// ----- Sub Negotiate -----

func SocksServerSubNegotiate(iconn io.ReadWriter) (cmd byte, dst string, err error) {

	cmd, dst, err = SocksServerSubNegotiateRead(iconn)
	if err != nil {
		return
	}

	err = SocksServerSubNegotiateWrite(iconn)
	if err != nil {
		return
	}

	return

}

func SocksServerSubNegotiateRead(iconn io.Reader) (cmd byte, dst string, err error) {

	// +-----+-----+-------+------+----------+----------+
	// | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +-----+-----+-------+------+----------+----------+
	// |  1  |  1  | X'00' |  1   | Variable |    2     |
	// +-----+-----+-------+------+----------+----------+

	buf := make([]byte, 512)

	l := 0
	i := 0

	/* VER */
	l = 1
	_, err = io.ReadFull(iconn, buf[i:i+l])
	if err != nil {
		return
	}
	ver := buf[i]
	if ver != 0x05 /* SOCKS5 */ {
		err = NewVersionNotSupportedError()
		return
	}
	i += l

	/* CMD */
	l = 1
	_, err = io.ReadFull(iconn, buf[i:i+l])
	if err != nil {
		return
	}
	cmd = buf[i]
	i += l

	/* RSV */
	l = 1
	_, err = io.ReadFull(iconn, buf[i:i+l])
	if err != nil {
		return
	}
	i += l

	/* DST */
	dst, err = ReadAddr(iconn)
	if err != nil {
		return
	}

	return

}

func SocksServerSubNegotiateWrite(iconn io.Writer) (err error) {

	// +-----+-----+-------+------+----------+----------+
	// | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +-----+-----+-------+------+----------+----------+
	// |  1  |  1  | X'00' |  1   | Variable |    2     |
	// +-----+-----+-------+------+----------+----------+

	_, err = iconn.Write([]byte{
		/* VER */ 0x05, /* SOCKS5 */
		/* REP */ 0x00,
		/* RSV */ 0x00,
		/* ATYP */ 0x01, /* IP V4 address */
		/* BND.ADDR */ 0x00, 0x00, 0x00, 0x00, /* 0.0.0.0 */
		/* BND.PORT */ 0x00, 0x00, /* 0 */
	})
	if err != nil {
		return
	}

	return

}
