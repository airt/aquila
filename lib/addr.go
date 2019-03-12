package lib

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
)

func ReadAddrBytes(iconn io.Reader, buf []byte) (n int, err error) {

	// +------+----------+------+
	// | ATYP |   ADDR   | PORT |
	// +------+----------+------+
	// |  1   | Variable |  2   |
	// +------+----------+------+

	l := 0
	i := 0

	/* ATYP */
	l = 1
	_, err = io.ReadFull(iconn, buf[i:i+l])
	if err != nil {
		return
	}
	atyp := buf[i]
	i += l

	/* ADDR */
	switch atyp {
	case 0x01: /* IP V4 address */
		l = net.IPv4len
		_, err = io.ReadFull(iconn, buf[i:i+l])
		if err != nil {
			return
		}
		i += l
	case 0x04: /* IP V6 address */
		l = net.IPv6len
		_, err = io.ReadFull(iconn, buf[i:i+l])
		if err != nil {
			return
		}
		i += l
	case 0x03: /* DOMAINNAME */
		l = 1
		_, err = io.ReadFull(iconn, buf[i:i+l])
		if err != nil {
			return
		}
		ldn := int(buf[i])
		i += l
		l = ldn
		_, err = io.ReadFull(iconn, buf[i:i+l])
		if err != nil {
			return
		}
		i += l
	default:
		err = NewAddressTypeNotSupportedError()
		return
	}

	/* PORT */
	l = 2
	_, err = io.ReadFull(iconn, buf[i:i+l])
	if err != nil {
		return
	}
	i += l

	n = i

	return

}

func ReadAddr(iconn io.Reader) (addr string, err error) {

	// +------+----------+------+
	// | ATYP |   ADDR   | PORT |
	// +------+----------+------+
	// |  1   | Variable |  2   |
	// +------+----------+------+

	buf := make([]byte, 512)
	var n int
	n, err = ReadAddrBytes(iconn, buf)
	if err != nil {
		return
	}

	/* ATYP */
	atyp := buf[0]

	/* ADDR */
	var host string
	switch atyp {
	case 0x01: /* IP V4 address */
		host = net.IP(buf[1 : 1+net.IPv4len]).String()
	case 0x04: /* IP V6 address */
		host = net.IP(buf[1 : 1+net.IPv6len]).String()
	case 0x03: /* DOMAINNAME */
		host = string(buf[2 : n-2])
	default:
		err = NewAddressTypeNotSupportedError()
		return
	}

	/* PORT */
	port := int(binary.BigEndian.Uint16(buf[n-2:]))

	addr = net.JoinHostPort(host, strconv.Itoa(port))

	return

}
