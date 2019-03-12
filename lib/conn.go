package lib

import (
	"io"
)

func Pipe(src io.Reader, dst io.Writer) (err error) {

	buf := make([]byte, 4096)

	for {

		var nr, nw int

		nr, err = src.Read(buf)
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			return
		}

		nw, err = dst.Write(buf[:nr])
		if err != nil {
			return
		}

		if nr != nw {
			err = io.ErrShortWrite
			return
		}

	}

	return

}

func Concatenate(iconn io.ReadWriter, oconn io.ReadWriter) (err error) {

	r := make(chan error)

	go func() {
		r <- Pipe(iconn, oconn)
	}()

	go func() {
		r <- Pipe(oconn, iconn)
	}()

	err = <-r
	if err != nil {
		return
	}

	err = <-r
	if err != nil {
		return
	}

	return

}
