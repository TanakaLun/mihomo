package httpmask

import (
	"io"
)

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func tryCloseRead(target any) error {
	if closer, ok := target.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return nil
}

func tryCloseWrite(target any) error {
	if closer, ok := target.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	if closer, ok := target.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
