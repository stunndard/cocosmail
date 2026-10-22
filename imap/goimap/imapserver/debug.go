package imapserver

import "io"

// cocosmail: a protocol log for each connection, the DebugWriter option is
// one writer for all of them, with both directions mixed.

// SetDebug sets writers getting what the client sends (in) and what the
// server sends (out), decrypted. Call it in NewSession, before anything is
// sent.
func (c *Conn) SetDebug(in, out io.Writer) {
	c.debugIn, c.debugOut = in, out
}

func (c *Conn) debugReadWriter(rw io.ReadWriter) io.ReadWriter {
	return debugReadWriter{c, rw}
}

type debugReadWriter struct {
	c  *Conn
	rw io.ReadWriter
}

func (d debugReadWriter) Read(p []byte) (int, error) {
	n, err := d.rw.Read(p)
	if n > 0 && d.c.debugIn != nil {
		_, _ = d.c.debugIn.Write(p[:n])
	}
	return n, err
}

func (d debugReadWriter) Write(p []byte) (int, error) {
	n, err := d.rw.Write(p)
	if n > 0 && d.c.debugOut != nil {
		_, _ = d.c.debugOut.Write(p[:n])
	}
	return n, err
}
