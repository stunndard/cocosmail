package core

import (
	"bufio"
	"bytes"
	"io"

	"github.com/stunndard/cocosmail/message"
)

// maxHeaderBlock caps the header block kept in memory. Without a blank line,
// the message is all header block, up to this size.
const maxHeaderBlock = 1 << 20

// queuedMessage is the message of a delivery, in its file in the store.
// Only the header block is kept in memory, to be changed: the body is read
// from the file each time the message is written, so a big message isn't
// held in memory.
type queuedMessage struct {
	store Storer
	key   string
	// Header is the header block, with the blank line ending it
	Header []byte
	// size of the header block in the file
	headerLen int64
}

// loadQueuedMessage reads the header block of the message stored as key
func loadQueuedMessage(store Storer, key string) (*queuedMessage, error) {
	r, err := store.Get(key)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	header, err := readHeaderBlock(r)
	if err != nil {
		return nil, err
	}
	return &queuedMessage{store: store, key: key, Header: header, headerLen: int64(len(header))}, nil
}

// readHeaderBlock reads r up to the first blank line, included
func readHeaderBlock(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)
	var header []byte
	for len(header) < maxHeaderBlock {
		line, err := br.ReadSlice('\n')
		header = append(header, line...)
		switch {
		case err == bufio.ErrBufferFull:
			continue
		case err == io.EOF:
			return header, nil
		case err != nil:
			return nil, err
		}
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	return header, nil
}

// Prepend adds header lines on top of the message
func (m *queuedMessage) Prepend(lines string) {
	m.Header = append([]byte(lines), m.Header...)
}

// MessageID is the Message-ID header, without <>
func (m *queuedMessage) MessageID() string {
	return string(message.RawGetMessageId(&m.Header))
}

// Body returns the message after the header block, from the file
func (m *queuedMessage) Body() (io.ReadCloser, error) {
	r, err := m.store.Get(m.key)
	if err != nil {
		return nil, err
	}
	if s, ok := r.(io.Seeker); ok {
		_, err = s.Seek(m.headerLen, io.SeekStart)
	} else {
		_, err = io.CopyN(io.Discard, r, m.headerLen)
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// Reader returns the message: the header block, as changed, then the body
func (m *queuedMessage) Reader() (io.ReadCloser, error) {
	body, err := m.Body()
	if err != nil {
		return nil, err
	}
	return messageReader{io.MultiReader(bytes.NewReader(m.Header), body), body}, nil
}

type messageReader struct {
	io.Reader
	io.Closer
}

// Excerpt returns the header block and the start of the body, at most limit
// bytes of it, and if the body was cut
func (m *queuedMessage) Excerpt(limit int64) (string, bool, error) {
	body, err := m.Body()
	if err != nil {
		return "", false, err
	}
	defer body.Close()
	start, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return "", false, err
	}
	cut := int64(len(start)) > limit
	if cut {
		start = start[:limit]
	}
	return string(m.Header) + string(start), cut, nil
}
