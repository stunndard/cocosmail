package core

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stunndard/cocosmail/message"
)

func storeMessage(t *testing.T, raw string) *queuedMessage {
	dir := t.TempDir()
	st, err := NewDiskStore(dir)
	require.NoError(t, err)
	require.NoError(t, st.Put("abcdef", strings.NewReader(raw)))
	m, err := loadQueuedMessage(st, "abcdef")
	require.NoError(t, err)
	return m
}

func readMessage(t *testing.T, m *queuedMessage) string {
	r, err := m.Reader()
	require.NoError(t, err)
	defer r.Close()
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(b)
}

func TestQueuedMessage(t *testing.T) {
	m := storeMessage(t, "Message-ID: <a@b>\r\nSubject: hi\r\n\r\nbody\r\n\r\nmore\r\n")
	assert.Equal(t, "Message-ID: <a@b>\r\nSubject: hi\r\n\r\n", string(m.Header))
	assert.Equal(t, "a@b", m.MessageID())

	m.Prepend("Received: here\r\n")
	m.Prepend("Return-Path: <x@y>\r\n")
	assert.Equal(t, "Return-Path: <x@y>\r\nReceived: here\r\nMessage-ID: <a@b>\r\nSubject: hi\r\n\r\nbody\r\n\r\nmore\r\n", readMessage(t, m))
	// read again, for another route
	assert.Contains(t, readMessage(t, m), "\r\n\r\nbody\r\n\r\nmore\r\n")

	excerpt, cut, err := m.Excerpt(6)
	require.NoError(t, err)
	assert.True(t, cut)
	assert.Equal(t, "Return-Path: <x@y>\r\nReceived: here\r\nMessage-ID: <a@b>\r\nSubject: hi\r\n\r\nbody\r\n", excerpt)
	excerpt, cut, err = m.Excerpt(100)
	require.NoError(t, err)
	assert.False(t, cut)
	assert.True(t, strings.HasSuffix(excerpt, "more\r\n"))
}

func TestQueuedMessageNoHeaders(t *testing.T) {
	// no blank line: all is header block
	m := storeMessage(t, "just text\r\nno blank line")
	assert.Equal(t, "just text\r\nno blank line", string(m.Header))
	assert.Equal(t, "just text\r\nno blank line", readMessage(t, m))

	// starts with the blank line: no header
	m = storeMessage(t, "\r\nbody\r\n")
	assert.Equal(t, "\r\n", string(m.Header))
	assert.Equal(t, "", m.MessageID())
	assert.Equal(t, "\r\nbody\r\n", readMessage(t, m))
}

func TestQueuedMessageLongLines(t *testing.T) {
	// a line longer than the read buffer
	long := "X-Long: " + strings.Repeat("a", 10000) + "\r\n"
	m := storeMessage(t, long+"\r\nbody")
	assert.Equal(t, long+"\r\n", string(m.Header))
	assert.Equal(t, long+"\r\nbody", readMessage(t, m))
}

func TestRedactAuthData(t *testing.T) {
	old := Cfg
	t.Cleanup(func() { Cfg = old })
	Cfg = &Config{}
	raw := "Received: from " + message.AuthDataStart + "client.isp.example ([203.0.113.7] helo=[laptop])" + message.AuthDataEnd + "\r\n" +
		"        by mail.example.com with ESMTPS\r\nSubject: hi\r\n\r\nbody\r\n"
	shown := "Received: from client.isp.example ([203.0.113.7] helo=[laptop])\r\n        by mail.example.com with ESMTPS\r\nSubject: hi\r\n\r\n"
	hidden := "Received: from local\r\n        by mail.example.com with ESMTPS\r\nSubject: hi\r\n\r\n"

	m := storeMessage(t, raw)
	m.redactAuthData(true)
	assert.Equal(t, hidden, string(m.Header), "remote")

	m = storeMessage(t, raw)
	m.redactAuthData(false)
	assert.Equal(t, shown, string(m.Header), "local")

	// tenants isolated
	Cfg.cfg.SmtpdHideReceivedFromAuthLocal = true
	m = storeMessage(t, raw)
	m.redactAuthData(false)
	assert.Equal(t, hidden, string(m.Header), "local, hidden")

	// a copy, for a pipe: the original keeps the marks
	m = storeMessage(t, raw)
	piped := *m
	piped.redactAuthData(false)
	assert.Equal(t, hidden, string(piped.Header))
	assert.Contains(t, string(m.Header), message.AuthDataStart)
}
