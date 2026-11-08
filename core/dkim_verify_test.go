package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/authres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dkimTestKey sets up a key for example.com, selector sel, in the DNS
// lookups of the verifier
func dkimTestKey(t *testing.T) *DkimConfig {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	priv := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	name, record, err := DkimDNSRecord(DkimData{Domain: "example.com", Selector: "sel", PrivateKey: priv})
	require.NoError(t, err)
	old := dkimLookupTXT
	t.Cleanup(func() { dkimLookupTXT = old })
	dkimLookupTXT = func(domain string) ([]string, error) {
		switch domain {
		case name:
			return []string{record}, nil
		case "slow._domainkey.example.com":
			return nil, &net.DNSError{Err: "timeout", Name: domain, IsTimeout: true}
		}
		return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
	}
	return &DkimConfig{PrivKey: priv, Selector: "sel"}
}

// dkimSign returns raw signed for example.com
func dkimSign(t *testing.T, dkc *DkimConfig, raw string) string {
	sig, err := dkimSignature(storeMessage(t, raw), "example.com", dkc)
	require.NoError(t, err)
	return sig + raw
}

func verifyString(raw string) string {
	var s []string
	for _, r := range dkimVerify(strings.NewReader(raw)) {
		s = append(s, formatResult("mx", r, ""))
	}
	return strings.Join(s, "; ")
}

const dkimTestMessage = "From: alice@example.com\r\nSubject: hi\r\nDate: Mon, 9 Nov 2026 10:00:00 +0000\r\n\r\nbody\r\n"

func TestDkimVerify(t *testing.T) {
	dkc := dkimTestKey(t)
	signed := dkimSign(t, dkc, dkimTestMessage)

	assert.Equal(t, "dkim=pass header.d=example.com header.i=@example.com", verifyString(signed))
	assert.Equal(t, "dkim=none", verifyString(dkimTestMessage))
	assert.Equal(t, `dkim=fail reason="body hash did not verify" header.d=example.com header.i=@example.com`,
		verifyString(strings.Replace(signed, "body", "changed", 1)))
	assert.Contains(t, verifyString(strings.Replace(signed, "Subject: hi", "Subject: ho", 1)), "dkim=fail")

	// no key, DNS down
	assert.Contains(t, verifyString(strings.Replace(signed, "s=sel", "s=gone", 1)), "dkim=permerror")
	assert.Contains(t, verifyString(strings.Replace(signed, "s=sel", "s=slow", 1)), "dkim=temperror")

	// a result for each signature
	twice := dkimSign(t, dkc, signed)
	assert.Equal(t, "dkim=pass header.d=example.com header.i=@example.com; dkim=pass header.d=example.com header.i=@example.com", verifyString(twice))
}

func TestAuthResultsHeader(t *testing.T) {
	results := []authres.Result{
		&authres.DKIMResult{Value: authres.ResultPass, Domain: "example.com", Identifier: "@example.com"},
		&authres.DKIMResult{Value: authres.ResultPass, Domain: "esp.example", Identifier: "@esp.example"},
		&authres.DKIMResult{Value: authres.ResultFail, Reason: "body hash did not verify", Domain: "example.com"},
	}
	h := authResultsHeader("mail.example.com", results, []string{"mail.example.com"})
	assert.Equal(t, "Authentication-Results: mail.example.com;\r\n"+
		"        dkim=pass (author) header.d=example.com header.i=@example.com;\r\n"+
		"        dkim=pass (third-party) header.d=esp.example header.i=@esp.example;\r\n"+
		"        dkim=fail reason=\"body hash did not verify\" header.d=example.com\r\n", h)

	// no From: no comment
	h = authResultsHeader("mx", results[:1], nil)
	assert.Equal(t, "Authentication-Results: mx;\r\n        dkim=pass header.d=example.com header.i=@example.com\r\n", h)
	h = authResultsHeader("mx", []authres.Result{&authres.DKIMResult{Value: authres.ResultNone}}, []string{"example.com"})
	assert.Equal(t, "Authentication-Results: mx;\r\n        dkim=none\r\n", h)
}

func TestStripAuthResults(t *testing.T) {
	header := "Received: from x\r\n by y\r\n" +
		"Authentication-Results: mail.example.com;\r\n dkim=pass header.d=bank.example\r\n" +
		"Authentication-Results: mx.other.example; dkim=pass\r\n" +
		"authentication-results:MAIL.example.com 1 (forged); spf=pass\r\n" +
		"Subject: hi\r\n\r\n"
	got, removed := stripAuthResults([]byte(header), []string{"", "mail.example.com"})
	assert.Equal(t, 2, removed)
	assert.Equal(t, "Received: from x\r\n by y\r\nAuthentication-Results: mx.other.example; dkim=pass\r\nSubject: hi\r\n\r\n", string(got))

	got, removed = stripAuthResults([]byte("Subject: hi\r\n\r\n"), []string{"mail.example.com"})
	assert.Equal(t, 0, removed)
	assert.Equal(t, "Subject: hi\r\n\r\n", string(got))
}

// we add a Message-ID when it's missing: the signature covers its absence,
// the check sees the message as sent
func TestSpoolDkimClientData(t *testing.T) {
	dkc := dkimTestKey(t)
	spoolTestStore(t)
	signed := dkimSign(t, dkc, dkimTestMessage)
	require.Contains(t, signed, "message-id")

	sp, err := NewSpool()
	require.NoError(t, err)
	defer sp.Abort()
	_, err = sp.WriteString("Message-ID: <added@example.com>\r\n")
	require.NoError(t, err)
	sp.markDataStart()
	_, err = sp.WriteString(signed)
	require.NoError(t, err)

	whole, err := sp.Reader()
	require.NoError(t, err)
	b, err := io.ReadAll(whole)
	require.NoError(t, err)
	whole.Close()
	assert.Contains(t, verifyString(string(b)), "dkim=fail")

	r, err := sp.clientData()
	require.NoError(t, err)
	defer r.Close()
	assert.Equal(t, "dkim=pass header.d=example.com header.i=@example.com", formatResult("mx", dkimVerify(r)[0], ""))
}

// the headers go beside the message in the store, delivery adds them on top
func TestSpoolHeadersFile(t *testing.T) {
	dir := spoolTestStore(t)
	sp, err := NewSpool()
	require.NoError(t, err)
	_, err = sp.WriteString("Subject: hi\r\n\r\nbody\r\n")
	require.NoError(t, err)
	sp.setHeaders("Authentication-Results: mx; dkim=none\r\n")

	// plugins see what's delivered
	r, err := sp.Reader()
	require.NoError(t, err)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	r.Close()
	assert.Equal(t, "Authentication-Results: mx; dkim=none\r\nSubject: hi\r\n\r\nbody\r\n", string(b))

	require.NoError(t, sp.commit())
	assert.Empty(t, spoolFiles(t, dir))
	st, err := NewDiskStore(dir)
	require.NoError(t, err)
	m, err := loadQueuedMessage(st, sp.key)
	require.NoError(t, err)
	m.Prepend("Delivered-To: alice@example.com\r\n")
	assert.Equal(t, "Delivered-To: alice@example.com\r\nAuthentication-Results: mx; dkim=none\r\nSubject: hi\r\n\r\nbody\r\n", readMessage(t, m))

	require.NoError(t, delStored(st, sp.key))
	_, err = os.Stat(st.getStoragePath(sp.key) + headersSuffix)
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(st.getStoragePath(sp.key))
	assert.True(t, os.IsNotExist(err))

	// no headers file: nothing added, deleting the message works
	sp, err = NewSpool()
	require.NoError(t, err)
	_, err = sp.WriteString("Subject: hi\r\n\r\n")
	require.NoError(t, err)
	require.NoError(t, sp.commit())
	m, err = loadQueuedMessage(st, sp.key)
	require.NoError(t, err)
	assert.Equal(t, "Subject: hi\r\n\r\n", string(m.Header))
	assert.NoError(t, delStored(st, sp.key))
}

func TestSpoolAbortHeaders(t *testing.T) {
	dir := spoolTestStore(t)
	sp, err := NewSpool()
	require.NoError(t, err)
	sp.setHeaders("Authentication-Results: mx; dkim=none\r\n")
	// as if the move of the message failed after its headers file
	require.NoError(t, writeSynced(sp.path+headersSuffix, sp.headers))
	sp.Abort()
	assert.Empty(t, spoolFiles(t, dir))
}
