package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDkimSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pkcs8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	// the TXT record cocosmail tells to publish
	name, record, err := DkimDNSRecord(DkimData{Domain: "example.com", Selector: "sel", PrivateKey: pkcs1})
	require.NoError(t, err)
	lookup := func(domain string) ([]string, error) {
		assert.Equal(t, name, domain)
		return []string{record}, nil
	}

	body := strings.Repeat("line of the body\r\n", 50000)
	for _, privKey := range []string{pkcs1, pkcs8} {
		m := storeMessage(t, "From: alice@example.com\r\nSubject: hi\r\nMessage-ID: <a@b>\r\n\r\n"+body)
		m.Prepend("Received: cocosmail deliverd remote x; now\r\n")
		sig, err := dkimSignature(m, "example.com", &DkimConfig{PrivKey: privKey, Selector: "sel"})
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(sig, "DKIM-Signature: "))
		assert.True(t, strings.HasSuffix(sig, "\r\n"))
		assert.Contains(t, sig, "c=relaxed/simple;")
		// folded like our Received header
		lines := strings.Split(strings.TrimSuffix(sig, "\r\n"), "\r\n")
		assert.Greater(t, len(lines), 2)
		for _, l := range lines[1:] {
			assert.True(t, strings.HasPrefix(l, dkimIndent) && l[len(dkimIndent)] != ' ', l)
			assert.LessOrEqual(t, len(l), 78, l)
		}
		m.Prepend(sig)

		verifications, err := dkim.VerifyWithOptions(strings.NewReader(readMessage(t, m)), &dkim.VerifyOptions{LookupTXT: lookup})
		require.NoError(t, err)
		require.Len(t, verifications, 1)
		assert.NoError(t, verifications[0].Err)
		assert.Equal(t, "example.com", verifications[0].Domain)
		assert.Equal(t, dkimHeaders, verifications[0].HeaderKeys)
	}

	_, err = dkimSignature(storeMessage(t, "From: a@b\r\n\r\n"), "example.com", &DkimConfig{PrivKey: "not a key"})
	assert.Error(t, err)
}
