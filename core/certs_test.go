package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeCert writes a new self-signed certificate for cn, with mtime
func writeCert(t *testing.T, crt, key, cn string, mtime time.Time) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDer, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}), 0600))
	touch(t, mtime, crt, key)
}

func touch(t *testing.T, mtime time.Time, files ...string) {
	for _, f := range files {
		require.NoError(t, os.Chtimes(f, mtime, mtime))
	}
}

func commonName(t *testing.T, c *Cert) string {
	cert, err := c.GetCertificate(nil)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	return leaf.Subject.CommonName
}

func TestCertReload(t *testing.T) {
	Logger = logrus.New()
	dir := t.TempDir()
	// certbot style: the files are symlinks to live/, which point to archive/
	archive := filepath.Join(dir, "archive")
	live := filepath.Join(dir, "live")
	require.NoError(t, os.Mkdir(archive, 0700))
	require.NoError(t, os.Mkdir(live, 0700))
	if err := os.Symlink(archive, filepath.Join(dir, "try")); err != nil {
		t.Skip("no symlinks:", err)
	}
	t0 := time.Now().Add(-time.Hour)
	writeCert(t, filepath.Join(archive, "fullchain1.pem"), filepath.Join(archive, "privkey1.pem"), "one", t0)
	link := func(n string) {
		for _, f := range []string{"fullchain", "privkey"} {
			l := filepath.Join(live, f+".pem")
			_ = os.Remove(l)
			require.NoError(t, os.Symlink(filepath.Join(archive, f+n+".pem"), l))
		}
	}
	link("1")
	crt, key := filepath.Join(dir, "smtp-t.crt"), filepath.Join(dir, "smtp-t.key")
	require.NoError(t, os.Symlink(filepath.Join(live, "fullchain.pem"), crt))
	require.NoError(t, os.Symlink(filepath.Join(live, "privkey.pem"), key))

	c, err := LoadCert(crt, key)
	require.NoError(t, err)
	assert.Equal(t, "one", commonName(t, c))
	again, err := LoadCert(crt, key)
	require.NoError(t, err)
	assert.Same(t, c, again, "shared")

	// renewed
	writeCert(t, filepath.Join(archive, "fullchain2.pem"), filepath.Join(archive, "privkey2.pem"), "two", t0.Add(time.Minute))
	link("2")
	assert.Equal(t, "two", commonName(t, c))

	// copied over, the .crt first: the old one is kept until the .key matches
	writeCert(t, filepath.Join(dir, "new.crt"), filepath.Join(dir, "new.key"), "three", t0)
	data, err := os.ReadFile(filepath.Join(dir, "new.crt"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(archive, "fullchain2.pem"), data, 0600))
	touch(t, t0.Add(2*time.Minute), filepath.Join(archive, "fullchain2.pem"))
	assert.Equal(t, "two", commonName(t, c))
	data, err = os.ReadFile(filepath.Join(dir, "new.key"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(archive, "privkey2.pem"), data, 0600))
	touch(t, t0.Add(2*time.Minute), filepath.Join(archive, "privkey2.pem"))
	assert.Equal(t, "three", commonName(t, c))

	// gone for a moment
	require.NoError(t, os.Remove(filepath.Join(live, "privkey.pem")))
	assert.Equal(t, "three", commonName(t, c))

	_, err = LoadCert(filepath.Join(dir, "none.crt"), filepath.Join(dir, "none.key"))
	assert.Error(t, err)
}
