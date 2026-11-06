package core

import (
	"crypto/tls"
	"fmt"
	"os"
	"path"
	"sync"
	"time"
)

// CertPaths returns the certificate and key files of a listener:
// ssl/PROTO-NAME.crt and .key
func CertPaths(proto, name string) (crt, key string) {
	base := path.Join(Cfg.GetBasePath(), "ssl", proto+"-"+name)
	return base + ".crt", base + ".key"
}

// Cert is a certificate loaded from files, loaded again when they change
// (certbot renewing them, through a symlink or a copy), checked on each TLS
// handshake and every few seconds. A broken new file is logged once and the
// old certificate is kept.
type Cert struct {
	crt, key string

	mu     sync.Mutex
	cert   *tls.Certificate
	stamp  fileStamp // of the files cert was loaded from
	failed fileStamp // of the files that failed to load
}

// size and modification time of both files, following symlinks
type fileStamp struct {
	crtSize, keySize int64
	crtMod, keyMod   time.Time
}

var (
	certsMu sync.Mutex
	certs   = make(map[[2]string]*Cert)
	// how often the files are checked without connections
	certCheckInterval = 5 * time.Second
)

// LoadCert returns the certificate of the files crt and key, shared by all
// listeners and sessions using them. It fails if they can't be loaded now.
func LoadCert(crt, key string) (*Cert, error) {
	certsMu.Lock()
	defer certsMu.Unlock()
	if c, ok := certs[[2]string{crt, key}]; ok {
		return c, nil
	}
	c := &Cert{crt: crt, key: key}
	stamp, err := c.files()
	if err == nil {
		err = c.load(stamp)
	}
	if err != nil {
		return nil, err
	}
	certs[[2]string{crt, key}] = c
	go func() {
		for range time.Tick(certCheckInterval) {
			c.GetCertificate(nil)
		}
	}()
	return c, nil
}

// LoadListenerCert is LoadCert for the certificate of a listener
func LoadListenerCert(proto, name string) (*Cert, error) {
	return LoadCert(CertPaths(proto, name))
}

// TLSConfig returns a server configuration using the certificate
func (c *Cert) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: c.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// GetCertificate returns the certificate, first loading it again if the
// files changed. For tls.Config.
func (c *Cert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	stamp, err := c.files()
	if err != nil || stamp == c.stamp || stamp == c.failed {
		// files missing for a moment: keep the old one
		return c.cert, nil
	}
	if err := c.load(stamp); err != nil {
		// maybe the .crt is written and the .key not yet: tried again when
		// they change
		c.failed = stamp
		Logger.Error(fmt.Sprintf("certificate %s not reloaded, the old one is used: %s", c.crt, err))
		return c.cert, nil
	}
	Logger.Info("certificate " + c.crt + " reloaded")
	return c.cert, nil
}

func (c *Cert) files() (fileStamp, error) {
	crt, err := os.Stat(c.crt)
	if err != nil {
		return fileStamp{}, err
	}
	key, err := os.Stat(c.key)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{crt.Size(), key.Size(), crt.ModTime(), key.ModTime()}, nil
}

func (c *Cert) load(stamp fileStamp) error {
	cert, err := tls.LoadX509KeyPair(c.crt, c.key)
	if err != nil {
		return err
	}
	c.cert, c.stamp = &cert, stamp
	return nil
}
