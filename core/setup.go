package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
)

var hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// SetupDomain returns the mail domain of the server hostname: mail.example.com
// gives example.com, example.com itself
func SetupDomain(hostname string) string {
	if _, parent, ok := strings.Cut(hostname, "."); ok && strings.Contains(parent, ".") {
		return parent
	}
	return hostname
}

// SetupSettings are the settings of a new server named hostname: SMTP on 25
// (other servers), 587 and 465 (mail clients), IMAP on 993, POP3 on 995,
// delivery of outgoing mail, DKIM signed. Listeners use the certificate
// named hostname.
func SetupSettings(hostname string) map[string]string {
	dsn := func(port, ssl string) string {
		return "[::]:" + port + ":" + hostname + ":" + ssl + ":" + hostname
	}
	return map[string]string{
		"me":                 hostname,
		"smtpd_launch":       "true",
		"smtpd_dsns":         dsn("25", "nossl") + ";" + dsn("587", "nossl") + ";" + dsn("465", "ssl"),
		"imapd_launch":       "true",
		"imapd_dsns":         dsn("993", "ssl"),
		"pop3d_launch":       "true",
		"pop3d_dsns":         dsn("995", "ssl"),
		"deliverd_launch":    "true",
		"deliverd_dkim_sign": "true",
	}
}

// Setup configures a new server named hostname, in a database without
// settings: SetupSettings, its mail domain, a DKIM key for it and self-signed
// certificates where there are none. It returns what it did.
func Setup(db *gorm.DB, hostname string) (done []string, err error) {
	hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if !hostnameRe.MatchString(hostname) {
		return nil, errors.New("bad hostname " + hostname + ", it must be like mail.example.com")
	}
	if stored, err := SettingsFromDB(db); err != nil {
		return nil, err
	} else if len(stored) > 0 {
		return nil, errors.New("the database has settings already")
	}
	if _, err = ImportSettings(db, SetupSettings(hostname), false); err != nil {
		return nil, err
	}
	done = append(done, "settings: SMTP on ports 25, 587 and 465, IMAP on 993, POP3 on 995, outgoing mail DKIM signed")
	if err = loadDBSettings(db); err != nil {
		return done, err
	}

	domain := SetupDomain(hostname)
	if err = RcpthostAdd(domain, true, false); err != nil && !strings.Contains(err.Error(), "already") {
		return done, err
	}
	done = append(done, "domain "+domain)
	if _, err = DkimEnable(domain); err != nil && !strings.Contains(err.Error(), "already") {
		return done, err
	}
	done = append(done, "DKIM key for "+domain)

	written, err := writeSelfSignedCerts(hostname)
	if len(written) > 0 {
		done = append(done, "self-signed certificate for "+hostname+": "+strings.Join(written, ", ")+
			", replace it with a real one")
	}
	return done, err
}

// writeSelfSignedCerts writes a certificate for hostname to the SMTP, IMAP
// and POP3 certificate files named hostname that don't exist
func writeSelfSignedCerts(hostname string) (written []string, err error) {
	var crtPEM, keyPEM []byte
	for _, proto := range []string{"smtp", "imap", "pop3"} {
		crt, key := CertPaths(proto, hostname)
		if fileExists(crt) || fileExists(key) {
			continue
		}
		if crtPEM == nil {
			if crtPEM, keyPEM, err = selfSignedCert(hostname); err != nil {
				return written, err
			}
		}
		if err = os.WriteFile(key, keyPEM, 0600); err != nil {
			return written, err
		}
		if err = os.WriteFile(crt, crtPEM, 0644); err != nil {
			return written, err
		}
		written = append(written, "ssl/"+proto+"-"+hostname+".crt")
	}
	return written, nil
}

// selfSignedCert returns a certificate for hostname, valid for 10 years
func selfSignedCert(hostname string) (crtPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	crtPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return crtPEM, keyPEM, nil
}
