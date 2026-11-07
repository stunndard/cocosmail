// Provide tools for DKIM support

package core

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/jinzhu/gorm"
)

// DkimConfig represents DKIM configuration for a domain
type DkimConfig struct {
	Id       int64
	Domain   string
	PubKey   string `sql:"type:text;"`
	PrivKey  string `sql:"type:text;"`
	Selector string
	Headers  string
}

// DkimEnable enabled DKIM on domain
func DkimEnable(domain string) (dkc *DkimConfig, err error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	// Check if DKIM is alreadu enabled
	dkc = &DkimConfig{}
	err = DB.Where("domain = ?", domain).Find(dkc).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	} else if err == nil {
		return nil, errors.New("DKIM is already enabled on " + domain)
	}

	// Create new key pairs
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	privKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privKey),
	}
	// privKeyPem
	privKeyPem := string(pem.EncodeToMemory(&privKeyBlock))
	pubKeyDer, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}
	pubKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubKeyDer,
	}
	t := strings.Split(string(pem.EncodeToMemory(&pubKeyBlock)), "\n")
	pubKey := strings.Join(t[1:len(t)-2], "")

	// selector: unique to prevent collision with existing record
	selector := strconv.FormatInt(time.Now().Unix(), 10)

	// save
	dkc = &DkimConfig{
		Domain:   domain,
		PubKey:   pubKey,
		PrivKey:  privKeyPem,
		Selector: selector,
		Headers:  "",
	}

	err = DB.Save(dkc).Error
	return dkc, err
}

// DkimDisable Disable DKIM for domain domain by removing his
// DkimConfig entry
func DkimDisable(domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	// Check if DKIM is alreadu enabled
	err := DB.Where("domain = ?", domain).Delete(&DkimConfig{}).Error
	if err != nil && err == gorm.ErrRecordNotFound {
		return nil
	}
	return err
}

// DkimGetConfig returns DKIM config for domain domain
func DkimGetConfig(domain string) (dkc *DkimConfig, err error) {
	dkc = &DkimConfig{}
	domain = strings.ToLower(domain)
	err = DB.Where("domain = ?", domain).First(dkc).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		} else {
			return nil, err
		}
	}
	return dkc, nil
}

// dkimHeaders are the header fields signed
var dkimHeaders = []string{"from", "subject", "date", "message-id"}

// dkimSignature returns the DKIM-Signature header field of m for domain,
// with the key of dkc. The message is read from its file as a stream.
func dkimSignature(m *queuedMessage, domain string, dkc *DkimConfig) (string, error) {
	key, err := dkimPrivateKey(dkc.PrivKey)
	if err != nil {
		return "", err
	}
	signer, err := dkim.NewSigner(&dkim.SignOptions{
		Domain:     domain,
		Selector:   dkc.Selector,
		Signer:     key,
		HeaderKeys: dkimHeaders,
	})
	if err != nil {
		return "", err
	}
	r, err := m.Reader()
	if err != nil {
		signer.Close()
		return "", err
	}
	defer r.Close()
	if _, err := io.Copy(signer, r); err != nil {
		signer.Close()
		return "", err
	}
	if err := signer.Close(); err != nil {
		return "", err
	}
	return signer.Signature(), nil
}

// dkimPrivateKey parses a PEM private key, PKCS #1 or PKCS #8
func dkimPrivateKey(privKey string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(privKey))
	if block == nil {
		return nil, errors.New("the DKIM private key is not in PEM format")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("unable to parse the DKIM private key: " + err.Error())
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("the DKIM private key can't sign")
	}
	return signer, nil
}
