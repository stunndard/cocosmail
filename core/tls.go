package core

import (
	"fmt"
)

//
func tlsGetVersion(v uint16) string {
	versionMap := map[uint16]string{
		0x0300: "SSL 3.0",
		0x0301: "TLS 1.0",
		0x0302: "TLS 1.1",
		0x0303: "TLS 1.2",
		0x0304: "TLS 1.3",
	}
	version, found := versionMap[v]
	if found {
		return version
	}
	return fmt.Sprintf("unknown tls: %x", v)
}

// tlsGetCipherSuite returns cipher suite as string
func tlsGetCipherSuite(cs uint16) string {
	csMap := map[uint16]string{
		0x0005: "TLS_RSA_WITH_RC4_128_SHA",
		0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
		// that the client is doing version fallback. See
		// https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00.
		0x5600: "TLS_FALLBACK_SCSV",
	}
	cipher, found := csMap[cs]
	if found {
		return cipher
	}
	return fmt.Sprintf("unknown cipher: %x", cs)
}
