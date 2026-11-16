// Test fixture for pqscan.
package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
)

func newServerKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func serverConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10, // TODO: raise to TLS 1.3
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}
