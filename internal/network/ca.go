package network

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultMaxCertCacheSize limits the certificate cache to prevent unbounded memory growth from CONNECT spam (BUG-039).
const DefaultMaxCertCacheSize = 512

// CertificateAuthority manages dynamic TLS certificate generation for HTTPS interception.
type CertificateAuthority struct {
	caCert       *x509.Certificate
	caKey        *rsa.PrivateKey
	caPEM        []byte
	caDER        []byte
	certPath     string
	certCache    map[string]*tls.Certificate
	certOrder    []string
	maxCacheSize int
	mu           sync.RWMutex
}

// NewCertificateAuthority creates an in-memory Root CA and writes its PEM cert to a temp file.
func NewCertificateAuthority() (*CertificateAuthority, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SecretHarbor Local Security Authority"},
			CommonName:   "SecretHarbor Root CA",
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated root certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// Write CA cert to temporary file for SSL_CERT_FILE / NODE_EXTRA_CA_CERTS
	f, err := os.CreateTemp("", "secretharbor-ca-*.crt")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(certPEM); err != nil {
		return nil, err
	}

	return &CertificateAuthority{
		caCert:       caCert,
		caKey:        priv,
		caPEM:        certPEM,
		caDER:        derBytes,
		certPath:     f.Name(),
		certCache:    make(map[string]*tls.Certificate),
		maxCacheSize: DefaultMaxCertCacheSize,
	}, nil
}

// CertPath returns the filesystem path of the temporary Root CA certificate.
func (ca *CertificateAuthority) CertPath() string {
	if ca == nil {
		return ""
	}
	return ca.certPath
}

// GetHostCertificate dynamically signs a TLS certificate for a specific hostname.
// Limits cache size with LRU eviction to prevent unbounded memory growth (BUG-039).
func (ca *CertificateAuthority) GetHostCertificate(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	cleanHost := strings.ToLower(strings.Trim(host, "[]"))

	if cert, ok := ca.certCache[cleanHost]; ok {
		// Update LRU access order
		ca.promoteKey(cleanHost)
		return cert, nil
	}

	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cleanHost,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(cleanHost); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{cleanHost}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.caCert, &hostKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes, ca.caDER},
		PrivateKey:  hostKey,
	}

	maxSize := ca.maxCacheSize
	if maxSize <= 0 {
		maxSize = DefaultMaxCertCacheSize
	}

	// Evict oldest certs if cache exceeds limit
	for len(ca.certCache) >= maxSize && len(ca.certOrder) > 0 {
		oldest := ca.certOrder[0]
		ca.certOrder = ca.certOrder[1:]
		delete(ca.certCache, oldest)
	}

	ca.certCache[cleanHost] = cert
	ca.certOrder = append(ca.certOrder, cleanHost)
	return cert, nil
}

func (ca *CertificateAuthority) promoteKey(key string) {
	for idx, k := range ca.certOrder {
		if k == key {
			ca.certOrder = append(ca.certOrder[:idx], ca.certOrder[idx+1:]...)
			ca.certOrder = append(ca.certOrder, key)
			return
		}
	}
}

// Cleanup removes the temporary Root CA certificate file.
func (ca *CertificateAuthority) Cleanup() {
	if ca != nil && ca.certPath != "" {
		_ = os.Remove(ca.certPath)
	}
}
