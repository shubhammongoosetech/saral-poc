package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GenerateCA creates an in-memory Root Certificate Authority for cluster mTLS
func GenerateCA(commonName string) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"SARAL Protocol Mesh CA"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}

// GenerateCert creates a signed certificate bound to a specific node/service identity (CN/SANs)
func GenerateCert(caCertPEM, caKeyPEM []byte, commonName string, hosts []string) ([]byte, []byte, error) {
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, errors.New("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("failed to decode CA key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate cert key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"SARAL Protocol Mesh Coordinator"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}

// BuildServerTLSConfig builds TLS 1.3 config with optional mutual TLS client certificate verification
func BuildServerTLSConfig(certPEM, keyPEM, caCertPEM []byte, requireMTLS bool) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid server certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if requireMTLS && len(caCertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCertPEM) {
			return nil, errors.New("failed to append CA cert to client CA pool")
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return errors.New("no verified peer certificate chains")
			}
			peerCert := verifiedChains[0][0]
			cn := strings.ToLower(peerCert.Subject.CommonName)
			if !strings.HasPrefix(cn, "saral-") {
				return fmt.Errorf("mTLS peer identity rejected: common name %q does not match trusted SARAL prefix", peerCert.Subject.CommonName)
			}
			return nil
		}
	}

	return config, nil
}

// BuildClientTLSConfig builds client TLS config for communicating with mutual TLS peers
func BuildClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM []byte) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if len(caCertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCertPEM) {
			return nil, errors.New("failed to append root CA")
		}
		config.RootCAs = pool
	}

	if len(clientCertPEM) > 0 && len(clientKeyPEM) > 0 {
		clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("invalid client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{clientCert}
	}

	return config, nil
}

// NewClient returns an HTTP client configured with TLS/mTLS transport
func NewClient(caCertPEM, clientCertPEM, clientKeyPEM []byte, timeout time.Duration) (*http.Client, error) {
	tlsConfig, err := BuildClientTLSConfig(caCertPEM, clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// LoadCertificatesFromDisk tries reading PEM files from disk if configured
func LoadCertificatesFromDisk(certPath, keyPath, caPath string) ([]byte, []byte, []byte, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	var caPEM []byte
	if caPath != "" {
		caPEM, _ = os.ReadFile(caPath)
	}
	return certPEM, keyPEM, caPEM, nil
}

// EnsureCertificates loads or provisions Root CA and service certificates on disk or in-memory
func EnsureCertificates(tlsDir, serviceID string, hosts []string) ([]byte, []byte, []byte, error) {
	candidateDirs := []string{
		tlsDir,
		os.Getenv("TLS_DIR"),
		"/etc/saral/tls",
		"/vault/tls",
		"../../infra/tls",
		"../infra/tls",
		"infra/tls",
	}

	var foundDir string
	for _, d := range candidateDirs {
		if d == "" {
			continue
		}
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			foundDir = d
			break
		}
	}

	if foundDir == "" {
		foundDir = "infra/tls"
		_ = os.MkdirAll(foundDir, 0755)
	}

	caCertPath := filepath.Join(foundDir, "ca.crt")
	caKeyPath := filepath.Join(foundDir, "ca.key")
	certPath := filepath.Join(foundDir, serviceID+".crt")
	keyPath := filepath.Join(foundDir, serviceID+".key")

	var caCertPEM, caKeyPEM []byte
	var err error

	if _, err = os.Stat(caCertPath); err == nil {
		caCertPEM, _ = os.ReadFile(caCertPath)
		caKeyPEM, _ = os.ReadFile(caKeyPath)
	}

	if len(caCertPEM) == 0 || len(caKeyPEM) == 0 {
		caCertPEM, caKeyPEM, err = GenerateCA("SARAL Protocol Cluster Root CA")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate CA: %w", err)
		}
		_ = os.WriteFile(caCertPath, caCertPEM, 0644)
		_ = os.WriteFile(caKeyPath, caKeyPEM, 0600)
	}

	var certPEM, keyPEM []byte
	if _, err = os.Stat(certPath); err == nil {
		certPEM, _ = os.ReadFile(certPath)
		keyPEM, _ = os.ReadFile(keyPath)
	}

	if len(certPEM) == 0 || len(keyPEM) == 0 {
		certPEM, keyPEM, err = GenerateCert(caCertPEM, caKeyPEM, serviceID, hosts)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate cert for %s: %w", serviceID, err)
		}
		_ = os.WriteFile(certPath, certPEM, 0644)
		_ = os.WriteFile(keyPath, keyPEM, 0600)
	}

	return certPEM, keyPEM, caCertPEM, nil
}

// SetupMTLSServer configures and starts a TLS 1.3 mTLS server on the given address
func SetupMTLSServer(addr string, handler http.Handler, certPEM, keyPEM, caCertPEM []byte) (*http.Server, net.Listener, error) {
	tlsConfig, err := BuildServerTLSConfig(certPEM, keyPEM, caCertPEM, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build mTLS server config: %w", err)
	}

	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	server := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	return server, listener, nil
}


