package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	cert *x509.Certificate
	pkey *rsa.PrivateKey
)

const (
	caKeyName     = "cakey.pem"
	caCertName    = "cacert.pem"
	bits          = 2048
	organization  = "Proxify CA"
	country       = "US"
	province      = "CA"
	locality      = "San Francisco"
	streetAddress = "548 Market St"
	postalCode    = "94104"
)

// CACertPath returns the on-disk CA certificate path under dir
func CACertPath(dir string) string {
	return filepath.Join(dir, caCertName)
}

// CAKeyPath returns the on-disk CA private key path under dir
func CAKeyPath(dir string) string {
	return filepath.Join(dir, caKeyName)
}

func SaveCAToFile(filename string) error {
	buffer, err := GetRawCA()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, buffer.Bytes(), 0600)
}

func GetRawCA() (*bytes.Buffer, error) {
	buffer := &bytes.Buffer{}
	err := pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

func SaveKeyToFile(filename string) error {
	buffer := &bytes.Buffer{}
	err := pem.Encode(buffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pkey)})
	if err != nil {
		return err
	}
	return os.WriteFile(filename, buffer.Bytes(), 0600)
}

// maxSerialNumber is the upper boundary used to create unique serial numbers
var maxSerialNumber = big.NewInt(0).SetBytes(bytes.Repeat([]byte{255}, 20))

// newAuthority creates a new CA certificate and private key using the
// standard library, preserving the exact shape martian's mitm.NewAuthority
// produced (subject, key usages, SubjectKeyId, backdated NotBefore).
func newAuthority(name, organization string, validity time.Duration) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	serial, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{organization},
		},
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-validity),
		NotAfter:              time.Now().Add(validity),
		DNSNames:              []string{name},
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return x509c, priv, nil
}

// generateCertificate creates new certificate
func generateCertificate(certFile, keyFile string) error {
	var err error
	cert, pkey, err = newAuthority("Proxify CA", organization, time.Duration(24*365)*time.Hour)
	if err != nil {
		gologger.Fatal().Msgf("failed to generate CA Certificate")
	}
	if err = SaveCAToFile(certFile); err != nil {
		gologger.Fatal().Msgf("failed to save certFile to disk got %v", err)
	}
	if err := SaveKeyToFile(keyFile); err != nil {
		gologger.Fatal().Msgf("failed to write private key to file got %v", err)
	}
	return nil
}

func readCertNKeyFromDisk(certFile, keyFile string) error {
	block, err := readPemFromDisk(certFile)
	if err != nil {
		return err
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("expired certificate found")
	}
	block, err = readPemFromDisk(keyFile)
	if err != nil {
		return err
	}
	pkey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	return nil
}

func readPemFromDisk(filename string) (*pem.Block, error) {
	Bin, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(Bin)
	if block == nil {
		return nil, fmt.Errorf("failed to decode pem block got nil")
	}
	return block, nil
}

func LoadCerts(dir string) error {
	certFile := CACertPath(dir)
	keyFile := CAKeyPath(dir)

	if !fileutil.FileExists(certFile) || !fileutil.FileExists(keyFile) {
		return generateCertificate(certFile, keyFile)
	}
	if err := readCertNKeyFromDisk(certFile, keyFile); err != nil {
		return fmt.Errorf("malformed/expired certificate found generating new ones\nNote: Certificates must be reinstalled")
	}
	if cert == nil || pkey == nil {
		return errors.New("something went wrong, cannot start proxify")
	}
	return nil
}
