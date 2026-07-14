package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCAPair generates a CA/key pair with the given validity window and
// writes it to dir using the package's on-disk names and PEM formats.
func writeCAPair(t *testing.T, dir string, notBefore, notAfter time.Time) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Proxify CA", Organization: []string{organization}},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(CACertPath(dir), certPem, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CAKeyPath(dir), keyPem, 0600); err != nil {
		t.Fatal(err)
	}
}

func fileState(t *testing.T, path string) (string, time.Time) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return string(sum[:]), info.ModTime()
}

func TestCAPathAccessors(t *testing.T) {
	if got, want := CACertPath("/tmp/x"), filepath.Join("/tmp/x", "cacert.pem"); got != want {
		t.Fatalf("CACertPath = %q, want %q", got, want)
	}
	if got, want := CAKeyPath("/tmp/x"), filepath.Join("/tmp/x", "cakey.pem"); got != want {
		t.Fatalf("CAKeyPath = %q, want %q", got, want)
	}
}

func TestLoadCertsGeneratesValidCA(t *testing.T) {
	dir := t.TempDir()
	if err := LoadCerts(dir); err != nil {
		t.Fatalf("LoadCerts: %v", err)
	}

	for _, path := range []string{CACertPath(dir), CAKeyPath(dir)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s permissions = %o, want 0600", path, perm)
		}
	}

	certBlock, err := readPemFromDisk(CACertPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("generated cert does not parse: %v", err)
	}
	if ca.Subject.CommonName != "Proxify CA" {
		t.Errorf("CommonName = %q, want %q", ca.Subject.CommonName, "Proxify CA")
	}
	if len(ca.Subject.Organization) != 1 || ca.Subject.Organization[0] != organization {
		t.Errorf("Organization = %v, want [%q]", ca.Subject.Organization, organization)
	}
	if !ca.IsCA || !ca.BasicConstraintsValid {
		t.Error("certificate is not a valid CA")
	}
	wantUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	if ca.KeyUsage != wantUsage {
		t.Errorf("KeyUsage = %v, want %v", ca.KeyUsage, wantUsage)
	}
	if len(ca.ExtKeyUsage) != 1 || ca.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth]", ca.ExtKeyUsage)
	}
	oneYear := time.Duration(24*365) * time.Hour
	if got := ca.NotAfter.Sub(time.Now()); got > oneYear || got < oneYear-time.Hour {
		t.Errorf("NotAfter is %v from now, want ~one year", got)
	}
	if got := time.Now().Sub(ca.NotBefore); got > oneYear+time.Hour || got < oneYear-time.Hour {
		t.Errorf("NotBefore is %v ago, want backdated ~one year", got)
	}
	if len(ca.DNSNames) != 1 || ca.DNSNames[0] != "Proxify CA" {
		t.Errorf("DNSNames = %v, want [Proxify CA]", ca.DNSNames)
	}
	pkixpub, err := x509.MarshalPKIXPublicKey(ca.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyID := sha1.Sum(pkixpub)
	if !bytes.Equal(ca.SubjectKeyId, keyID[:]) {
		t.Errorf("SubjectKeyId = %x, want SHA-1 of PKIX public key %x", ca.SubjectKeyId, keyID)
	}
	if ca.SerialNumber.Sign() < 0 || ca.SerialNumber.Cmp(maxSerialNumber) >= 0 {
		t.Errorf("SerialNumber = %v, want in [0, 2^160)", ca.SerialNumber)
	}

	keyBlock, err := readPemFromDisk(CAKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if keyBlock.Type != "RSA PRIVATE KEY" {
		t.Errorf("key PEM type = %q, want RSA PRIVATE KEY (PKCS#1)", keyBlock.Type)
	}
	priv, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("generated key does not parse as PKCS#1: %v", err)
	}
	if priv.N.BitLen() != 2048 {
		t.Errorf("key size = %d bits, want 2048", priv.N.BitLen())
	}
	pub, ok := ca.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("cert public key is %T, want *rsa.PublicKey", ca.PublicKey)
	}
	if pub.N.Cmp(priv.N) != 0 {
		t.Error("certificate public key does not match private key")
	}
}

func TestLoadCertsSecondCallPreservesFiles(t *testing.T) {
	dir := t.TempDir()
	if err := LoadCerts(dir); err != nil {
		t.Fatalf("first LoadCerts: %v", err)
	}
	certHash, certMtime := fileState(t, CACertPath(dir))
	keyHash, keyMtime := fileState(t, CAKeyPath(dir))

	if err := LoadCerts(dir); err != nil {
		t.Fatalf("second LoadCerts: %v", err)
	}
	if h, m := fileState(t, CACertPath(dir)); h != certHash || !m.Equal(certMtime) {
		t.Error("second LoadCerts rewrote cacert.pem")
	}
	if h, m := fileState(t, CAKeyPath(dir)); h != keyHash || !m.Equal(keyMtime) {
		t.Error("second LoadCerts rewrote cakey.pem")
	}
}

func TestSaveCAToFileEqualsGetRawCA(t *testing.T) {
	dir := t.TempDir()
	if err := LoadCerts(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := GetRawCA()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "exported.pem")
	if err := SaveCAToFile(out); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, raw.Bytes()) {
		t.Error("SaveCAToFile output differs from GetRawCA")
	}
	block, _ := pem.Decode(saved)
	if block == nil {
		t.Fatal("saved CA is not valid PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("saved CA does not parse: %v", err)
	}
}

func TestLoadCertsPreGeneratedPKCS1Pair(t *testing.T) {
	dir := t.TempDir()
	writeCAPair(t, dir, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	certHash, certMtime := fileState(t, CACertPath(dir))

	if err := LoadCerts(dir); err != nil {
		t.Fatalf("LoadCerts on valid pre-generated pair: %v", err)
	}
	if h, m := fileState(t, CACertPath(dir)); h != certHash || !m.Equal(certMtime) {
		t.Error("LoadCerts rewrote a valid existing certificate")
	}
	if cert == nil || pkey == nil {
		t.Fatal("package globals not populated from disk")
	}
}

func TestLoadCertsExpiredCertReturnsError(t *testing.T) {
	dir := t.TempDir()
	writeCAPair(t, dir, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	err := LoadCerts(dir)
	if err == nil {
		t.Fatal("LoadCerts on expired certificate: want error, got nil")
	}
	if !strings.Contains(err.Error(), "malformed/expired certificate") {
		t.Errorf("error = %q, want the documented malformed/expired message", err)
	}
}
