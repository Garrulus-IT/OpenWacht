// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func verify(t *testing.T, ca *CA, leaf *x509.Certificate, name string) error {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: time.Now()})
	return err
}

// fremdLeaf stellt mit der CA ein Zertifikat für beliebige Namen aus, an
// HTTPSLeaf vorbei, so wie es ein Angreifer mit dem CA-Schlüssel täte.
func fremdLeaf(t *testing.T, ca *CA, names ...string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl, err := leafTemplate(names, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m, err := finishLeaf(tmpl, ca.Cert, ca.Key, key)
	if err != nil {
		t.Fatal(err)
	}
	return m.Leaf
}

func TestHTTPSCANameConstraints(t *testing.T) {
	now := time.Now()
	ca, err := NewHTTPSCA([]string{"openwacht.example.com", "10.10.0.5"}, now)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ca.HTTPSLeaf([]string{"openwacht.example.com", "10.10.0.5"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(t, ca, m.Leaf, "openwacht.example.com"); err != nil {
		t.Fatalf("eigener Name: %v", err)
	}
	if err := verify(t, ca, m.Leaf, "10.10.0.5"); err != nil {
		t.Fatalf("eigene IP: %v", err)
	}
	if d := m.Leaf.NotAfter.Sub(m.Leaf.NotBefore); d > 825*24*time.Hour || d < 190*24*time.Hour {
		t.Fatalf("Laufzeit %v", d)
	}
	if len(m.Leaf.ExtKeyUsage) != 1 || m.Leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("EKU serverAuth fehlt")
	}
	// Mit dem CA-Schlüssel ausgestellte Zertifikate für fremde Namen gelten nicht.
	for _, n := range []string{"bank.example", "example.com", "10.10.0.6"} {
		if err := verify(t, ca, fremdLeaf(t, ca, n), n); err == nil {
			t.Fatalf("%s: Zertifikat für fremden Namen wurde akzeptiert", n)
		}
	}
	// Unternamen des eingetragenen Namens sind erlaubt (RFC 5280).
	if err := verify(t, ca, fremdLeaf(t, ca, "x.openwacht.example.com"), "x.openwacht.example.com"); err != nil {
		t.Fatalf("Untername: %v", err)
	}
	if !ca.Cert.PermittedDNSDomainsCritical {
		t.Fatal("Beschränkung nicht kritisch")
	}
}

func TestHTTPSCANurIP(t *testing.T) {
	ca, err := NewHTTPSCA([]string{"192.0.2.10"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(t, ca, fremdLeaf(t, ca, "bank.example"), "bank.example"); err == nil {
		t.Fatal("CA nur mit IP darf keine DNS-Namen beglaubigen")
	}
	ca2, err := NewHTTPSCA([]string{"openwacht.example.com"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(t, ca2, fremdLeaf(t, ca2, "192.0.2.1"), "192.0.2.1"); err == nil {
		t.Fatal("CA nur mit DNS darf keine IP-Adressen beglaubigen")
	}
}

func TestSelfSignedUndTLS(t *testing.T) {
	m, err := SelfSigned([]string{"openwacht", "10.10.0.5"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.TLS()
	if err != nil {
		t.Fatal(err)
	}
	if c.Leaf.IsCA || c.Leaf.Subject.CommonName != "OpenWacht Einrichtung" {
		t.Fatal("falsches Einrichtungszertifikat")
	}
	if fp := SHA256Hex(c.Leaf); len(fp) != 95 || strings.Count(fp, ":") != 31 {
		t.Fatalf("Fingerabdruck %q", fp)
	}
	// Schlüssel eines anderen Zertifikats wird abgelehnt.
	m2, _ := SelfSigned([]string{"openwacht"}, time.Now())
	m.KeyDER = m2.KeyDER
	if _, err := m.TLS(); err == nil {
		t.Fatal("fremder Schlüssel angenommen")
	}
}

func pemKey(t *testing.T, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestParseUploaded(t *testing.T) {
	now := time.Now()
	ca, _ := NewHTTPSCA([]string{"openwacht.example.com"}, now)
	m, _ := ca.HTTPSLeaf([]string{"openwacht.example.com"}, now)
	got, err := ParseUploaded(append(m.CertPEM, ca.CertPEM()...), pemKey(t, m.KeyDER), []string{"openwacht.example.com"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(got.CertPEM), "BEGIN CERTIFICATE") != 2 {
		t.Fatal("Kette verloren")
	}
	if _, err := ParseUploaded(m.CertPEM, pemKey(t, m.KeyDER), []string{"anders.example.com"}, now); err == nil {
		t.Fatal("falscher Name angenommen")
	}
	if _, err := ParseUploaded(m.CertPEM, pemKey(t, m.KeyDER), []string{"openwacht.example.com"}, now.AddDate(1, 0, 0)); err == nil {
		t.Fatal("abgelaufenes Zertifikat angenommen")
	}
	other, _ := SelfSigned([]string{"openwacht.example.com"}, now)
	if _, err := ParseUploaded(m.CertPEM, pemKey(t, other.KeyDER), []string{"openwacht.example.com"}, now); err == nil {
		t.Fatal("fremder Schlüssel angenommen")
	}
	if _, err := ParseUploaded(ca.CertPEM(), pemKey(t, mustKey(t, ca)), nil, now); err == nil {
		t.Fatal("CA als Serverzertifikat angenommen")
	}
}

func mustKey(t *testing.T, ca *CA) []byte {
	k, err := ca.KeyDER()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNormalizeNames(t *testing.T) {
	got, err := NormalizeNames([]string{" OpenWacht.Example.com ", "10.10.0.5", "openwacht.example.com", "", "::1"})
	if err != nil || strings.Join(got, ",") != "openwacht.example.com,10.10.0.5,::1" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"*.example.com", "host:443", "-a.example", "a..b", "0.0.0.0", "ä.example", "fe80::1%eth0"} {
		if _, err := NormalizeNames([]string{bad}); err == nil {
			t.Fatalf("%q angenommen", bad)
		}
	}
	if _, err := NormalizeNames(nil); err == nil {
		t.Fatal("leere Liste angenommen")
	}
}
