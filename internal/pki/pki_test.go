// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

const agentID = "0b1c2d3e-4f50-4a6b-8c7d-8e9fa0b1c2d3"

var now = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func csr(t *testing.T, key any, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: []string{"boese.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCAUndAgentZertifikat(t *testing.T) {
	ca, err := NewCA("Test-CA", now)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, err := ca.SignAgentCSR(csr(t, key, "admin"), agentID, 30*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	// Identität vergibt die Zentrale, nicht der CSR.
	if cert.Subject.CommonName != agentID || len(cert.DNSNames) != 0 {
		t.Errorf("Namen aus dem CSR übernommen: %v %v", cert.Subject, cert.DNSNames)
	}
	id, err := AgentID(cert)
	if err != nil || id != agentID {
		t.Fatalf("AgentID: %q %v", id, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("Agent-Zertifikat nicht gegen CA gültig: %v", err)
	}
	// Ein Agent-Zertifikat taugt nicht als Server-Zertifikat.
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Error("Agent-Zertifikat als Server-Zertifikat gültig")
	}
	if !cert.NotAfter.Equal(now.Add(30 * 24 * time.Hour).Truncate(time.Second)) {
		t.Errorf("Laufzeit: %v", cert.NotAfter)
	}
	// Ed25519 ist ebenfalls erlaubt.
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ca.SignAgentCSR(csr(t, edKey, "x"), agentID, time.Hour, now); err != nil {
		t.Errorf("Ed25519 abgelehnt: %v", err)
	}
}

func TestCSRNegativ(t *testing.T) {
	ca, _ := NewCA("Test-CA", now)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := csr(t, key, "x")
	if _, err := ca.SignAgentCSR(good, "keine-uuid", time.Hour, now); err == nil {
		t.Error("ungültige Agent-ID akzeptiert")
	}
	bad := append([]byte{}, good...)
	bad[len(bad)-5] ^= 0xff
	if _, err := ca.SignAgentCSR(bad, agentID, time.Hour, now); err == nil {
		t.Error("CSR mit kaputter Signatur akzeptiert")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := ca.SignAgentCSR(csr(t, rsaKey, "x"), agentID, time.Hour, now); err == nil {
		t.Error("RSA-Schlüssel akzeptiert")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := ca.SignAgentCSR(csr(t, p384, "x"), agentID, time.Hour, now); err == nil {
		t.Error("P-384 akzeptiert")
	}
	if _, err := ca.SignAgentCSR([]byte("müll"), agentID, time.Hour, now); err == nil {
		t.Error("Müll als CSR akzeptiert")
	}
}

func TestCASpeichernUndLaden(t *testing.T) {
	ca, _ := NewCA("Test-CA", now)
	der, err := ca.KeyDER()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(ca.CertPEM(), der)
	if err != nil || !loaded.Cert.Equal(ca.Cert) {
		t.Fatalf("LoadCA: %v", err)
	}
	other, _ := NewCA("Andere", now)
	otherKey, _ := other.KeyDER()
	if _, err := LoadCA(ca.CertPEM(), otherKey); err == nil {
		t.Error("fremder Schlüssel zur CA akzeptiert")
	}
}

func TestServerZertifikatUndPinning(t *testing.T) {
	ca, _ := NewCA("Test-CA", now)
	sc, err := ca.ServerCert([]string{"zentrale.test", "10.0.0.5"}, 30*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint(ca.Cert)
	got, err := VerifyPinnedServer(sc.Certificate, fp, "zentrale.test", now)
	if err != nil || !got.Equal(ca.Cert) {
		t.Fatalf("gültiger Server abgelehnt: %v", err)
	}
	if _, err := VerifyPinnedServer(sc.Certificate, fp, "10.0.0.5", now); err != nil {
		t.Errorf("IP-Name abgelehnt: %v", err)
	}
	// Falscher Fingerabdruck: anderer Server, z. B. Man-in-the-Middle.
	other, _ := NewCA("Angreifer", now)
	if _, err := VerifyPinnedServer(sc.Certificate, Fingerprint(other.Cert), "zentrale.test", now); err == nil ||
		!strings.Contains(err.Error(), "Fingerabdruck") {
		t.Errorf("falscher Fingerabdruck akzeptiert: %v", err)
	}
	// Angreifer liefert die echte CA mit, signiert aber selbst.
	evil, _ := other.ServerCert([]string{"zentrale.test"}, time.Hour, now)
	forged := [][]byte{evil.Certificate[0], ca.Cert.Raw}
	if _, err := VerifyPinnedServer(forged, fp, "zentrale.test", now); err == nil {
		t.Error("fremd signiertes Server-Zertifikat mit echter CA in der Kette akzeptiert")
	}
	if _, err := VerifyPinnedServer(sc.Certificate, fp, "anderer.test", now); err == nil {
		t.Error("falscher Hostname akzeptiert")
	}
	if _, err := VerifyPinnedServer(sc.Certificate, fp, "zentrale.test", now.AddDate(0, 2, 0)); err == nil {
		t.Error("abgelaufenes Server-Zertifikat akzeptiert")
	}
	if _, err := VerifyPinnedServer(sc.Certificate[:1], fp, "zentrale.test", now); err == nil {
		t.Error("Kette ohne CA akzeptiert")
	}
}

func TestAgentIDNurAusURI(t *testing.T) {
	ca, _ := NewCA("Test-CA", now)
	sc, _ := ca.ServerCert([]string{"x.test"}, time.Hour, now)
	if _, err := AgentID(sc.Leaf); err == nil {
		t.Error("Server-Zertifikat als Agent erkannt")
	}
}

func TestCABundle(t *testing.T) {
	now := time.Now()
	a, _ := NewCA("A", now)
	b, _ := NewCA("B", now)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "kein CA"}, NotBefore: now, NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: false}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, &leafKey.PublicKey, a.Key)
	leaf, _ := x509.ParseCertificate(der)
	got, err := ParseCABundle(CABundlePEM([]*x509.Certificate{b.Cert, a.Cert}))
	if err != nil || len(got) != 2 || Fingerprint(got[0]) != Fingerprint(b.Cert) {
		t.Fatalf("Reihenfolge: %v", err)
	}
	for name, in := range map[string][]byte{
		"CA und Nicht-CA": CABundlePEM([]*x509.Certificate{a.Cert, leaf}),
		"leer":            nil,
		"doppelt":         CABundlePEM([]*x509.Certificate{a.Cert, a.Cert}),
	} {
		if _, err := ParseCABundle(in); err == nil {
			t.Errorf("%s angenommen", name)
		}
	}
}
