// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// HTTPS-Zertifikate für die Oberfläche (Etappe 21a). Die Zentrale macht TLS
// selbst; Caddy entfällt.
//
//   - Einrichtung: ein selbstsigniertes Serverzertifikat für die Adressen des
//     Rechners, nur bis zum Ende des Assistenten. Der Browser warnt; den
//     Fingerabdruck gibt `installieren` aus.
//   - Eigene CA: eine Wurzel, die nur für die eingetragenen Namen gilt (Name
//     Constraints). Wer die Zentrale übernimmt, kann damit keine fremden
//     Seiten für die Geräte fälschen, auf denen die Wurzel installiert ist.
//   - Hochgeladen: Zertifikat und Schlüssel des Betreibers.

// HTTPSLeafValidity: Laufzeit der Serverzertifikate der eigenen CA. Apple
// verlangt höchstens 825 Tage; 200 Tage folgen den öffentlichen Regeln ab 2026.
const HTTPSLeafValidity = 200 * 24 * time.Hour

// HTTPSRenewBefore: so lange vor Ablauf stellt die Zentrale ein neues aus.
const HTTPSRenewBefore = 30 * 24 * time.Hour

// MaxNames: höchstens so viele Namen bzw. Adressen.
const MaxNames = 16

// ValidName prüft einen Hostnamen oder eine IP-Adresse für das Zertifikat.
// Keine Platzhalter (*), keine Ports, keine abschließenden Punkte.
func ValidName(n string) error {
	if n == "" || len(n) > 253 {
		return errors.New("Name leer oder zu lang")
	}
	if a, err := netip.ParseAddr(n); err == nil {
		if a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return fmt.Errorf("%q: diese Adresse geht nicht", n)
		}
		return nil
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%q ist kein gültiger Hostname", n)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("%q ist kein gültiger Hostname (nur Buchstaben, Ziffern, - und .)", n)
			}
		}
	}
	return nil
}

// NormalizeNames prüft die Liste, macht Hostnamen klein und entfernt Doppelte.
// Die Reihenfolge bleibt (der erste Name ist die Adresse der Oberfläche).
func NormalizeNames(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, n := range in {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if err := ValidName(n); err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(n); err == nil {
			n = a.String()
		} else {
			n = strings.ToLower(n)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("mindestens ein Name oder eine Adresse nötig")
	}
	if len(out) > MaxNames {
		return nil, fmt.Errorf("höchstens %d Namen", MaxNames)
	}
	return out, nil
}

func splitNames(names []string) (dns []string, ips []net.IP) {
	for _, n := range names {
		if a, err := netip.ParseAddr(n); err == nil {
			ips = append(ips, net.IP(a.AsSlice()))
		} else {
			dns = append(dns, n)
		}
	}
	return dns, ips
}

// NewHTTPSCA erzeugt die eigene CA der Oberfläche, beschränkt auf names
// (DNS-Namen samt Unternamen, IP-Adressen genau). Kommen keine DNS-Namen vor,
// erlaubt die CA nur „invalid“ (also praktisch keinen); ohne IP-Adressen nur
// 0.0.0.0/32 und ::/128 (also keine). Die Beschränkung ist kritisch markiert.
func NewHTTPSCA(names []string, now time.Time) (*CA, error) {
	if len(names) == 0 {
		return nil, errors.New("mindestens ein Name nötig")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	dns, ips := splitNames(names)
	if len(dns) == 0 {
		dns = []string{"invalid"}
	}
	var ranges []*net.IPNet
	for _, ip := range ips {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		ranges = append(ranges, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	if len(ranges) == 0 {
		ranges = []*net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(32, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(128, 128)}}
	}
	tmpl := &x509.Certificate{
		SerialNumber:                sn,
		Subject:                     pkix.Name{CommonName: "OpenWacht-Wurzel " + names[0], Organization: []string{"OpenWacht"}},
		NotBefore:                   now.Add(-5 * time.Minute),
		NotAfter:                    now.AddDate(10, 0, 0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         dns,
		PermittedIPRanges:           ranges,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Material ist ein Serverzertifikat mit Kette (PEM) und Schlüssel (PKCS#8).
type Material struct {
	CertPEM []byte // Serverzertifikat, danach ggf. Zwischenzertifikate
	KeyDER  []byte
	Leaf    *x509.Certificate
}

// TLS macht daraus ein tls.Certificate.
func (m Material) TLS() (tls.Certificate, error) {
	k, err := x509.ParsePKCS8PrivateKey(m.KeyDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	var c tls.Certificate
	rest := m.CertPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			c.Certificate = append(c.Certificate, b.Bytes)
		}
	}
	if len(c.Certificate) == 0 {
		return tls.Certificate{}, errors.New("kein Zertifikat")
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	pub, ok := k.(interface{ Public() crypto.PublicKey })
	if !ok {
		return tls.Certificate{}, errors.New("Schlüssel nicht nutzbar")
	}
	if eq, ok := pub.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(leaf.PublicKey) {
		return tls.Certificate{}, errors.New("Schlüssel passt nicht zum Zertifikat")
	}
	c.PrivateKey = k
	c.Leaf = leaf
	return c, nil
}

func leafTemplate(names []string, validity time.Duration, now time.Time) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	dns, ips := splitNames(names)
	return &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}, nil
}

func finishLeaf(tmpl, parent *x509.Certificate, signer crypto.Signer, key *ecdsa.PrivateKey, chain ...*x509.Certificate) (Material, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		return Material{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return Material{}, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Material{}, err
	}
	out := CertToPEM(leaf)
	for _, c := range chain {
		out = append(out, CertToPEM(c)...)
	}
	return Material{CertPEM: out, KeyDER: kd, Leaf: leaf}, nil
}

// HTTPSLeaf stellt mit der eigenen CA ein Serverzertifikat für names aus.
// Die Kette enthält die CA nicht (der Browser hat sie installiert).
func (ca *CA) HTTPSLeaf(names []string, now time.Time) (Material, error) {
	if len(names) == 0 {
		return Material{}, errors.New("mindestens ein Name nötig")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, err
	}
	tmpl, err := leafTemplate(names, HTTPSLeafValidity, now)
	if err != nil {
		return Material{}, err
	}
	return finishLeaf(tmpl, ca.Cert, ca.Key, key)
}

// SelfSigned erzeugt das vorläufige Zertifikat für den Assistenten
// (selbstsigniert, 30 Tage).
func SelfSigned(names []string, now time.Time) (Material, error) {
	if len(names) == 0 {
		return Material{}, errors.New("mindestens ein Name nötig")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, err
	}
	tmpl, err := leafTemplate(names, 30*24*time.Hour, now)
	if err != nil {
		return Material{}, err
	}
	tmpl.Subject = pkix.Name{CommonName: "OpenWacht Einrichtung", Organization: []string{"OpenWacht"}}
	return finishLeaf(tmpl, tmpl, key, key)
}

// ParseUploaded prüft ein hochgeladenes Zertifikat (PEM, mit Kette) und den
// Schlüssel (PEM: PKCS#8, PKCS#1 oder EC). Es muss für names[0] gelten, noch
// gültig sein und darf keine CA sein. Rückgabe mit Schlüssel als PKCS#8.
func ParseUploaded(certPEM, keyPEM []byte, names []string, now time.Time) (Material, error) {
	if len(certPEM) > 60000 || len(keyPEM) > 16000 {
		return Material{}, errors.New("Zertifikat oder Schlüssel zu groß")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Material{}, errors.New("Zertifikat und Schlüssel passen nicht zusammen oder sind kein PEM")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return Material{}, err
	}
	if leaf.IsCA {
		return Material{}, errors.New("das erste Zertifikat ist eine CA, nicht das Serverzertifikat")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return Material{}, fmt.Errorf("Zertifikat gilt nicht (gültig von %s bis %s)", leaf.NotBefore.Format("02.01.2006"), leaf.NotAfter.Format("02.01.2006"))
	}
	if len(names) > 0 {
		if err := leaf.VerifyHostname(names[0]); err != nil {
			return Material{}, fmt.Errorf("Zertifikat gilt nicht für %s", names[0])
		}
	}
	kd, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		return Material{}, errors.New("Schlüsseltyp wird nicht unterstützt")
	}
	var out []byte
	for _, der := range pair.Certificate {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return Material{CertPEM: out, KeyDER: kd, Leaf: leaf}, nil
}

// SHA256Hex ist der SHA-256 über das ganze Zertifikat in der Form, die
// Browser anzeigen (AB:CD:…).
func SHA256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}
