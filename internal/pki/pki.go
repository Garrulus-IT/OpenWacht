// SPDX-License-Identifier: AGPL-3.0-only

// Package pki enthält die Zertifikatsstelle für Agents: eine eigene CA, die
// Client-Zertifikate für Agents und das Server-Zertifikat des Agent-Ports der
// Zentrale ausstellt. Nur Standardbibliothek, ECDSA P-256.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// AgentURIPrefix steht im URI-SAN jedes Agent-Zertifikats, gefolgt von der Agent-ID.
const AgentURIPrefix = "urn:openwacht:agent:"

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// CA ist die Zertifikatsstelle für Agents.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func serial() (*big.Int, error) {
	// 128 Bit Zufall, positiv
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// NewCA erzeugt eine neue CA mit 10 Jahren Laufzeit. Sie darf nur
// End-Zertifikate ausstellen (MaxPathLen 0).
func NewCA(name string, now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"OpenWacht"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
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

// CertPEM ist das CA-Zertifikat als PEM.
func (ca *CA) CertPEM() []byte { return CertToPEM(ca.Cert) }

// KeyDER ist der private Schlüssel (PKCS#8) zum verschlüsselten Speichern.
func (ca *CA) KeyDER() ([]byte, error) { return x509.MarshalPKCS8PrivateKey(ca.Key) }

// LoadCA setzt eine CA aus gespeichertem Zertifikat (PEM) und Schlüssel (PKCS#8) zusammen.
func LoadCA(certPEM, keyDER []byte) (*CA, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("CA-Schlüssel passt nicht zum CA-Zertifikat")
	}
	if !cert.IsCA {
		return nil, errors.New("gespeichertes Zertifikat ist keine CA")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Fingerprint ist der SHA-256 über den öffentlichen Schlüssel (SPKI) eines
// Zertifikats, Base64url ohne Auffüllung. Steckt im Registrierungs-Token.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ServerCert stellt das TLS-Zertifikat für den Agent-Port aus.
func (ca *CA) ServerCert(names []string, validity time.Duration, now time.Time) (tls.Certificate, error) {
	if len(names) == 0 {
		return tls.Certificate{}, errors.New("mindestens ein Name für das Server-Zertifikat nötig")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	sn, err := serial()
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Kette mit CA, damit der Agent beim ersten Kontakt die CA prüfen kann.
	return tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// SignAgentCSR prüft einen CSR und stellt ein Client-Zertifikat für agentID
// aus. Was im CSR an Namen steht, wird ignoriert: Identität vergibt nur die
// Zentrale. Erlaubt sind ECDSA P-256 und Ed25519.
func (ca *CA) SignAgentCSR(csrDER []byte, agentID string, validity time.Duration, now time.Time) (*x509.Certificate, error) {
	if !uuidRE.MatchString(agentID) {
		return nil, errors.New("ungültige Agent-ID")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("CSR nicht lesbar: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR-Signatur ungültig: %w", err)
	}
	if err := checkAgentKey(csr.PublicKey); err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(AgentURIPrefix + agentID)
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: agentID},
		URIs:         []*url.URL{u},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func checkAgentKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return errors.New("nur ECDSA P-256 oder Ed25519 erlaubt")
		}
	case ed25519.PublicKey:
	default:
		return errors.New("nur ECDSA P-256 oder Ed25519 erlaubt")
	}
	return nil
}

// AgentID liest die Agent-ID aus einem (bereits geprüften) Client-Zertifikat.
func AgentID(cert *x509.Certificate) (string, error) {
	if len(cert.URIs) != 1 {
		return "", errors.New("Zertifikat enthält keine eindeutige Agent-Kennung")
	}
	s := cert.URIs[0].String()
	id, ok := strings.CutPrefix(s, AgentURIPrefix)
	if !ok || !uuidRE.MatchString(id) {
		return "", errors.New("Zertifikat enthält keine gültige Agent-Kennung")
	}
	return id, nil
}

// SerialHex ist die Seriennummer als Hex-Text (für die Datenbank).
func SerialHex(cert *x509.Certificate) string { return cert.SerialNumber.Text(16) }

// --- PEM-Hilfen ---------------------------------------------------------------

func CertToPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func ParseCertPEM(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("kein PEM-Zertifikat")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// VerifyPinnedServer prüft beim ersten Kontakt eines Agents die Kette des
// Servers gegen eine CA, die nur über ihren Fingerabdruck bekannt ist: Die
// CA muss in der vom Server gelieferten Kette stecken, ihr Fingerabdruck
// muss passen, und das Server-Zertifikat muss von ihr signiert und für host
// gültig sein. Liefert die CA für spätere Verbindungen.
func VerifyPinnedServer(rawCerts [][]byte, fingerprint, host string, now time.Time) (*x509.Certificate, error) {
	if len(rawCerts) < 2 {
		return nil, errors.New("Server liefert keine CA mit")
	}
	var ca *x509.Certificate
	for _, raw := range rawCerts[1:] {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		if c.IsCA && Fingerprint(c) == fingerprint {
			ca = c
			break
		}
	}
	if ca == nil {
		return nil, errors.New("die CA des Servers passt nicht zum Fingerabdruck im Token – falsche Zentrale oder Angriff")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("Server-Zertifikat ungültig: %w", err)
	}
	return ca, nil
}

// MaxCABundle: höchstens so viele CAs in ca.pem (aktiv, neu, alt).
const MaxCABundle = 3

// ParseCABundle liest ein PEM-Bündel von CA-Zertifikaten (Agent-CA-Wechsel,
// Etappe 32): mindestens eine, höchstens drei, jede eine CA, keine doppelt,
// nichts außer Zertifikaten. Die Reihenfolge bleibt erhalten; die erste ist
// die ausstellende CA.
func ParseCABundle(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	seen := map[string]bool{}
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, errors.New("CA-Bündel enthält etwas anderes als Zertifikate")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		if !c.IsCA || !c.BasicConstraintsValid {
			return nil, errors.New("CA-Bündel enthält ein Zertifikat, das keine CA ist")
		}
		fp := Fingerprint(c)
		if seen[fp] {
			return nil, errors.New("CA doppelt im Bündel")
		}
		seen[fp] = true
		out = append(out, c)
		if len(out) > MaxCABundle {
			return nil, fmt.Errorf("höchstens %d CAs im Bündel", MaxCABundle)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("CA-Bündel ist leer")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("CA-Bündel enthält unlesbare Daten")
	}
	return out, nil
}

// CABundlePEM setzt CAs zu einem PEM-Bündel zusammen.
func CABundlePEM(cas []*x509.Certificate) []byte {
	var out []byte
	for _, c := range cas {
		out = append(out, CertToPEM(c)...)
	}
	return out
}
