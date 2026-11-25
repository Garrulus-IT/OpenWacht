// SPDX-License-Identifier: AGPL-3.0-only

// Package citrixtest ist eine Attrappe des Citrix Monitor Service (OData v4
// unter /Citrix/Monitor/OData/v4/Data/) für Tests: HTTPS mit
// selbstsigniertem Zertifikat und echter NTLMv2-Prüfung (Challenge, dann
// NTProofStr gegen das Passwort). Nur Testdaten.
//
// Fehlerfälle: Forbidden (Konto ohne Citrix-Rolle), NoNTLM (Server verlangt
// nur Basic), FailuresBroken (ConnectionFailureLogs liefert 500), Pages
// (Maschinen über mehrere Seiten), ForeignNext (Fortsetzung auf fremde
// Adresse), Huge (übergroße Antwort).
package citrixtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // nur für die NTLM-Prüfung der Attrappe
)

// Testwerte (keine echten Zugangsdaten).
const (
	User     = `BEISPIEL\svc-openwacht`
	Password = "nur-ein-testpasswort-1"
)

// Server ist die Attrappe.
type Server struct {
	*httptest.Server
	Host string
	Port uint16
	Pin  string // SHA-256 des Zertifikats (hex)

	mu             sync.Mutex
	challenges     map[string][8]byte // je Verbindung (RemoteAddr)
	authed         map[string]bool
	Requests       []string // Pfad und Abfrage jeder bedienten Anfrage
	Methods        []string
	Forbidden      bool
	NoNTLM         bool
	FailuresBroken bool
	Pages          bool
	ForeignNext    bool
	Huge           bool
	Machines       []map[string]any
	Failures       []int
}

// Start startet die Attrappe mit drei VDAs (einer nicht registriert, einer im
// Wartungsmodus) und vier Fehlschlägen (zweimal Registrierungs-Timeout,
// einmal „keine Maschine frei“, einmal „None“).
func Start(t *testing.T) *Server {
	t.Helper()
	s, err := Serve("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Serve startet die Attrappe auf addr (für das Bilder-Skript).
func Serve(addr string) (*Server, error) {
	s := &Server{challenges: map[string][8]byte{}, authed: map[string]bool{},
		Machines: []map[string]any{
			{"Name": `BEISPIEL\VDA-01`, "DnsName": "vda-01.beispiel.example", "CurrentRegistrationState": 1, "IsInMaintenanceMode": false},
			{"Name": `BEISPIEL\VDA-02`, "DnsName": "vda-02.beispiel.example", "CurrentRegistrationState": 2, "IsInMaintenanceMode": false},
			{"Name": `BEISPIEL\VDA-03`, "DnsName": "vda-03.beispiel.example", "CurrentRegistrationState": 2, "IsInMaintenanceMode": true},
		},
		Failures: []int{3, 3, 12, 1},
	}
	cert, err := selfSigned()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.Server.Listener.Close()
	s.Server.Listener = ln
	s.Server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.Server.StartTLS()
	sum := sha256.Sum256(cert.Certificate[0])
	s.Pin = hex.EncodeToString(sum[:])
	host, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	var p int
	fmt.Sscan(port, &p)
	s.Host, s.Port = host, uint16(p)
	return s, nil
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "ddc.beispiel.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func utf16le(s string) []byte {
	var b bytes.Buffer
	for _, r := range utf16.Encode([]rune(s)) {
		b.WriteByte(byte(r))
		b.WriteByte(byte(r >> 8))
	}
	return b.Bytes()
}

func hmacMD5(key []byte, data ...[]byte) []byte {
	m := hmac.New(md5.New, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// challengeMessage: Typ 2 mit Unicode, NTLM, erweiterter Sitzungssicherheit
// und Zielinformation (nur MsvAvEOL).
func challengeMessage(ch [8]byte) []byte {
	const flags = 0x00000001 | 0x00000004 | 0x00000200 | 0x00008000 | 0x00080000 | 0x00800000 | 0x20000000 | 0x80000000
	info := []byte{0, 0, 0, 0} // MsvAvEOL
	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	binary.Write(&b, binary.LittleEndian, uint32(2))
	binary.Write(&b, binary.LittleEndian, [2]uint16{0, 0}) // Zielname leer
	binary.Write(&b, binary.LittleEndian, uint32(48))
	binary.Write(&b, binary.LittleEndian, uint32(flags))
	b.Write(ch[:])
	b.Write(make([]byte, 8))
	binary.Write(&b, binary.LittleEndian, [2]uint16{uint16(len(info)), uint16(len(info))})
	binary.Write(&b, binary.LittleEndian, uint32(48))
	b.Write(info)
	return b.Bytes()
}

func field(msg []byte, at int) []byte {
	if len(msg) < at+8 {
		return nil
	}
	l := int(binary.LittleEndian.Uint16(msg[at:]))
	off := int(binary.LittleEndian.Uint32(msg[at+4:]))
	if off < 0 || off+l > len(msg) {
		return nil
	}
	return msg[off : off+l]
}

func fromUTF16(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// verify prüft eine Typ-3-Nachricht wie ein Domänencontroller (NTLMv2).
func verify(msg []byte, ch [8]byte) bool {
	if len(msg) < 64 || !bytes.HasPrefix(msg, []byte("NTLMSSP\x00")) || binary.LittleEndian.Uint32(msg[8:]) != 3 {
		return false
	}
	nt, domain, user := field(msg, 20), fromUTF16(field(msg, 28)), fromUTF16(field(msg, 36))
	wantDomain, wantUser, _ := strings.Cut(User, `\`)
	if !strings.EqualFold(domain, wantDomain) || !strings.EqualFold(user, wantUser) || len(nt) < 32 {
		return false
	}
	h := md4.New()
	h.Write(utf16le(Password))
	v2 := hmacMD5(h.Sum(nil), utf16le(strings.ToUpper(user)+domain))
	return hmac.Equal(nt[:16], hmacMD5(v2, ch[:], nt[16:]))
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Methods = append(s.Methods, r.Method)
	if s.NoNTLM {
		w.Header().Set("WWW-Authenticate", `Basic realm="ddc"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !s.authed[r.RemoteAddr] {
		a := r.Header.Get("Authorization")
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(a, "NTLM "))
		switch {
		case !strings.HasPrefix(a, "NTLM ") || err != nil || len(raw) < 12:
			w.Header().Set("WWW-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
			return
		case binary.LittleEndian.Uint32(raw[8:]) == 1:
			var ch [8]byte
			rand.Read(ch[:])
			s.challenges[r.RemoteAddr] = ch
			w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(challengeMessage(ch)))
			w.WriteHeader(http.StatusUnauthorized)
			return
		default:
			ch, ok := s.challenges[r.RemoteAddr]
			delete(s.challenges, r.RemoteAddr)
			if !ok || !verify(raw, ch) {
				w.Header().Set("WWW-Authenticate", "NTLM")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			s.authed[r.RemoteAddr] = true
		}
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.Requests = append(s.Requests, r.URL.RequestURI())
	if s.Forbidden {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json; odata.metadata=minimal")
	const base = "/Citrix/Monitor/OData/v4/Data/"
	switch r.URL.Path {
	case base + "Machines":
		if s.Huge {
			w.Write([]byte(`{"value":[` + strings.Repeat(`{"Name":"x"},`, 1<<20) + `{}]}`))
			return
		}
		list := s.Machines
		page := map[string]any{}
		if s.Pages && r.URL.Query().Get("seite") == "" {
			list = list[:1]
			next := "Machines?seite=2"
			if s.ForeignNext {
				next = "https://anderer.beispiel.example/Citrix/Monitor/OData/v4/Data/Machines?seite=2"
			}
			page["@odata.nextLink"] = next
		} else if s.Pages {
			list = list[1:]
		}
		page["value"] = list
		json.NewEncoder(w).Encode(page)
	case base + "ConnectionFailureLogs":
		if s.FailuresBroken {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var list []map[string]int
		for _, c := range s.Failures {
			list = append(list, map[string]int{"ConnectionFailureEnumValue": c})
		}
		json.NewEncoder(w).Encode(map[string]any{"value": list})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
