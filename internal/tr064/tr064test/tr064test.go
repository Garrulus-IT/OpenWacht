// SPDX-License-Identifier: AGPL-3.0-only

// Package tr064test: Attrappe einer FRITZ!Box (TR-064 mit Digest) für Tests.
package tr064test

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Zugangsdaten, die die Attrappe annimmt (nur für Tests).
const (
	User     = "openwacht"
	Password = "test-nur-attrappe"
	Realm    = "F!Box SOAP-Auth"
)

// Fake ist eine kleine FRITZ!Box-Attrappe. Felder nur unter Mu ändern.
type Fake struct {
	Mu sync.Mutex
	// Values: Antwortwerte je „Dienst#Aktion“ (Dienst kurz, z. B. DeviceInfo)
	Values map[string]map[string]string
	// Denied: Aktionen, die mit 606 abgelehnt werden („Dienst#Aktion“)
	Denied map[string]bool
	// Calls: aufgerufene Aktionen; Unauth: Anfragen ohne gültige Anmeldung
	Calls  map[string]int
	Unauth int
	// Methods: benutzte HTTP-Methoden und Pfade
	Paths map[string]int
	// SHA256: Digest mit SHA-256 statt MD5
	SHA256 bool
	// NoPPP: keine PPP-Verbindung (Kabel/Glasfaser)
	NoPPP bool
	// Nonce: aktueller Nonce; Rotate erzwingt einen neuen (stale)
	Nonce string
	n     int
}

// NewFake: FRITZ!Box 7590 an DSL, verbunden.
func NewFake() *Fake {
	f := &Fake{Calls: map[string]int{}, Paths: map[string]int{}, Denied: map[string]bool{}, Nonce: "n1"}
	f.Values = map[string]map[string]string{
		"DeviceInfo#GetInfo": {"NewModelName": "FRITZ!Box 7590", "NewSoftwareVersion": "154.07.57", "NewUpTime": "100000",
			"NewSerialNumber": "GEHEIM-SERIE", "NewDeviceLog": "geheimes Protokoll", "NewManufacturerName": "AVM"},
		"WANCommonInterfaceConfig#GetCommonLinkProperties": {"NewWANAccessType": "DSL", "NewLayer1UpstreamMaxBitRate": "40000000",
			"NewLayer1DownstreamMaxBitRate": "250000000", "NewPhysicalLinkStatus": "Up"},
		"WANCommonInterfaceConfig#GetAddonInfos": {"NewByteSendRate": "1000", "NewX_AVM_DE_TotalBytesSent64": "5000000000",
			"NewX_AVM_DE_TotalBytesReceived64": "90000000000"},
		"WANCommonInterfaceConfig#GetTotalBytesSent":     {"NewTotalBytesSent": "705032704"},
		"WANCommonInterfaceConfig#GetTotalBytesReceived": {"NewTotalBytesReceived": "4100654080"},
		"WANPPPConnection#GetStatusInfo":                 {"NewConnectionStatus": "Connected", "NewLastConnectionError": "ERROR_NONE", "NewUptime": "3600"},
		"WANPPPConnection#GetExternalIPAddress":          {"NewExternalIPAddress": "203.0.113.7"},
		"WANIPConnection#GetStatusInfo":                  {"NewConnectionStatus": "Unconfigured", "NewUptime": "0"},
		"WANIPConnection#GetExternalIPAddress":           {"NewExternalIPAddress": "0.0.0.0"},
		"WANDSLInterfaceConfig#GetInfo": {"NewStatus": "Up", "NewUpstreamCurrRate": "40000", "NewDownstreamCurrRate": "250000",
			"NewUpstreamMaxRate": "46000", "NewDownstreamMaxRate": "280000", "NewEnable": "1"},
	}
	return f
}

// Set ändert einen Antwortwert unter Mu.
func (f *Fake) Set(action, key, value string) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.Values[action][key] = value
}

// Deny lässt Aktionen mit 606 ablehnen (Recht fehlt).
func (f *Fake) Deny(actions ...string) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	for _, a := range actions {
		f.Denied[a] = true
	}
}

// Unknown lässt Aktionen mit 401 ablehnen (Aktion unbekannt), wie die echte
// FRITZ!Box 7590 mit FRITZ!OS 8.51 bei GetAddonInfos über TR-064.
func (f *Fake) Unknown(actions ...string) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	for _, a := range actions {
		delete(f.Values, a)
	}
}

// Count: wie oft eine Aktion aufgerufen wurde.
func (f *Fake) Count(action string) int {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return f.Calls[action]
}

// AllCalls: alle aufgerufenen Aktionen.
func (f *Fake) AllCalls() map[string]int {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	out := map[string]int{}
	for k, v := range f.Calls {
		out[k] = v
	}
	return out
}

// Rotate: neuer Nonce (die Box meldet stale=true).
func (f *Fake) Rotate() {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.n++
	f.Nonce = "n" + strconv.Itoa(f.n+1)
}

const desc = `<?xml version="1.0"?>
<root xmlns="urn:dslforum-org:device-1-0"><device><deviceType>urn:dslforum-org:device:InternetGatewayDevice:1</deviceType>
<serviceList>
<service><serviceType>urn:dslforum-org:service:DeviceInfo:1</serviceType><controlURL>/upnp/control/deviceinfo</controlURL></service>
<service><serviceType>urn:dslforum-org:service:DeviceConfig:1</serviceType><controlURL>/upnp/control/deviceconfig</controlURL></service>
<service><serviceType>urn:dslforum-org:service:X_AVM-DE_Homeauto:1</serviceType><controlURL>/upnp/control/x_homeauto</controlURL></service>
</serviceList>
<deviceList><device><deviceType>urn:dslforum-org:device:WANDevice:1</deviceType><serviceList>
<service><serviceType>urn:dslforum-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/upnp/control/wancommonifconfig1</controlURL></service>
<service><serviceType>urn:dslforum-org:service:WANDSLInterfaceConfig:1</serviceType><controlURL>/upnp/control/wandslifconfig1</controlURL></service>
</serviceList><deviceList><device><serviceList>
%s<service><serviceType>urn:dslforum-org:service:WANIPConnection:1</serviceType><controlURL>/upnp/control/wanipconnection1</controlURL></service>
</serviceList></device></deviceList></device></deviceList>
</device></root>`

const pppService = `<service><serviceType>urn:dslforum-org:service:WANPPPConnection:1</serviceType><controlURL>/upnp/control/wanpppconn1</controlURL></service>
`

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.Paths[r.Method+" "+r.URL.Path]++
	if r.Method == http.MethodGet && r.URL.Path == "/tr64desc.xml" {
		ppp := pppService
		if f.NoPPP {
			ppp = ""
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, desc, ppp)
		return
	}
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, "/upnp/control/") {
		http.NotFound(w, r)
		return
	}
	action := r.Header.Get("SoapAction")
	svc, act, _ := strings.Cut(action, "#")
	parts := strings.Split(svc, ":")
	if len(parts) < 2 {
		http.Error(w, "bad", 500)
		return
	}
	key := parts[len(parts)-2] + "#" + act
	io.Copy(io.Discard, io.LimitReader(r.Body, 1<<16))
	if !f.authorized(r) {
		f.Unauth++
		stale := ""
		if strings.Contains(r.Header.Get("Authorization"), `nonce="`) &&
			!strings.Contains(r.Header.Get("Authorization"), `nonce="`+f.Nonce+`"`) {
			stale = `, stale=true`
		}
		alg := "MD5"
		if f.SHA256 {
			alg = "SHA-256"
		}
		w.Header().Set("WWW-Authenticate", `Digest realm="`+Realm+`", nonce="`+f.Nonce+`", algorithm=`+alg+`, qop="auth"`+stale)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.Calls[key]++
	vals, ok := f.Values[key]
	if f.Denied[key] || !ok {
		code := 401
		if f.Denied[key] {
			code = 606
		}
		w.WriteHeader(500)
		fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>`+
			`<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>`+
			`<UPnPError xmlns="urn:dslforum-org:control-1-0"><errorCode>%d</errorCode><errorDescription>x</errorDescription></UPnPError>`+
			`</detail></s:Fault></s:Body></s:Envelope>`, code)
		return
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>`)
	fmt.Fprintf(&b, `<u:%sResponse xmlns:u="%s">`, act, svc)
	for k, v := range vals {
		fmt.Fprintf(&b, "<%s>%s</%s>", k, v, k)
	}
	fmt.Fprintf(&b, `</u:%sResponse></s:Body></s:Envelope>`, act)
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	io.WriteString(w, b.String())
}

// authorized prüft die Digest-Antwort (RFC 7616, qop=auth).
func (f *Fake) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Digest ") {
		return false
	}
	p := map[string]string{}
	for _, part := range strings.Split(h[7:], ", ") {
		k, v, _ := strings.Cut(part, "=")
		p[k] = strings.Trim(v, `"`)
	}
	if p["username"] != User || p["realm"] != Realm || p["nonce"] != f.Nonce || p["uri"] != r.URL.Path || p["qop"] != "auth" {
		return false
	}
	sum := func(s string) string {
		if f.SHA256 {
			x := sha256.Sum256([]byte(s))
			return hex.EncodeToString(x[:])
		}
		x := md5.Sum([]byte(s))
		return hex.EncodeToString(x[:])
	}
	ha1 := sum(User + ":" + Realm + ":" + Password)
	ha2 := sum(r.Method + ":" + r.URL.Path)
	return p["response"] == sum(ha1+":"+p["nonce"]+":"+p["nc"]+":"+p["cnonce"]+":auth:"+ha2)
}

// Server: laufende Attrappe.
type Server struct {
	*httptest.Server
	Host string
	Port uint16
	// Pin: SHA-256 des Zertifikats (nur mit TLS)
	Pin string
}

// Start startet die Attrappe über HTTP.
func Start(t *testing.T, f *Fake) *Server {
	t.Helper()
	return wrap(t, httptest.NewServer(f), "")
}

// StartTLS startet die Attrappe über HTTPS (selbstsigniert).
func StartTLS(t *testing.T, f *Fake) *Server {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return wrap(t, srv, hex.EncodeToString(sum[:]))
}

func wrap(t *testing.T, srv *httptest.Server, pin string) *Server {
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	return &Server{Server: srv, Host: host, Port: uint16(p), Pin: pin}
}
