// SPDX-License-Identifier: AGPL-3.0-only

package traps

// Lesen eingehender Pakete. Alles, was ein Absender schickt, ist nicht
// vertrauenswürdig: höchstens MaxPacket Bytes, höchstens MaxVarbinds Werte,
// Texte bereinigt und gekürzt, OIDs geprüft.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Grenzen.
const (
	MaxPacket   = 8192
	MaxVarbinds = 20
	MaxValue    = 200
	maxOID      = 200
)

const (
	oidSysUpTime    = "1.3.6.1.2.1.1.3.0"
	oidSnmpTrapOID  = "1.3.6.1.6.3.1.1.4.1.0"
	oidUnknownEngID = ".1.3.6.1.6.3.15.1.1.4.0"
	oidNotInTimeWin = ".1.3.6.1.6.3.15.1.1.2.0"
)

// Varbind ist ein Wert aus einem Trap, so wie er gespeichert wird.
type Varbind struct {
	OID   string `json:"oid"`
	Type  string `json:"typ"`
	Value string `json:"wert"`
}

// Notification ist ein gelesener Trap oder Inform.
type Notification struct {
	Version   string // snmp.V1, snmp.V2c, snmp.V3
	Inform    bool
	Authentic bool // nur v3 (authPriv geprüft)
	TrapOID   string
	Varbinds  []Varbind
}

var oidPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// normOID: ohne führenden Punkt, geprüft.
func normOID(s string) (string, bool) {
	s = strings.TrimPrefix(s, ".")
	if len(s) > maxOID || !oidPattern.MatchString(s) {
		return "", false
	}
	return s, true
}

// peekVersion liest die Version aus dem BER-Kopf (SEQUENCE, INTEGER version).
func peekVersion(b []byte) (string, error) {
	if len(b) < 5 || b[0] != 0x30 {
		return "", errors.New("kein SNMP-Paket")
	}
	i := 1
	if b[i]&0x80 == 0 {
		i++
	} else {
		n := int(b[i] & 0x7f)
		if n == 0 || n > 2 {
			return "", errors.New("Länge ungültig")
		}
		i += 1 + n
	}
	if len(b) < i+3 || b[i] != 0x02 || b[i+1] != 0x01 {
		return "", errors.New("Version fehlt")
	}
	switch b[i+2] {
	case 0:
		return snmp.V1, nil
	case 1:
		return snmp.V2c, nil
	case 3:
		return snmp.V3, nil
	}
	return "", fmt.Errorf("Version %d unbekannt", b[i+2])
}

// formatValue macht aus einem Wert Text für Protokoll und Regeln.
func formatValue(p gosnmp.SnmpPDU) Varbind {
	oid, _ := normOID(p.Name)
	v := Varbind{OID: oid}
	switch p.Type {
	case gosnmp.OctetString, gosnmp.Opaque, gosnmp.BitString:
		b, _ := p.Value.([]byte)
		if s, ok := p.Value.(string); ok {
			b = []byte(s)
		}
		if printableText(b) {
			v.Type, v.Value = "Text", snmp.CleanText(b, MaxValue)
		} else {
			if len(b) > (MaxValue-2)/2 {
				b = b[:(MaxValue-2)/2]
			}
			v.Type, v.Value = "Bytes", "0x"+hex.EncodeToString(b)
		}
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.Uinteger32, gosnmp.Counter64:
		v.Type, v.Value = "Zahl", gosnmp.ToBigInt(p.Value).String()
	case gosnmp.TimeTicks:
		v.Type, v.Value = "Zeit", gosnmp.ToBigInt(p.Value).String()
	case gosnmp.ObjectIdentifier:
		s, _ := p.Value.(string)
		if o, ok := normOID(s); ok {
			v.Type, v.Value = "OID", o
		} else {
			v.Type = "OID"
		}
	case gosnmp.IPAddress:
		s, _ := p.Value.(string)
		v.Type, v.Value = "IP", snmp.CleanText([]byte(s), 45)
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		v.Type = "Leer"
	default:
		v.Type = "Unbekannt"
	}
	if len(v.Value) > 4*MaxValue {
		v.Value = v.Value[:4*MaxValue]
	}
	return v
}

// printableText: gültiges UTF-8 ohne Steuerzeichen (außer Leerraum am Ende,
// z. B. Nullbytes von C-Strings).
func printableText(b []byte) bool {
	b = []byte(strings.TrimRight(string(b), "\x00\r\n\t "))
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return false
		}
	}
	return true
}

// notification baut aus einem gelesenen Paket den Trap. v1-Traps werden
// nach RFC 3584 (3.1) in eine Trap-OID übersetzt.
func notification(pkt *gosnmp.SnmpPacket, version string) (*Notification, error) {
	n := &Notification{Version: version}
	vars := pkt.Variables
	switch {
	case version == snmp.V1:
		if pkt.PDUType != gosnmp.Trap {
			return nil, fmt.Errorf("PDU %v ist kein v1-Trap", pkt.PDUType)
		}
		ent, ok := normOID(pkt.Enterprise)
		switch {
		case pkt.GenericTrap >= 0 && pkt.GenericTrap <= 5:
			n.TrapOID = "1.3.6.1.6.3.1.1.5." + strconv.Itoa(pkt.GenericTrap+1)
		case pkt.GenericTrap == 6 && ok && pkt.SpecificTrap >= 0:
			n.TrapOID = ent + ".0." + strconv.Itoa(pkt.SpecificTrap)
		default:
			return nil, errors.New("v1-Trap ohne gültige Kennung")
		}
		if len(vars) == 0 {
			vars = pkt.SnmpTrap.Variables
		}
	case pkt.PDUType == gosnmp.SNMPv2Trap || pkt.PDUType == gosnmp.InformRequest:
		n.Inform = pkt.PDUType == gosnmp.InformRequest
		// RFC 3416: sysUpTime.0 und snmpTrapOID.0 stehen vorn.
		if len(vars) < 2 {
			return nil, errors.New("Trap ohne sysUpTime und snmpTrapOID")
		}
		if o, _ := normOID(vars[0].Name); o != oidSysUpTime {
			return nil, errors.New("Trap ohne sysUpTime.0 an erster Stelle")
		}
		if o, _ := normOID(vars[1].Name); o != oidSnmpTrapOID || vars[1].Type != gosnmp.ObjectIdentifier {
			return nil, errors.New("Trap ohne snmpTrapOID.0 an zweiter Stelle")
		}
		s, _ := vars[1].Value.(string)
		t, ok := normOID(s)
		if !ok {
			return nil, errors.New("Trap-OID ungültig")
		}
		n.TrapOID = t
		vars = vars[2:]
	default:
		return nil, fmt.Errorf("PDU %v ist weder Trap noch Inform", pkt.PDUType)
	}
	for _, p := range vars {
		if len(n.Varbinds) >= MaxVarbinds {
			break
		}
		vb := formatValue(p)
		if vb.OID == "" {
			continue
		}
		n.Varbinds = append(n.Varbinds, vb)
	}
	return n, nil
}

// decodeCommunity liest einen v1/v2c-Trap und gibt den Index der Quelle
// zurück, deren Community passt (Vergleich in konstanter Zeit), sonst -1.
func decodeCommunity(msg []byte, version string, communities []string) (*Notification, *gosnmp.SnmpPacket, int, error) {
	x := &gosnmp.GoSNMP{}
	pkt, err := x.UnmarshalTrap(append([]byte(nil), msg...), false)
	if err != nil {
		return nil, nil, -1, err
	}
	if (version == snmp.V1) != (pkt.Version == gosnmp.Version1) {
		return nil, nil, -1, errors.New("Version passt nicht")
	}
	idx := -1
	for i, c := range communities {
		if subtle.ConstantTimeCompare([]byte(c), []byte(pkt.Community)) == 1 {
			idx = i
		}
	}
	if idx < 0 {
		return nil, nil, -1, errCommunity
	}
	n, err := notification(pkt, version)
	if err != nil {
		return nil, nil, -1, err
	}
	return n, pkt, idx, nil
}

var errCommunity = errors.New("Community passt nicht")

// informResponseV2 baut die Antwort auf einen v2c-Inform (RFC 3416 4.2.7):
// dieselben Werte, Fehlerstatus 0.
func informResponseV2(pkt *gosnmp.SnmpPacket) ([]byte, error) {
	resp := *pkt
	resp.PDUType = gosnmp.GetResponse
	resp.Error, resp.ErrorIndex = gosnmp.NoError, 0
	return resp.MarshalMsg()
}

// discoveryProbe meldet, ob ein v3-Paket eine Anfrage zur Engine-Ermittlung
// ist (RFC 3414, 4): ohne Benutzer und Engine-ID, nicht authentifiziert.
func discoveryProbe(msg []byte) (*gosnmp.SnmpPacket, bool) {
	x := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{}}
	pkt, err := x.UnmarshalTrap(append([]byte(nil), msg...), true)
	if err != nil || pkt.MsgFlags&gosnmp.AuthPriv != gosnmp.NoAuthNoPriv || pkt.MsgFlags&gosnmp.Reportable == 0 {
		return nil, false
	}
	usm, ok := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok || usm.UserName != "" || usm.AuthoritativeEngineID != "" {
		return nil, false
	}
	return pkt, true
}

// report baut eine Report-PDU der eigenen Engine. Für „unbekannte Engine“
// ohne Authentifizierung, für „außerhalb des Zeitfensters“ mit den
// Schlüsseln des Benutzers (authNoPriv, RFC 3414 3.2.7 a).
func report(req *gosnmp.SnmpPacket, eng *localEngine, now uint32, oid string, counter uint32,
	usm *gosnmp.UsmSecurityParameters) ([]byte, error) {
	sp := &gosnmp.UsmSecurityParameters{}
	flags := gosnmp.NoAuthNoPriv
	if usm != nil {
		sp = usm.Copy().(*gosnmp.UsmSecurityParameters)
		flags = gosnmp.AuthNoPriv
	}
	sp.AuthoritativeEngineID = eng.id
	sp.AuthoritativeEngineBoots = eng.boots
	sp.AuthoritativeEngineTime = now
	rep := &gosnmp.SnmpPacket{
		Version: gosnmp.Version3, MsgFlags: flags, SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: sp, ContextEngineID: eng.id, ContextName: req.ContextName,
		PDUType: gosnmp.Report, MsgID: req.MsgID, RequestID: req.RequestID, MsgMaxSize: MaxPacket,
		Variables: []gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.Counter32, Value: uint(counter)}},
	}
	return rep.MarshalMsg()
}

// informResponseV3 beantwortet einen v3-Inform mit derselben Sicherheitsstufe
// und denselben Werten. Das Salz für AES ist neu und zufällig, sonst würde
// der Schlüsselstrom des Informs wiederverwendet.
func informResponseV3(pkt *gosnmp.SnmpPacket, eng *localEngine, now uint32) ([]byte, error) {
	usm, ok := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		return nil, errors.New("keine USM-Parameter")
	}
	sp := usm.Copy().(*gosnmp.UsmSecurityParameters)
	sp.AuthoritativeEngineID, sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = eng.id, eng.boots, now
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	sp.PrivacyParameters = salt
	resp := *pkt
	resp.SecurityParameters = sp
	resp.MsgFlags = gosnmp.AuthPriv // ohne „reportable“
	resp.PDUType = gosnmp.GetResponse
	resp.Error, resp.ErrorIndex = gosnmp.NoError, 0
	resp.MsgMaxSize = MaxPacket
	return resp.MarshalMsg()
}

// decodeV3 versucht die Zugangsdaten eines Benutzers. Nur authPriv.
func decodeV3(msg []byte, v *snmp.V3Auth) (*gosnmp.SnmpPacket, error) {
	x := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv,
		SecurityParameters: v.USM("")}
	pkt, err := x.UnmarshalTrap(append([]byte(nil), msg...), true)
	if err != nil {
		return nil, err
	}
	if pkt.MsgFlags&gosnmp.AuthPriv != gosnmp.AuthPriv {
		return nil, errors.New("nicht authPriv")
	}
	if _, ok := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters); !ok {
		return nil, errors.New("keine USM-Parameter")
	}
	return pkt, nil
}
