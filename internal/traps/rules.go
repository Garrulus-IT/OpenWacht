// SPDX-License-Identifier: AGPL-3.0-only

package traps

// Regeln: Trap-OID → Zustand. Je Quelle gelten die Regeln ihres Mandanten
// und seiner Vorfahren, eigener Mandant zuerst, darin nach Position. Die
// erste passende Regel gilt.

import (
	"strings"
	"unicode/utf8"
)

// Rule ist eine Regel, wie sie traps_rules() liefert.
type Rule struct {
	ID, Tenant string
	Pos        int
	Name       string
	Group      string // "" = ohne
	Device     string // "" = ohne
	TrapOID    string // genau, „x.*“ oder „*“
	VbOID      string // "" = keine Bedingung
	VbOp       string
	VbValue    string
	Action     string // warn, crit, ok, ignore
	KeyOID     string // "" = nicht unterscheiden
}

// Source ist eine Quelle mit eingeschalteten Traps.
type Source struct {
	ID, Tenant, Device, DeviceName string
	Version, Host                  string
	Port                           int
	Secret                         Secret
	Tenants                        []string // eigener Mandant zuerst
	Groups                         []string // eigene Gruppe zuerst, dann Eltern
}

// RuleSet: Regeln je Mandant, sortiert.
type RuleSet map[string][]Rule

// oidMatches: „*“ = alle, „a.b.*“ = a.b selbst und alles darunter, sonst genau.
func oidMatches(pattern, oid string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasSuffix(pattern, ".*"):
		p := strings.TrimSuffix(pattern, ".*")
		return oid == p || strings.HasPrefix(oid, p+".")
	}
	return oid == pattern
}

// findVarbind: erster Wert, dessen OID gleich ist oder darunter liegt
// (z. B. ifIndex = 1.3.6.1.2.1.2.2.1.1 findet 1.3.6.1.2.1.2.2.1.1.5).
func findVarbind(n *Notification, oid string) (Varbind, bool) {
	for _, v := range n.Varbinds {
		if v.OID == oid || strings.HasPrefix(v.OID, oid+".") {
			return v, true
		}
	}
	return Varbind{}, false
}

func (r *Rule) condition(n *Notification) bool {
	if r.VbOID == "" {
		return true
	}
	want := strings.ToLower(r.VbValue)
	match := func(v Varbind) bool {
		got := strings.ToLower(v.Value)
		switch r.VbOp {
		case "gleich", "nicht":
			return got == want
		case "enthaelt":
			return strings.Contains(got, want)
		case "beginnt":
			return strings.HasPrefix(got, want)
		}
		return false
	}
	if r.VbOp == "nicht" {
		// „nicht gleich“: kein Wert unter der OID hat den Wert
		for _, v := range n.Varbinds {
			if (v.OID == r.VbOID || strings.HasPrefix(v.OID, r.VbOID+".")) && match(v) {
				return false
			}
		}
		return true
	}
	for _, v := range n.Varbinds {
		if (v.OID == r.VbOID || strings.HasPrefix(v.OID, r.VbOID+".")) && match(v) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (r *Rule) inScope(src *Source) bool {
	switch {
	case r.Device != "":
		return r.Device == src.Device
	case r.Group != "":
		return contains(src.Groups, r.Group)
	}
	return true
}

// Match liefert die erste passende Regel und den Schlüssel, nach dem
// Zustände getrennt werden ("" = nicht unterschieden).
func (rs RuleSet) Match(src *Source, n *Notification) (*Rule, string) {
	for _, t := range src.Tenants {
		list := rs[t]
		for i := range list {
			r := &list[i]
			if !r.inScope(src) || !oidMatches(r.TrapOID, n.TrapOID) || !r.condition(n) {
				continue
			}
			inst := ""
			if r.KeyOID != "" && r.Action != "ignore" {
				if v, ok := findVarbind(n, r.KeyOID); ok {
					inst = v.Value
				}
				if utf8.RuneCountInString(inst) > 100 {
					inst = string([]rune(inst)[:100])
				}
			}
			return r, inst
		}
	}
	return nil, ""
}

// Bekannte Traps und Werte, für verständliche Meldungen.
var knownTraps = map[string]string{
	"1.3.6.1.6.3.1.1.5.1": "coldStart",
	"1.3.6.1.6.3.1.1.5.2": "warmStart",
	"1.3.6.1.6.3.1.1.5.3": "linkDown",
	"1.3.6.1.6.3.1.1.5.4": "linkUp",
	"1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
	"1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
	"1.3.6.1.2.1.33.2.1":  "upsTrapOnBattery",
	"1.3.6.1.2.1.33.2.3":  "upsTrapAlarmEntryAdded",
	"1.3.6.1.2.1.33.2.4":  "upsTrapAlarmEntryRemoved",
}

var knownVarbinds = map[string]string{
	"1.3.6.1.2.1.2.2.1.1":    "ifIndex",
	"1.3.6.1.2.1.2.2.1.2":    "ifDescr",
	"1.3.6.1.2.1.2.2.1.7":    "ifAdminStatus",
	"1.3.6.1.2.1.2.2.1.8":    "ifOperStatus",
	"1.3.6.1.2.1.31.1.1.1.1": "ifName",
}

// TrapName: bekannter Name oder die OID.
func TrapName(oid string) string {
	if n, ok := knownTraps[oid]; ok {
		return n
	}
	return oid
}

func varbindName(oid string) string {
	for prefix, name := range knownVarbinds {
		if strings.HasPrefix(oid, prefix+".") {
			return name + oid[len(prefix):]
		}
	}
	return oid
}

// Message: kurze Meldung für Zustand und Alarm (höchstens 300 Zeichen).
func Message(n *Notification) string {
	var b strings.Builder
	b.WriteString(TrapName(n.TrapOID))
	for i, v := range n.Varbinds {
		if i == 3 {
			b.WriteString(", …")
			break
		}
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString(", ")
		}
		val := v.Value
		if utf8.RuneCountInString(val) > 60 {
			val = string([]rune(val)[:60]) + "…"
		}
		b.WriteString(varbindName(v.OID) + " = " + val)
	}
	if !n.Authentic {
		b.WriteString(" (unbestätigt: v1/v2c)")
	}
	s := b.String()
	if utf8.RuneCountInString(s) > 300 {
		s = string([]rune(s)[:300])
	}
	return s
}
