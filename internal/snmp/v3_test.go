// SPDX-License-Identifier: AGPL-3.0-only

package snmp

import (
	"context"
	"strings"
	"testing"
)

// Die Gegenstelle (siehe testTarget) kennt diese v3-Benutzer (CI und
// Sandbox-Anleitung):
//
//	createUser wtest SHA-256 "auth-pass-123" AES "priv-pass-123"
//	createUser wsha1 SHA "auth-pass-123" AES "priv-pass-123"
//	createUser w256 SHA-512 "auth-pass-123" AES-256 "priv-pass-123"
//	rouser wtest priv (ebenso die anderen)
const (
	testAuthPass = "auth-pass-123"
	testPrivPass = "priv-pass-123"
)

func TestV3GegenSnmpd(t *testing.T) {
	host, port, _ := testTarget(t)
	c := loopbackClient()
	ctx := context.Background()
	for _, tc := range []struct{ user, auth, priv string }{
		{"wtest", AuthSHA256, PrivAES},
		{"wsha1", AuthSHA, PrivAES},
		{"w256", AuthSHA512, PrivAES256},
	} {
		t.Run(tc.user, func(t *testing.T) {
			cfg := Config{Version: V3, Host: host, Port: port,
				V3: &V3Auth{User: tc.user, Auth: tc.auth, AuthPass: testAuthPass, Priv: tc.priv, PrivPass: testPrivPass}}
			sys, err := c.Probe(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if sys.Name == "" || sys.Descr == "" {
				t.Fatalf("Systemdaten unvollständig: %+v", sys)
			}
			snap, err := c.Poll(ctx, cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(snap.Partial) > 0 || snap.Memory == nil || len(snap.Interfaces) == 0 {
				t.Fatalf("Abfrage unvollständig: partial=%v speicher=%v ifs=%d", snap.Partial, snap.Memory, len(snap.Interfaces))
			}
			// 64-Bit-Zähler wie bei v2c
			if snap.Counters == nil {
				t.Fatal("keine Zähler")
			}
		})
	}
}

func TestV3Fehlerfaelle(t *testing.T) {
	host, port, _ := testTarget(t)
	c := loopbackClient()
	ctx := context.Background()
	ok := V3Auth{User: "wtest", Auth: AuthSHA256, AuthPass: testAuthPass, Priv: PrivAES, PrivPass: testPrivPass}
	for _, tc := range []struct {
		name string
		mod  func(*V3Auth)
		want string
	}{
		{"unbekannter Benutzer", func(v *V3Auth) { v.User = "niemand" }, "Anmeldung abgelehnt"},
		{"falsches Auth-Passwort", func(v *V3Auth) { v.AuthPass = "falsch-falsch" }, "Anmeldung abgelehnt"},
		{"falsches Verfahren", func(v *V3Auth) { v.Auth = AuthSHA }, "Anmeldung abgelehnt"},
		// Mit falschem Verschlüsselungs-Passwort antwortet Net-SNMP nicht (der
		// Report wäre unverschlüsselt nicht zulässig): keine Antwort.
		{"falsches Priv-Passwort", func(v *V3Auth) { v.PrivPass = "falsch-falsch" }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := ok
			tc.mod(&v)
			_, err := c.Probe(ctx, Config{Version: V3, Host: host, Port: port, V3: &v})
			if err == nil {
				t.Fatal("erwartet: Fehler")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Meldung %q, erwartet %q", err, tc.want)
			}
			for _, secret := range []string{v.AuthPass, v.PrivPass} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("Passwort in der Meldung: %q", err)
				}
			}
		})
	}
}

func TestV3Validate(t *testing.T) {
	ok := V3Auth{User: "wtest", Auth: AuthSHA256, AuthPass: testAuthPass, Priv: PrivAES, PrivPass: testPrivPass}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*V3Auth){
		"MD5":              func(v *V3Auth) { v.Auth = "md5" },
		"DES":              func(v *V3Auth) { v.Priv = "des" },
		"3DES":             func(v *V3Auth) { v.Priv = "3des" },
		"ohne Priv":        func(v *V3Auth) { v.Priv = "" },
		"ohne Auth":        func(v *V3Auth) { v.Auth = "none" },
		"unbekannt":        func(v *V3Auth) { v.Auth = "sha3" },
		"kurzes Passwort":  func(v *V3Auth) { v.AuthPass = "1234567" },
		"kurzes Priv":      func(v *V3Auth) { v.PrivPass = "kurz" },
		"langes Passwort":  func(v *V3Auth) { v.PrivPass = strings.Repeat("x", 129) },
		"Steuerzeichen":    func(v *V3Auth) { v.AuthPass = "abc\ndefgh" },
		"Umlaut":           func(v *V3Auth) { v.AuthPass = "passwört12" },
		"leerer Benutzer":  func(v *V3Auth) { v.User = "" },
		"langer Benutzer":  func(v *V3Auth) { v.User = strings.Repeat("u", 33) },
		"Leerzeichen Rand": func(v *V3Auth) { v.User = " wtest" },
	} {
		v := ok
		mod(&v)
		if err := v.Validate(); err == nil {
			t.Errorf("%s: erwartet abgelehnt", name)
		} else if strings.Contains(err.Error(), v.AuthPass) || strings.Contains(err.Error(), v.PrivPass) {
			t.Errorf("%s: Passwort in der Meldung", name)
		}
	}
	var nilV3 *V3Auth
	if nilV3.Validate() == nil {
		t.Error("nil erwartet abgelehnt")
	}
	// Ohne Zugangsdaten darf open nicht weiterlaufen.
	if _, err := loopbackClient().open(context.Background(), Config{Version: V3, Host: "127.0.0.1"}); err == nil {
		t.Error("open ohne v3-Daten")
	}
	for in, want := range map[string]string{"SHA-256": AuthSHA256, "sha1": AuthSHA, "HMAC-SHA": AuthSHA, " SHA512 ": AuthSHA512} {
		if got := NormalizeAuth(in); got != want {
			t.Errorf("NormalizeAuth(%q) = %q", in, got)
		}
	}
	for in, want := range map[string]string{"AES-128": PrivAES, "AES": PrivAES, "AES256-C": PrivAES256C, "aes-192": PrivAES192} {
		if got := NormalizePriv(in); got != want {
			t.Errorf("NormalizePriv(%q) = %q", in, got)
		}
	}
}
