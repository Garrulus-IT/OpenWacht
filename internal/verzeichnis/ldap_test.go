// SPDX-License-Identifier: AGPL-3.0-only

package verzeichnis

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// Gegenstelle: OpenLDAP mit AD-ähnlichem Schema (Sandbox-Notiz „Etappe 22a“).
// OPENWACHT_TEST_LDAPS=ldaps://127.0.0.1:16636, OPENWACHT_TEST_LDAP_CA=<PEM-Datei>.
func testConfig(t *testing.T) Config {
	t.Helper()
	u := os.Getenv("OPENWACHT_TEST_LDAPS")
	if u == "" {
		if os.Getenv("OPENWACHT_REQUIRE_LDAP") != "" {
			t.Fatal("OPENWACHT_TEST_LDAPS fehlt")
		}
		t.Skip("OPENWACHT_TEST_LDAPS nicht gesetzt")
	}
	ca, err := os.ReadFile(os.Getenv("OPENWACHT_TEST_LDAP_CA"))
	if err != nil {
		t.Fatal(err)
	}
	return Config{URL: u, CAPEM: string(ca), BindDN: "cn=svc-openwacht,ou=dienst,dc=firma,dc=test",
		BindPassword: "dienst-pass-123", BaseDN: "dc=firma,dc=test"}
}

var (
	gAdmins = "cn=GG-OpenWacht-Admins,ou=gruppen,dc=firma,dc=test"
	gOps    = "cn=GG-OpenWacht-Operatoren,ou=gruppen,dc=firma,dc=test"
)

func TestAnmeldung(t *testing.T) {
	c := testConfig(t)
	ctx := context.Background()
	if err := c.Test(ctx); err != nil {
		t.Fatal(err)
	}
	u, err := c.Authenticate(ctx, "anna@firma.test", "anna-pass-123", []string{gAdmins, gOps})
	if err != nil {
		t.Fatal(err)
	}
	if u.Email() != "anna@firma.test" || u.Name != "Anna Admin" || u.Disabled || len(u.ID) != 32 ||
		strings.Join(u.Groups, ";") != gAdmins {
		t.Fatalf("%+v", u)
	}
	// DOMAIN\name über sAMAccountName
	if u, err := c.Authenticate(ctx, `FIRMA\otto`, "otto-pass-123", []string{gAdmins, gOps}); err != nil || strings.Join(u.Groups, ";") != gOps {
		t.Fatalf("otto: %+v %v", u, err)
	}
	// gesperrt im Verzeichnis: Anmeldung geht, Disabled ist gesetzt (die Zentrale sperrt)
	if u, err := c.Authenticate(ctx, "gustav@firma.test", "gustav-pass-123", nil); err != nil || !u.Disabled {
		t.Fatalf("gustav: %+v %v", u, err)
	}
	// Negativfälle
	if _, err := c.Authenticate(ctx, "anna@firma.test", "falsch", nil); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("falsches Passwort: %v", err)
	}
	if _, err := c.Authenticate(ctx, "anna@firma.test", "", nil); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("leeres Passwort (unauthenticated bind): %v", err)
	}
	if _, err := c.Authenticate(ctx, "niemand@firma.test", "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unbekannt: %v", err)
	}
	if _, err := c.Authenticate(ctx, "*@firma.test", "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Platzhalter im Namen: %v", err)
	}
	if _, err := c.Authenticate(ctx, "anna)(|(cn=*", "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Filter-Injektion: %v", err)
	}
	bad := c
	bad.BindPassword = "falsch"
	if err := bad.Test(ctx); err == nil {
		t.Fatal("falsches Dienstkonto-Passwort angenommen")
	}
	noCA := c
	noCA.CAPEM = ""
	if err := noCA.Test(ctx); err == nil {
		t.Fatal("Zertifikat ohne passende CA angenommen")
	}
}

func TestAbgleich(t *testing.T) {
	c := testConfig(t)
	ctx := context.Background()
	conn, err := c.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	u, err := c.LookupByID(ctx, conn, "000102030405060708090a0b0c0d0e0f", []string{gAdmins})
	if err != nil || u.Email() != "anna@firma.test" || len(u.Groups) != 1 {
		t.Fatalf("%+v %v", u, err)
	}
	if _, err := c.LookupByID(ctx, conn, "ffffffffffffffffffffffffffffffff", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unbekannte GUID: %v", err)
	}
}

func TestValidateURLUndLogin(t *testing.T) {
	for _, ok := range []string{"ldaps://dc1.firma.de", "ldap://dc1.firma.de:389", "ldaps://10.10.0.5:3269"} {
		if _, _, _, err := ValidateURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://dc1", "ldaps://", "ldaps://dc1/dc=x", "ldaps://u:p@dc1", "ldaps://dc1:99999"} {
		if _, _, _, err := ValidateURL(bad); err == nil {
			t.Errorf("%s angenommen", bad)
		}
	}
	if _, _, st, _ := ValidateURL("ldap://dc1"); !st {
		t.Error("ldap:// ohne StartTLS")
	}
	if n, d, nb := SplitLogin(`FIRMA\anna`); n != "anna" || d != "" || nb != "FIRMA" {
		t.Error(n, d, nb)
	}
	if n, d, _ := SplitLogin("Anna@Firma.de"); n != "Anna" || d != "firma.de" {
		t.Error(n, d)
	}
}
