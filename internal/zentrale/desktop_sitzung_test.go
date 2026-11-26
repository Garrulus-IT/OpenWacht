package zentrale

import (
	"context"
	"encoding/base32"
	"errors"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/desktop"
)

// Die Desktop-App meldet sich wie der Browser an (Passwort, Code, CSRF).
func TestDesktopSitzung(t *testing.T) {
	_, srv, _ := quellenServer(t)
	kontoMitRollen(t, "q_desktop", "Fertigung", map[string]string{"Fertigung": "operator"}, false, false)
	t.Cleanup(func() { resetLogin(t, "q_desktop") })

	// 2FA einrichten wie im Browser
	c := newClient(t, srv)
	expectStatus(t, "Anmeldung", c.login("q_desktop"), 200)
	r := c.do("POST", "/api/v1/zwei-faktor/einrichten", nil)
	expectStatus(t, "einrichten", r, 200)
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(r.body["geheimnis"].(string))
	step := auth.TOTPStep(time.Now())
	expectStatus(t, "bestätigen", c.do("POST", "/api/v1/zwei-faktor/bestaetigen", map[string]string{"code": auth.TOTPCode(secret, step)}), 200)

	ctx := context.Background()
	dc := desktop.Client{Zentrale: srv.URL, Sitzung: &desktop.Sitzung{}}
	if _, err := dc.Anmelden(ctx, "q_desktop@test.invalid", "falsch-falsch-falsch"); err == nil {
		t.Fatal("falsches Passwort angenommen")
	} else if errors.Is(err, desktop.ErrSitzung) {
		t.Errorf("falsches Passwort als abgelaufene Sitzung gemeldet: %v", err)
	}
	resetLogin(t, "q_desktop")
	code, err := dc.Anmelden(ctx, "q_desktop@test.invalid", testPassword)
	if err != nil || !code {
		t.Fatalf("Schritt 1: code=%v %v", code, err)
	}
	if dc.Sitzung.Aktiv() {
		t.Fatal("vor dem Code schon angemeldet")
	}
	if err := dc.ZweiterFaktor(ctx, "q_desktop@test.invalid", auth.TOTPCode(secret, step+1)); err != nil {
		t.Fatalf("Schritt 2: %v", err)
	}
	if !dc.Sitzung.Aktiv() {
		t.Fatal("nicht angemeldet")
	}
	st, err := dc.StandHolen(ctx)
	if err != nil || len(st.Mandanten) == 0 {
		t.Fatalf("Stand: %v %+v", err, st.Mandanten)
	}
	// Ändernde Anfrage mit CSRF: unbekanntes Fenster → 404, nicht 403
	var fz *desktop.FehlerZentrale
	if err := dc.FensterLoeschen(ctx, "00000000-0000-0000-0000-000000000000"); !errors.As(err, &fz) || fz.Code == 403 || fz.Code == 401 {
		t.Errorf("Löschen mit Sitzung: %v", err)
	}
	if err := dc.Abmelden(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := dc.StandHolen(ctx); err == nil {
		t.Error("nach dem Abmelden noch Zugriff")
	}
}
