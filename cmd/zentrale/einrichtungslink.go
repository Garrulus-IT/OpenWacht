// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/pki"
	"github.com/garrulus-it/openwacht/internal/zentrale"
)

// Einrichtungslink: für die Installation unter Linux (installieren,
// einrichtungslink) und für den Betrieb ohne systemd (dienst: Docker, Windows).

// neuerLinkHinweis: wie man einen neuen Link bekommt (dienst setzt ihn um).
var neuerLinkHinweis = "sudo openwacht-zentrale einrichtungslink"

type setupLink struct {
	Offen         bool     `json:"offen"`
	Token         string   `json:"token,omitempty"`
	Fingerabdruck string   `json:"fingerabdruck,omitempty"`
	Namen         []string `json:"namen,omitempty"`
	Adresse       string   `json:"adresse,omitempty"`
}

func printSetupLink(out io.Writer, l setupLink, proxy bool) {
	if !l.Offen {
		if l.Adresse != "" {
			fmt.Fprintf(out, "\nOpenWacht ist eingerichtet: %s\n", l.Adresse)
		} else {
			fmt.Fprintln(out, "\nOpenWacht ist eingerichtet.")
		}
		return
	}
	fmt.Fprintf(out, "\nEinrichtung im Browser öffnen (gilt %d Minuten, nur einmal bis „Fertig“):\n\n", int(zentrale.SetupTokenTTL/time.Minute))
	hosts := l.Namen
	if len(hosts) == 0 && !proxy {
		hosts = zentrale.HostNames() // Zentrale noch nicht gestartet (ohne systemd)
	}
	if proxy || len(hosts) == 0 {
		hosts = []string{"<Adresse der Oberfläche>"}
	}
	for _, h := range hosts {
		if a, err := netip.ParseAddr(h); err == nil && a.Is6() {
			h = "[" + h + "]"
		}
		fmt.Fprintf(out, "    https://%s/einrichtung#%s\n", h, l.Token)
	}
	if l.Fingerabdruck != "" {
		fmt.Fprintf(out, "\nDer Browser warnt vor dem vorläufigen Zertifikat. Weiter nur, wenn er diesen\nSHA-256-Fingerabdruck zeigt:\n\n    %s\n", l.Fingerabdruck)
	}
	fmt.Fprintln(out, "\nNeuer Link: "+neuerLinkHinweis)
}

func newSetupLink(ctx context.Context, conn *pgx.Conn, wait time.Duration) (setupLink, error) {
	var l setupLink
	raw, hash, err := zentrale.NewSetupToken()
	if err != nil {
		return l, err
	}
	tag, err := conn.Exec(ctx, `UPDATE openwacht.setup_state SET token_hash = $1, expires_at = now() + $2::interval
		WHERE done_at IS NULL AND NOT EXISTS (SELECT 1 FROM openwacht.tenants WHERE parent_id IS NULL)`,
		hash, fmt.Sprintf("%d seconds", int(zentrale.SetupTokenTTL/time.Second)))
	if err != nil {
		return l, err
	}
	if tag.RowsAffected() == 0 {
		var base *string
		_ = conn.QueryRow(ctx, `SELECT base_url FROM openwacht.settings`).Scan(&base)
		if base != nil {
			l.Adresse = *base
		}
		return l, nil
	}
	l.Offen, l.Token = true, raw
	deadline := time.Now().Add(wait)
	for {
		var certPEM string
		var names []string
		err := conn.QueryRow(ctx, `SELECT cert_pem, names FROM openwacht.https_material WHERE kind = 'einrichtung'`).Scan(&certPEM, &names)
		if err == nil {
			if c, err := pki.ParseCertPEM([]byte(certPEM)); err == nil {
				l.Fingerabdruck, l.Namen = pki.SHA256Hex(c), names
			}
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return l, err
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return l, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return l, nil
}
