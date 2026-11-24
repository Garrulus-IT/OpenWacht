// SPDX-License-Identifier: AGPL-3.0-only

package alarm

// Webhooks (eigenes JSON, signiert) und Teams (Workflows) – Etappe 20a.
//
// Die URL eines Webhooks legt ein Mandanten-Admin fest. Wie bei ntfy darf sie
// nur zu einem Host gehen, den der Betreiber als Alarmziel freigegeben hat
// (sonst wäre der Webhook ein Weg ins interne Netz). Weiterleitungen werden
// nicht verfolgt. Die URL ist ein Geheimnis (Teams trägt die Signatur in der
// Abfrage) und erscheint nie in Fehlertexten oder Logs.
//
// Signatur nach „Standard Webhooks“ (standardwebhooks.com): Kopfzeilen
// webhook-id, webhook-timestamp (Unix-Sekunden) und webhook-signature
// „v1,<Base64 von HMAC-SHA256(Schlüssel, id.timestamp.rumpf)>“; der Schlüssel
// wird als „whsec_<Base64>“ einmal angezeigt.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// MaxHookURL: so lang darf eine Webhook-URL sein (Teams-URLs sind lang).
const MaxHookURL = 2000

// canonicalHost: Host klein und ohne Standardport.
func canonicalHost(scheme, host string) string {
	host = strings.ToLower(host)
	if scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	} else if scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	}
	return host
}

// NormalizeHookURL prüft eine Webhook-URL und liefert sie samt Ursprung
// (https://host[:port]), der angezeigt und in der Datenbank sichtbar ist.
func NormalizeHookURL(raw string) (full, origin string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxHookURL {
		return "", "", fmt.Errorf("URL fehlt oder ist länger als %d Zeichen", MaxHookURL)
	}
	if strings.ContainsFunc(raw, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		return "", "", errors.New("URL mit Leer- oder Steuerzeichen")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", "", errors.New("keine gültige Adresse (Form https://host/pfad)")
	}
	if u.User != nil || u.Fragment != "" {
		return "", "", errors.New("keine Zugangsdaten oder Anker in der Adresse")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = canonicalHost(u.Scheme, u.Host)
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return "", "", errors.New("http nur für Loopback, sonst https")
		}
	default:
		return "", "", errors.New("nur https (oder http für Loopback)")
	}
	return u.String(), u.Scheme + "://" + u.Host, nil
}

// AllowedURL: Liegt die (normalisierte) URL unter einem freigegebenen Ziel?
// Ein Ziel ohne Pfad gibt den ganzen Host frei, eines mit Pfad nur diesen
// Pfad und alles darunter.
func (t *Targets) AllowedURL(full string) bool {
	u, err := url.Parse(full)
	if err != nil || t == nil {
		return false
	}
	host := canonicalHost(u.Scheme, u.Host)
	for _, x := range t.List() {
		tu, err := url.Parse(x)
		if err != nil || tu.Scheme != u.Scheme || canonicalHost(tu.Scheme, tu.Host) != host {
			continue
		}
		p := strings.TrimRight(tu.Path, "/")
		if p == "" || u.Path == p || strings.HasPrefix(u.Path, p+"/") {
			return true
		}
	}
	return false
}

// NewHookSecret: 32 Zufallsbytes als „whsec_<Base64>“.
func NewHookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + base64.StdEncoding.EncodeToString(b), nil
}

// HookSignature: „v1,<Signatur>“ für id, Zeit und Rumpf.
func HookSignature(secret, id string, ts int64, body []byte) (string, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil || len(key) < 16 || !strings.HasPrefix(secret, "whsec_") {
		return "", errors.New("ungültiger Signaturschlüssel")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHookSignature prüft eine Signatur wie ein Empfänger (für Tests und
// als Beispiel in der Doku); tolerance begrenzt das Alter.
func VerifyHookSignature(secret, id, ts, sigHeader string, body []byte, now time.Time, tolerance time.Duration) bool {
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(t, 0)); d > tolerance || d < -tolerance {
		return false
	}
	want, err := HookSignature(secret, id, t, body)
	if err != nil {
		return false
	}
	for _, s := range strings.Fields(sigHeader) {
		if hmac.Equal([]byte(s), []byte(want)) {
			return true
		}
	}
	return false
}

// PostHook schickt body an full. Ist secret gesetzt, wird signiert. Die URL
// muss freigegeben sein; das wird hier erneut geprüft.
func (s *Sender) PostHook(ctx context.Context, full, secret string, body []byte, now time.Time) error {
	n, _, err := NormalizeHookURL(full)
	if err != nil || n != full || !s.Targets.AllowedURL(n) {
		return errors.New("Ziel ist nicht (mehr) als Alarmziel freigegeben")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n, bytes.NewReader(body))
	if err != nil {
		return errors.New("Anfrage nicht erstellbar")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OpenWacht")
	if secret != "" {
		id := "msg_" + randomID()
		ts := now.Unix()
		sig, err := HookSignature(secret, id, ts, body)
		if err != nil {
			return err
		}
		req.Header.Set("webhook-id", id)
		req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("webhook-signature", sig)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // ohne URL: die ist geheim
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.New("Zeitüberschreitung")
		}
		return fmt.Errorf("nicht erreichbar: %s", Clean(strings.ReplaceAll(err.Error(), full, "…"), 200))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("Ziel antwortete mit Weiterleitung (HTTP %d), Weiterleitungen werden nicht verfolgt", resp.StatusCode)
	}
	return fmt.Errorf("Ziel antwortete mit HTTP %d", resp.StatusCode)
}
