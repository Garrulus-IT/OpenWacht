// SPDX-License-Identifier: AGPL-3.0-only

package alarm

// Hinweise (Etappe 31): Meldungen der Zentrale über sich selbst an den
// Betreiber und Hinweise an Mandanten (Alarme seit Tagen durch eine
// Abhängigkeit unterdrückt). Einfacher als Alarme: Titel, Text, Zustand.

import (
	"encoding/json"
	"strings"
	"time"
)

// Notice: ein Hinweis für einen Kanal.
type Notice struct {
	Status   string // warn, crit, ok (Entwarnung)
	Title    string
	Text     string
	Since    time.Time
	Link     string
	Operator bool // an den Betreiber (Zustand der Zentrale)
	Channel  string
	Tenant   string
}

func (n Notice) subject() string {
	who := "OpenWacht"
	if !n.Operator {
		who += " " + Clean(n.Tenant, 100)
	}
	t := Clean(n.Title, 150)
	if n.Status == OK {
		t = "Erledigt: " + t
	}
	return Clean(who+": "+t, maxTitle)
}

func (n Notice) body() string {
	if n.Status == OK {
		return "Der Hinweis „" + Clean(n.Title, 150) + "“ ist erledigt."
	}
	return Clean(n.Text, 1000)
}

// Ntfy: Nachricht für ntfy.
func (n Notice) Ntfy() Message {
	prio := map[string]int{Crit: 5, Warn: 4, OK: 3}[n.Status]
	tag := map[string]string{Crit: "rotating_light", Warn: "warning", OK: "white_check_mark"}[n.Status]
	return Message{Title: Clean(symbol[n.Status]+" "+n.subject(), maxTitle), Message: clip(n.body(), maxMessage),
		Priority: prio, Tags: []string{tag}}
}

// Hook: JSON für einen Webhook (Typ openwacht.hinweis).
func (n Notice) Hook(now time.Time) []byte {
	ev := "problem"
	if n.Status == OK {
		ev = "erholt"
	}
	since := n.Since.UTC().Truncate(time.Second)
	p := HookPayload{Type: "openwacht.hinweis", Version: 1, Sent: now.UTC().Truncate(time.Second),
		Channel: Clean(n.Channel, 100), Tenant: Clean(n.Tenant, 100),
		Events: []HookEvent{{Event: ev, Status: n.Status, Tenant: Clean(n.Tenant, 100), Device: "OpenWacht",
			Sensor: Clean(n.Title, 100), Message: Clean(n.body(), 300), Since: &since, Link: n.Link}}}
	if n.Operator {
		p.Events[0].Tenant = ""
	}
	b, _ := json.Marshal(p)
	return b
}

// Teams: Adaptive Card ohne Markdown aus Fremdtext.
func (n Notice) Teams() []byte {
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
		"version": "1.4", "body": []any{
			map[string]any{"type": "TextBlock", "weight": "Bolder", "wrap": true, "text": noMarkdown(n.subject())},
			map[string]any{"type": "TextBlock", "wrap": true, "text": noMarkdown(n.body())}}}
	b, _ := json.Marshal(map[string]any{"type": "message", "attachments": []any{map[string]any{
		"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": nil, "content": card}}})
	return b
}

// Mail: Text und HTML (maskiert über html/template).
func (n Notice) Mail() Mail {
	subject := n.subject()
	body := n.body()
	ft := foot(n.Tenant, n.Channel)
	text := body
	if n.Link != "" {
		text += "\n\n" + n.Link
	}
	return Mail{Subject: subject, Text: text + "\n\n-- \n" + ft + "\n",
		HTML: renderMail(subject, stateColor[n.Status], subject, []mailBlock{{Title: body, Link: n.Link}}, ft)}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut]) + "…"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
