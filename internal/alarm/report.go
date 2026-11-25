// SPDX-License-Identifier: AGPL-3.0-only

package alarm

// Ausführliche Meldungen für Mail, Webhook und Teams (Etappe 20a).
//
// Inhalt nach Entscheidung (21.11.2026): Betreff mit Zustand, Gerät
// und Fehler; im Text Zustand seit wann, Meldung, letzte OK-Messung, weitere
// Probleme am Gerät, Prognose bei Platten, Wartung, Link; in der Mail ein
// Graph der letzten 24 Stunden. Alle Texte stammen aus Namen und Meldungen,
// die Nutzer, Agents oder Geräte liefern: Sie werden bereinigt (Clean),
// beim HTML maskiert (html/template) und für Teams von Markdown befreit.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"sort"
	"strings"
	"time"
)

// Other: ein weiteres offenes Problem am selben Gerät.
type Other struct {
	Name    string
	Status  string
	Message string
	Since   time.Time
	Acked   bool
}

// Report: ein Ereignis mit allem, was Mail, Webhook und Teams zeigen.
type Report struct {
	Item
	Device      string // Name des Geräts
	Sensor      string // Name des Sensors ohne Gerät
	Since       *time.Time
	LastOK      *time.Time
	Others      []Other
	Forecast    string // nur bei Platten
	Maintenance bool
	Link        string // Seite des Geräts in der Oberfläche
	Chart       *Chart
}

// Kurzzeichen der Zustände für den Betreff.
var stateShort = map[string]string{OK: "OK", Warn: "WARN", Crit: "KRIT", Unknown: "UNBEKANNT"}

// StateText: Zustand in Worten.
var StateText = map[string]string{OK: "in Ordnung", Warn: "Warnung", Crit: "kritisch", Unknown: "unbekannt"}

// SplitLabel trennt „Gerät · Sensor“. Ohne Trenner ist es der Agent selbst.
func SplitLabel(label, device string) string {
	if device != "" {
		if rest, ok := strings.CutPrefix(label, device+" · "); ok {
			return rest
		}
		if label == device {
			return "Erreichbarkeit"
		}
	}
	if _, rest, ok := strings.Cut(label, " · "); ok {
		return rest
	}
	return label
}

// who: Gerät, bei fremdem Mandanten mit dessen Namen davor.
func (r Report) who(channelTenant string) string {
	d := Clean(r.Device, 100)
	if d == "" {
		d = Clean(r.Check, 100)
	}
	if r.Tenant != channelTenant {
		d = Clean(r.Tenant, 100) + " / " + d
	}
	return d
}

// SubjectMax: Länge des Betreffs. Kurz genug für die Liste im Postfach und
// fürs Handy (1.0.3: vorher bis 200 Zeichen mit der ganzen Meldung).
const SubjectMax = 90

// Subject: „KRIT · pve-1 · Platte /var“. Die Meldung steht im Text der Mail
// ganz oben, nicht im Betreff.
func (r Report) Subject(channelTenant string) string {
	st := stateShort[r.Status]
	switch r.Event {
	case Recovered:
		st = "OK"
	case Reminder:
		st = "Erinnerung " + st
	}
	return Clean(st+" · "+Clean(r.who(channelTenant), 45)+" · "+Clean(r.Sensor, 60), SubjectMax)
}

// headline: die Meldung als erste Zeile der Mail; bei einer Entwarnung ohne
// Meldung „wieder in Ordnung“.
func (r Report) headline() string {
	msg := Clean(r.Message, 300)
	if r.Event == Recovered && msg == "" {
		msg = "wieder in Ordnung"
	}
	return msg
}

// Fact: eine Zeile „Bezeichnung: Wert“.
type Fact struct{ Label, Value string }

// when: „21.11.2026 14:05 (vor 2 Std. 10 Min.)“ in der Zeitzone loc.
func when(t time.Time, now time.Time, loc *time.Location) string {
	return t.In(loc).Format("02.01.2006 15:04") + " (" + Ago(now.Sub(t)) + ")"
}

// Ago: „vor 5 Min.“, „vor 3 Std. 20 Min.“, „vor 2 Tagen“.
func Ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "gerade eben"
	case d < time.Hour:
		return fmt.Sprintf("vor %d Min.", int(d.Minutes()))
	case d < 24*time.Hour:
		h, m := int(d.Hours()), int(d.Minutes())%60
		if m == 0 {
			return fmt.Sprintf("vor %d Std.", h)
		}
		return fmt.Sprintf("vor %d Std. %d Min.", h, m)
	}
	days := int(d.Hours() / 24)
	if days == 1 {
		return "vor 1 Tag"
	}
	return fmt.Sprintf("vor %d Tagen", days)
}

// Facts: die Angaben eines Ereignisses in fester Reihenfolge.
func (r Report) Facts(channelTenant string, now time.Time, loc *time.Location) []Fact {
	var f []Fact
	if r.Tenant != channelTenant {
		f = append(f, Fact{"Mandant", Clean(r.Tenant, 100)})
	}
	f = append(f, Fact{"Gerät", Clean(r.Device, 100)}, Fact{"Sensor", Clean(r.Sensor, 100)})
	state := StateText[r.Status]
	switch r.Event {
	case Recovered:
		state = "wieder in Ordnung"
	case Reminder:
		state += " (Erinnerung, besteht weiter)"
	}
	f = append(f, Fact{"Zustand", state})
	if m := Clean(r.Message, 300); m != "" {
		f = append(f, Fact{"Meldung", m})
	}
	if r.Since != nil && r.Event != Recovered {
		f = append(f, Fact{"Seit", when(*r.Since, now, loc)})
	}
	if r.LastOK != nil && r.Event != Recovered {
		f = append(f, Fact{"Zuletzt in Ordnung", when(*r.LastOK, now, loc)})
	}
	if r.Forecast != "" {
		f = append(f, Fact{"Prognose", Clean(r.Forecast, 200)})
	}
	if r.Maintenance {
		f = append(f, Fact{"Wartung", "Gerät bzw. Sensor ist in Wartung"})
	}
	return f
}

// othersText: weitere Probleme in einer Zeile je Eintrag.
func (r Report) othersLines(now time.Time) []string {
	var out []string
	for i, o := range r.Others {
		if i == 10 {
			out = append(out, fmt.Sprintf("… und %d weitere", len(r.Others)-i))
			break
		}
		s := stateShort[o.Status] + " · " + Clean(o.Name, 150)
		if m := Clean(o.Message, 150); m != "" {
			s += ": " + m
		}
		s += " (seit " + strings.TrimPrefix(Ago(now.Sub(o.Since)), "vor ") + ")"
		if o.Acked {
			s += ", bestätigt"
		}
		out = append(out, s)
	}
	return out
}

// ChartCaption: „Letzte 24 Std.: min 88 %, max 96 %, zuletzt 96 % · Warnung 90 %, kritisch 95 %“.
func (c Chart) Caption() string {
	lo, hi, last, ok := c.Range()
	if !ok {
		return ""
	}
	h := int(math.Round(c.To.Sub(c.From).Hours()))
	s := fmt.Sprintf("%s, letzte %d Std.: min %s, max %s, zuletzt %s", Clean(c.Title, 100), h,
		c.num(lo), c.num(hi), c.num(last))
	var t []string
	if c.Warn > 0 {
		t = append(t, "Warnung "+c.num(c.Warn))
	}
	if c.Crit > 0 {
		t = append(t, "kritisch "+c.num(c.Crit))
	}
	if len(t) > 0 {
		s += " · gestrichelt: " + strings.Join(t, ", ")
	}
	return s
}

func (c Chart) num(v float64) string {
	f := "%.0f"
	if math.Abs(v) < 10 && v != math.Trunc(v) {
		f = "%.1f"
	}
	s := strings.Replace(fmt.Sprintf(f, v), ".", ",", 1)
	if c.Unit == "%" {
		return s + " %"
	}
	if c.Unit != "" {
		return s + " " + c.Unit
	}
	return s
}

// --- Mail ------------------------------------------------------------------------

// Mail: Inhalt einer Nachricht; Bilder hängen inline per Content-ID.
type Mail struct {
	Subject string
	Text    string
	HTML    string
	Images  []MailImage
	// Anhänge (Etappe 25: Monatsbericht als PDF); nicht zusammen mit Images
	Attachments []MailAttachment
}

// MailAttachment: Datei im Anhang.
type MailAttachment struct {
	Name, Type string
	Data       []byte
}

// MailImage: ein PNG mit Content-ID (ohne spitze Klammern).
type MailImage struct {
	CID  string
	Data []byte
}

var mailTmpl = template.Must(template.New("mail").Parse(`<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8"><title>{{.Subject}}</title></head>
<body style="margin:0;padding:16px;background:#eef2f6;font-family:D-DIN,Segoe UI,Helvetica,Arial,sans-serif;color:#14202e">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #c9d3de">
<tr><td style="background:{{.Color}};color:#ffffff;padding:12px 16px;font-size:16px;font-weight:bold">{{.Head}}</td></tr>
{{range .Blocks}}<tr><td style="padding:14px 16px;border-top:1px solid #c9d3de">
<div style="font-size:15px;font-weight:bold;margin-bottom:8px">{{.Title}}</div>
{{if .Lead}}<div style="font-size:16px;line-height:1.4;margin:0 0 12px">{{.Lead}}</div>{{end}}
<table role="presentation" cellpadding="0" cellspacing="0" style="font-size:14px;line-height:1.45">
{{range .Facts}}<tr><td style="padding:2px 12px 2px 0;color:#526172;vertical-align:top;white-space:nowrap">{{.Label}}</td><td style="padding:2px 0">{{.Value}}</td></tr>
{{end}}</table>
{{if .Image}}<div style="margin-top:12px"><img src="cid:{{.Image}}" width="600" alt="{{.Caption}}" style="display:block;width:100%;max-width:600px;height:auto;border:1px solid #c9d3de"></div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;font-size:11px;color:#526172"><tr><td>{{.AxisFrom}}</td><td align="right">jetzt</td></tr></table>
<div style="font-size:12px;color:#526172;margin-top:4px">{{.Caption}}</div>{{end}}
{{if .Others}}<div style="font-size:14px;font-weight:bold;margin-top:12px">Weitere offene Probleme am Gerät</div>
<ul style="margin:4px 0 0 18px;padding:0;font-size:14px">{{range .Others}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Link}}<div style="margin-top:12px"><a href="{{.Link}}" style="color:#0b6a8a;font-weight:bold">In OpenWacht öffnen</a></div>{{end}}
</td></tr>{{end}}
<tr><td style="padding:10px 16px;border-top:1px solid #c9d3de;font-size:12px;color:#526172">{{.Foot}}</td></tr>
</table></body></html>`))

type mailBlock struct {
	AxisFrom string // linke Beschriftung der Zeitachse
	Title    string
	Lead     string // Meldung, groß unter dem Titel
	Facts    []Fact
	Image    string
	Caption  string
	Others   []string
	Link     string
}

// Farben der Kopfzeile nach docs/design/tokens.css (hell). Weiße Schrift
// braucht ≥ 4,5:1: Warnung nimmt deshalb --text-warn statt --warn (3,7:1),
// Unbekannt --leise statt --unbek (3,8:1).
var stateColor = map[string]string{OK: "#2c7a57", Warn: "#7d5600", Crit: "#b3362f", Unknown: "#526172"}

// foot: Hinweis am Ende jeder Mail (woher, wie abbestellen).
func foot(channelTenant, channel string) string {
	return "OpenWacht · Alarmkanal „" + Clean(channel, 100) + "“ von " + Clean(channelTenant, 100) +
		". Alarm-Mails lassen sich in OpenWacht unter Alarme → Kanäle für dich abbestellen."
}

// BuildMail: eine Mail für ein Ereignis. Mit Graph, wenn r.Chart Punkte hat.
func BuildMail(channelTenant, channel string, r Report, now time.Time, loc *time.Location) Mail {
	m := Mail{Subject: r.Subject(channelTenant)}
	// Gerät, Sensor und Meldung stehen groß oben; in den Angaben darunter
	// nicht noch einmal.
	var facts []Fact
	for _, f := range r.Facts(channelTenant, now, loc) {
		if f.Label != "Meldung" && f.Label != "Gerät" && f.Label != "Sensor" {
			facts = append(facts, f)
		}
	}
	others := r.othersLines(now)
	lead := r.headline()
	b := mailBlock{Title: r.who(channelTenant) + " · " + Clean(r.Sensor, 100), Lead: lead, Facts: facts, Others: others, Link: r.Link}
	var txt strings.Builder
	txt.WriteString(b.Title + "\n")
	if lead != "" {
		txt.WriteString(lead + "\n")
	}
	txt.WriteString("\n")
	for _, f := range facts {
		txt.WriteString(f.Label + ": " + f.Value + "\n")
	}
	if r.Chart != nil {
		if data := r.Chart.PNG(); data != nil {
			b.Image, b.Caption = "graph1@openwacht", r.Chart.Caption()
			b.AxisFrom = fmt.Sprintf("vor %.0f Std.", r.Chart.To.Sub(r.Chart.From).Hours())
			m.Images = append(m.Images, MailImage{CID: b.Image, Data: data})
			txt.WriteString("\n" + b.Caption + "\n")
		}
	}
	if len(others) > 0 {
		txt.WriteString("\nWeitere offene Probleme am Gerät:\n")
		for _, o := range others {
			txt.WriteString("- " + o + "\n")
		}
	}
	if r.Link != "" {
		txt.WriteString("\nIn OpenWacht öffnen: " + r.Link + "\n")
	}
	ft := foot(channelTenant, channel)
	txt.WriteString("\n-- \n" + ft + "\n")
	m.Text = txt.String()
	color := stateColor[r.Status]
	if r.Event == Recovered {
		color = stateColor[OK]
	}
	m.HTML = renderMail(m.Subject, color, m.Subject, []mailBlock{b}, ft)
	return m
}

func renderMail(subject, color, head string, blocks []mailBlock, ft string) string {
	var buf bytes.Buffer
	_ = mailTmpl.Execute(&buf, map[string]any{"Subject": subject, "Color": template.CSS(color), "Head": head,
		"Blocks": blocks, "Foot": ft})
	return buf.String()
}

// sortReports: schlimmste zuerst, dann Mandant und Name (wie Build).
func sortReports(rs []Report) []Report {
	out := append([]Report(nil), rs...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ra, rb := rank[a.Status], rank[b.Status]
		if a.Event == Recovered {
			ra = -1
		}
		if b.Event == Recovered {
			rb = -1
		}
		if ra != rb {
			return ra > rb
		}
		if a.Tenant != b.Tenant {
			return a.Tenant < b.Tenant
		}
		return a.Check < b.Check
	})
	return out
}

// counts: „3 Probleme, 2 wieder OK“.
func counts(rs []Report) string {
	problems, recovered := 0, 0
	for _, r := range rs {
		if r.Event == Recovered {
			recovered++
		} else {
			problems++
		}
	}
	var parts []string
	switch {
	case problems == 1:
		parts = append(parts, "1 Problem")
	case problems > 1:
		parts = append(parts, fmt.Sprintf("%d Probleme", problems))
	}
	if recovered > 0 {
		parts = append(parts, fmt.Sprintf("%d wieder OK", recovered))
	}
	return strings.Join(parts, ", ")
}

// SummaryLimit: Ab so vielen Ereignissen in einem Durchlauf geht statt
// einzelner Mails eine Sammelmail raus (ohne Graphen).
const SummaryLimit = 10

// BuildSummary: eine Sammelmail für viele Ereignisse. Betreff mit dem
// schlimmsten Zustand vorn, im Text getrennt „Probleme“ und „Wieder in
// Ordnung“, je Ereignis eine Zeile (1.0.3).
func BuildSummary(channelTenant, channel string, rs []Report, link string) Mail {
	sorted := sortReports(rs)
	worst := OK
	for _, r := range sorted {
		if r.Event != Recovered && rank[r.Status] > rank[worst] {
			worst = r.Status
		}
	}
	subject := Clean(stateShort[worst]+" · OpenWacht: "+counts(sorted), SubjectMax)
	var problems, recovered []Report
	for _, r := range sorted {
		if r.Event == Recovered {
			recovered = append(recovered, r)
		} else {
			problems = append(problems, r)
		}
	}
	var txt strings.Builder
	txt.WriteString(counts(sorted) + "\n")
	var blocks []mailBlock
	section := func(title string, list []Report, withMsg bool) {
		if len(list) == 0 {
			return
		}
		b := mailBlock{Title: fmt.Sprintf("%s (%d)", title, len(list))}
		txt.WriteString("\n" + b.Title + "\n")
		for i, r := range list {
			if i == 200 {
				b.Facts = append(b.Facts, Fact{"…", fmt.Sprintf("und %d weitere", len(list)-i)})
				txt.WriteString(fmt.Sprintf("… und %d weitere\n", len(list)-i))
				break
			}
			st := stateShort[r.Status]
			if r.Event == Recovered {
				st = "OK"
			} else if r.Event == Reminder {
				st += " (Erinnerung)"
			}
			line := r.who(channelTenant) + " · " + Clean(r.Sensor, 100)
			if msg := Clean(r.Message, 150); withMsg && msg != "" {
				line += " – " + msg
			}
			b.Facts = append(b.Facts, Fact{st, line})
			txt.WriteString("- " + st + " · " + line + "\n")
		}
		blocks = append(blocks, b)
	}
	section("Probleme", problems, true)
	section("Wieder in Ordnung", recovered, false)
	if len(blocks) == 0 {
		blocks = append(blocks, mailBlock{Title: "Keine Ereignisse"})
	}
	if link != "" {
		txt.WriteString("\nIn OpenWacht öffnen: " + link + "\n")
		blocks[len(blocks)-1].Link = link
	}
	ft := foot(channelTenant, channel)
	txt.WriteString("\n-- \n" + ft + "\n")
	return Mail{Subject: subject, Text: txt.String(), HTML: renderMail(subject, stateColor[worst], subject, blocks, ft)}
}

// TestMail: „Test senden“ für einen Mail-Kanal bzw. die SMTP-Einstellung.
func TestMail(channelTenant, channel string) Mail {
	subject := Clean("OpenWacht "+Clean(channelTenant, 100)+": Testnachricht", 200)
	body := "Der Alarmkanal „" + Clean(channel, 100) + "“ funktioniert."
	ft := foot(channelTenant, channel)
	return Mail{Subject: subject, Text: body + "\n\n-- \n" + ft + "\n",
		HTML: renderMail(subject, stateColor[OK], subject, []mailBlock{{Title: body}}, ft)}
}

// --- Teams -------------------------------------------------------------------------

// TeamsLimit: Teams nimmt über Workflows etwa 28 KB an.
const TeamsLimit = 25000

// noMarkdown: Teams deutet Text in TextBlocks als Markdown. Fremdtexte dürfen
// keine Links oder Hervorhebungen erzeugen.
func noMarkdown(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune("\\`*_{}[]()#+-.!|<>~", r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

var teamsStyle = map[string]string{OK: "good", Warn: "warning", Crit: "attention", Unknown: "emphasis"}

// BuildTeams: eine Adaptive Card für einen Durchlauf. Passt nicht alles in
// TeamsLimit, fallen die letzten (am wenigsten schlimmen) Ereignisse weg und
// die Karte nennt ihre Zahl.
func BuildTeams(channelTenant string, rs []Report, now time.Time, loc *time.Location, link string) []byte {
	sorted := sortReports(rs)
	for n := min(len(sorted), 20); n >= 0; n-- {
		b := teamsCard(channelTenant, sorted[:n], len(sorted)-n, now, loc, link)
		if len(b) <= TeamsLimit || n == 0 {
			return b
		}
	}
	return nil
}

func teamsCard(channelTenant string, rs []Report, dropped int, now time.Time, loc *time.Location, link string) []byte {
	title := "OpenWacht " + Clean(channelTenant, 100) + ": " + counts(rs)
	if len(rs) == 0 {
		title = "OpenWacht " + Clean(channelTenant, 100)
	}
	body := []any{map[string]any{"type": "TextBlock", "text": noMarkdown(title), "weight": "Bolder", "size": "Medium", "wrap": true}}
	for _, r := range rs {
		var facts []any
		for _, f := range r.Facts(channelTenant, now, loc) {
			facts = append(facts, map[string]any{"title": noMarkdown(f.Label), "value": noMarkdown(f.Value)})
		}
		if o := r.othersLines(now); len(o) > 0 {
			facts = append(facts, map[string]any{"title": "Weitere Probleme", "value": noMarkdown(strings.Join(o, "; "))})
		}
		style := teamsStyle[r.Status]
		if r.Event == Recovered {
			style = "good"
		}
		items := []any{
			map[string]any{"type": "TextBlock", "text": noMarkdown(r.Subject(channelTenant)), "weight": "Bolder", "wrap": true},
			map[string]any{"type": "FactSet", "facts": facts},
		}
		if r.Link != "" {
			items = append(items, map[string]any{"type": "ActionSet", "actions": []any{
				map[string]any{"type": "Action.OpenUrl", "title": "Gerät öffnen", "url": r.Link}}})
		}
		body = append(body, map[string]any{"type": "Container", "style": style, "separator": true, "items": items})
	}
	if dropped > 0 {
		body = append(body, map[string]any{"type": "TextBlock", "wrap": true,
			"text": fmt.Sprintf("… und %d weitere Ereignisse", dropped)})
	}
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
		"version": "1.4", "msteams": map[string]any{"width": "Full"}, "body": body}
	if link != "" {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "In OpenWacht öffnen", "url": link}}
	}
	b, _ := json.Marshal(map[string]any{"type": "message", "attachments": []any{map[string]any{
		"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": nil, "content": card}}})
	return b
}

// TeamsTest: Karte für „Test senden“.
func TeamsTest(channelTenant, channel string) []byte {
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
		"version": "1.4", "body": []any{
			map[string]any{"type": "TextBlock", "weight": "Bolder", "wrap": true,
				"text": noMarkdown("OpenWacht " + Clean(channelTenant, 100) + ": Testnachricht")},
			map[string]any{"type": "TextBlock", "wrap": true,
				"text": noMarkdown("Der Alarmkanal „" + Clean(channel, 100) + "“ funktioniert.")}}}
	b, _ := json.Marshal(map[string]any{"type": "message", "attachments": []any{map[string]any{
		"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": nil, "content": card}}})
	return b
}

// --- Webhook (JSON) ------------------------------------------------------------------

// HookEvent: ein Ereignis im JSON eines Webhooks.
type HookEvent struct {
	Event   string     `json:"ereignis"` // problem, erholt, erinnerung
	Status  string     `json:"zustand"`  // ok, warn, crit, unknown
	Tenant  string     `json:"mandant"`
	Device  string     `json:"geraet"`
	Sensor  string     `json:"sensor"`
	Message string     `json:"meldung"`
	Since   *time.Time `json:"seit,omitempty"`
	LastOK  *time.Time `json:"zuletzt_ok,omitempty"`
	Fore    string     `json:"prognose,omitempty"`
	Maint   bool       `json:"wartung"`
	Others  int        `json:"weitere_probleme"`
	Link    string     `json:"link,omitempty"`
}

// HookPayload: der Rumpf eines Webhooks (Version 1).
type HookPayload struct {
	Type    string      `json:"typ"` // openwacht.alarm, openwacht.test
	Version int         `json:"version"`
	Sent    time.Time   `json:"gesendet"`
	Channel string      `json:"kanal"`
	Tenant  string      `json:"mandant"`
	Events  []HookEvent `json:"ereignisse"`
	More    int         `json:"weitere,omitempty"`
}

// HookLimit: so viele Ereignisse trägt ein Webhook höchstens.
const HookLimit = 200

// BuildHook: JSON für einen Durchlauf.
func BuildHook(channelTenant, channel string, rs []Report, now time.Time) []byte {
	p := HookPayload{Type: "openwacht.alarm", Version: 1, Sent: now.UTC().Truncate(time.Second),
		Channel: Clean(channel, 100), Tenant: Clean(channelTenant, 100), Events: []HookEvent{}}
	for i, r := range sortReports(rs) {
		if i == HookLimit {
			p.More = len(rs) - i
			break
		}
		p.Events = append(p.Events, HookEvent{Event: r.Event.String(), Status: r.Status, Tenant: Clean(r.Tenant, 100),
			Device: Clean(r.Device, 100), Sensor: Clean(r.Sensor, 100), Message: Clean(r.Message, 300),
			Since: r.Since, LastOK: r.LastOK, Fore: Clean(r.Forecast, 200), Maint: r.Maintenance,
			Others: len(r.Others), Link: r.Link})
	}
	b, _ := json.Marshal(p)
	return b
}

// HookTest: JSON für „Test senden“.
func HookTest(channelTenant, channel string, now time.Time) []byte {
	b, _ := json.Marshal(HookPayload{Type: "openwacht.test", Version: 1, Sent: now.UTC().Truncate(time.Second),
		Channel: Clean(channel, 100), Tenant: Clean(channelTenant, 100), Events: []HookEvent{}})
	return b
}
