// SPDX-License-Identifier: AGPL-3.0-only

// Package alarm entscheidet, wann ein Check-Zustand gemeldet wird, baut die
// Benachrichtigung und verschickt sie per ntfy.
//
// Die Logik stammt aus dem Python-Prototyp (decide/build_notification):
//
//   - Ein Fehler (crit, unknown) alarmiert erst nach Threshold Fehlschlägen in
//     Folge, und nur, wenn sich der gemeldete Zustand ändert.
//   - Besteht er weiter, kommt nach Reminder eine Erinnerung.
//   - Warnungen gehen sofort und einmalig raus.
//   - Bei Erholung kommt eine Entwarnung.
//   - Als gemeldet gilt ein Ereignis erst nach erfolgreichem Versand; der
//     Aufrufer speichert den gemeldeten Zustand nur dann.
package alarm

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Zustände wie in internal/checks.
const (
	OK      = "ok"
	Warn    = "warn"
	Crit    = "crit"
	Unknown = "unknown"
)

var rank = map[string]int{OK: 0, Warn: 1, Unknown: 2, Crit: 3}

// Event ist das Ergebnis von Decide.
type Event int

const (
	None      Event = iota
	Problem         // neuer oder veränderter Fehlerzustand
	Recovered       // wieder OK
	Reminder        // Fehler besteht weiter
)

func (e Event) String() string {
	switch e {
	case Problem:
		return "problem"
	case Recovered:
		return "erholt"
	case Reminder:
		return "erinnerung"
	}
	return "keins"
}

// Decide bestimmt das Ereignis für einen Check und einen Empfänger.
// alerted ist der zuletzt an diesen Empfänger gemeldete Zustand ("" = noch
// nie), alertedAt der Zeitpunkt dieser Meldung.
func Decide(status string, fails int, alerted string, alertedAt time.Time,
	threshold int, reminder time.Duration, now time.Time) Event {
	switch status {
	case OK:
		if alerted == "" || alerted == OK {
			return None
		}
		return Recovered
	case Warn:
		// Warnungen (z. B. Zertifikat läuft bald ab) sind stabil: sofort melden.
		if alerted == Warn {
			return None
		}
		return Problem
	case Crit, Unknown:
		if fails < threshold {
			return None
		}
		if alerted != status {
			return Problem
		}
		if reminder > 0 && !alertedAt.IsZero() && now.Sub(alertedAt) >= reminder {
			return Reminder
		}
	}
	return None
}

// Item ist ein zu meldendes Ereignis.
type Item struct {
	Tenant  string // Name des Mandanten des Checks
	Check   string
	Status  string
	Message string
	Event   Event
}

// Message ist eine ntfy-Nachricht (ohne Topic).
type Message struct {
	Title    string   `json:"title"`
	Message  string   `json:"message"`
	Priority int      `json:"priority"`
	Tags     []string `json:"tags"`
}

var symbol = map[string]string{OK: "✅", Warn: "⚠️", Crit: "❌", Unknown: "❔"}

// Grenzen: ntfy nimmt bis 4096 Byte Nachricht an.
const (
	maxLines   = 25
	maxMessage = 3800
	maxTitle   = 200
)

// Clean macht aus Fremdtext (Namen, Meldungen, Fehlertexte) eine Zeile ohne
// Steuerzeichen mit höchstens n Zeichen.
func Clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n-1]) + "…"
	}
	return s
}

// Build fasst die Ereignisse für einen Kanal zusammen. channelTenant ist der
// Mandant des Kanals: Gehört ein Check einem anderen (Untermandanten), steht
// dessen Name vor dem Check.
func Build(channelTenant string, items []Item) Message {
	sorted := append([]Item(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if rank[sorted[i].Status] != rank[sorted[j].Status] {
			return rank[sorted[i].Status] > rank[sorted[j].Status]
		}
		if sorted[i].Tenant != sorted[j].Tenant {
			return sorted[i].Tenant < sorted[j].Tenant
		}
		return sorted[i].Check < sorted[j].Check
	})
	problems, recovered := 0, 0
	worst := OK
	oneTenant := true
	for _, it := range sorted {
		if it.Tenant != sorted[0].Tenant {
			oneTenant = false
		}
		if it.Event == Recovered {
			recovered++
			continue
		}
		problems++
		if rank[it.Status] > rank[worst] {
			worst = it.Status
		}
	}
	var lines []string
	size := 0
	for i, it := range sorted {
		name := Clean(it.Check, 100)
		if it.Tenant != channelTenant {
			name = Clean(it.Tenant, 100) + " / " + name
		}
		line := fmt.Sprintf("%s %s: %s", symbol[it.Status], name, Clean(it.Message, 300))
		if it.Event == Reminder {
			line += " (Erinnerung)"
		}
		if len(lines) == maxLines || size+len(line)+1 > maxMessage {
			lines = append(lines, fmt.Sprintf("… und %d weitere", len(sorted)-i))
			break
		}
		lines = append(lines, line)
		size += len(line) + 1
	}
	var parts []string
	if problems == 1 {
		parts = append(parts, "1 Problem")
	} else if problems > 1 {
		parts = append(parts, fmt.Sprintf("%d Probleme", problems))
	}
	if recovered > 0 {
		parts = append(parts, fmt.Sprintf("%d wieder OK", recovered))
	}
	prefix := channelTenant
	if oneTenant && len(sorted) > 0 {
		prefix = sorted[0].Tenant
	}
	priority := map[string]int{OK: 3, Warn: 3, Unknown: 4, Crit: 4}[worst]
	tag := map[string]string{OK: "white_check_mark", Warn: "warning", Unknown: "grey_question", Crit: "rotating_light"}[worst]
	return Message{
		Title:    Clean(Clean(prefix, 100)+": "+strings.Join(parts, ", "), maxTitle),
		Message:  strings.Join(lines, "\n"),
		Priority: priority,
		Tags:     []string{tag},
	}
}

// TestMessage ist die Nachricht für „Test senden“.
func TestMessage(tenant, channel string) Message {
	return Message{
		Title:    Clean(Clean(tenant, 100)+": Testnachricht", maxTitle),
		Message:  "Der Alarmkanal „" + Clean(channel, 100) + "“ funktioniert ✅",
		Priority: 3,
		Tags:     []string{"test_tube"},
	}
}
