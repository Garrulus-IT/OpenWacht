// SPDX-License-Identifier: AGPL-3.0-only

package alarm

import (
	"fmt"
	"slices"
	"strings"

	"github.com/garrulus-it/openwacht/internal/snmp"
)

// Gegenstände einer Citrix-Site (1.0.6), zusätzlich zu stumm.
const (
	SubjectCitrixVDA      = "citrixvda"
	SubjectCitrixFailures = "citrixfehler"
)

// Schwellen für fehlgeschlagene Verbindungen der letzten Stunde (Annahme,
// nach den ersten Wochen im Betrieb prüfen).
const (
	citrixFailWarn = 5
	citrixFailCrit = 25
)

// CitrixFailureText: deutsche Kurzform von ConnectionFailureEnumValue
// (Citrix Monitor Service, „Descriptions for enums and error codes“).
func CitrixFailureText(code int) string {
	switch code {
	case 0:
		return "unbekannt"
	case 2:
		return "Sitzung vorbereiten"
	case 3:
		return "Registrierung abgelaufen"
	case 4:
		return "Verbindung abgelaufen"
	case 5:
		return "Lizenz"
	case 6:
		return "Ticket"
	case 7:
		return "sonstiges"
	case 8:
		return "allgemeiner Fehler"
	case 9:
		return "Wartungsmodus"
	case 10:
		return "Anwendung deaktiviert"
	case 11:
		return "Funktion nicht lizenziert"
	case 12:
		return "keine Maschine frei"
	case 13:
		return "Sitzungsgrenze erreicht"
	}
	return fmt.Sprintf("Code %d", code)
}

// citrixVDAState: Fehler, wenn VDAs außerhalb des Wartungsmodus nicht
// registriert sind; kritisch, wenn es keinen registrierten mehr gibt.
func citrixVDAState(x *snmp.Citrix) (string, string) {
	if x.Unregistered == 0 {
		return OK, fmt.Sprintf("alle %d VDAs registriert (%d im Wartungsmodus)", x.Registered, x.Maintenance)
	}
	names := strings.Join(x.UnregisteredNames, ", ")
	if x.Unregistered > len(x.UnregisteredNames) {
		names += ", …"
	}
	msg := fmt.Sprintf("%d von %d VDAs nicht registriert: %s", x.Unregistered, x.Machines, names)
	if x.Registered == 0 {
		return Crit, msg
	}
	return Warn, msg
}

func citrixFailureState(x *snmp.Citrix) (string, string) {
	if x.FailureTotal == 0 {
		return OK, fmt.Sprintf("keine fehlgeschlagenen Verbindungen in %d Minuten", x.FailureWindowMin)
	}
	parts := make([]string, 0, 3)
	for _, f := range x.Failures[:min(3, len(x.Failures))] {
		parts = append(parts, fmt.Sprintf("%d× %s", f.Count, CitrixFailureText(f.Code)))
	}
	msg := fmt.Sprintf("%d fehlgeschlagene Verbindungen in %d Minuten (%s)", x.FailureTotal, x.FailureWindowMin, strings.Join(parts, ", "))
	switch {
	case x.FailureTotal >= citrixFailCrit:
		return Crit, msg
	case x.FailureTotal >= citrixFailWarn:
		return Warn, msg
	}
	return OK, msg
}

func evaluateCitrix(host string, x *snmp.Citrix, partial []string, add func(sub, name, status, msg string)) {
	st, msg := citrixVDAState(x)
	add(SubjectCitrixVDA, host+" · VDAs", st, msg)
	if !slices.Contains(partial, "fehler") {
		st, msg := citrixFailureState(x)
		add(SubjectCitrixFailures, host+" · Verbindungsfehler", st, msg)
	}
}

// citrixSubjectName: Name für Gegenstände, die nicht mehr gemeldet werden.
func citrixSubjectName(host, sub string) (string, bool) {
	switch sub {
	case SubjectCitrixVDA:
		return host + " · VDAs", true
	case SubjectCitrixFailures:
		return host + " · Verbindungsfehler", true
	}
	return "", false
}
