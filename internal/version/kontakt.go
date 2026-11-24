// SPDX-License-Identifier: AGPL-3.0-only

package version

import (
	_ "embed"
	"strings"
)

// Meldeweg des Herstellers für Sicherheitslücken (security.txt, SECURITY.md).
// Eine Zeile mit einer Adresse wie mailto:… oder https://…; leer = noch kein
// Meldeweg festgelegt. Der Herausgeber trägt ihn vor 1.0 ein (eigener Pull Request).
//
//go:embed sicherheitskontakt.txt
var securityContact string

// SecurityContact liefert den Meldeweg des Herstellers oder "".
func SecurityContact() string { return strings.TrimSpace(securityContact) }
