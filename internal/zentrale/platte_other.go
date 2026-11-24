// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package zentrale

// diskUsage: Die Zentrale läuft nur unter Linux; anderswo keine Prüfung.
func diskUsage(paths []string) []diskInfo { return nil }
