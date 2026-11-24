// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import "syscall"

// diskUsage: Belegung je Dateisystem (gleiche Dateisysteme nur einmal, mit
// dem ersten Pfad). Fehlende Pfade werden übersprungen.
func diskUsage(paths []string) []diskInfo {
	var out []diskInfo
	seen := map[uint64]bool{}
	for _, p := range paths {
		var st syscall.Stat_t
		if syscall.Stat(p, &st) != nil {
			continue
		}
		if seen[uint64(st.Dev)] {
			continue
		}
		var fs syscall.Statfs_t
		if syscall.Statfs(p, &fs) != nil || fs.Blocks == 0 {
			continue
		}
		seen[uint64(st.Dev)] = true
		total := float64(fs.Blocks) * float64(fs.Bsize)
		avail := float64(fs.Bavail) * float64(fs.Bsize)
		free := float64(fs.Bfree) * float64(fs.Bsize)
		used := total - free
		// wie df: belegt / (belegt + für Benutzer verfügbar)
		pct := 100 * used / (used + avail)
		out = append(out, diskInfo{path: p, pct: pct, free: uint64(avail)})
	}
	return out
}
