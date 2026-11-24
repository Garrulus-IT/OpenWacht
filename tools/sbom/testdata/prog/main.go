// SPDX-License-Identifier: AGPL-3.0-only

// Testprogramm für tools/sbom: linkt genau ein fremdes Modul (x/sys), damit
// der Test die Build-Info eines echten Binarys mit Abhängigkeit prüfen kann.
package main

import (
	"fmt"

	"golang.org/x/sys/cpu"
)

func main() { fmt.Println(cpu.X86.HasAVX2) }
