// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main

import (
	"fmt"
	"os"
)

func run([]string) int {
	fmt.Fprintln(os.Stderr, "openwacht-desktop gibt es nur für Windows. Unter anderen Systemen: OpenWacht im Browser mit Hinweisen und Benachrichtigungen.")
	return 2
}
