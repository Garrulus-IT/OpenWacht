// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package checks

import (
	"context"
	"time"
)

// Ping-Check gibt es unter Linux und Windows (ping_linux.go, ping_windows.go).
func pingCheck(context.Context, *Guard, Spec, time.Duration) Result {
	return Result{Unknown, "Ping wird auf diesem System nicht unterstützt", "", 0}
}
