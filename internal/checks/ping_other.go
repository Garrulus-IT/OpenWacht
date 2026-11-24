// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package checks

import (
	"context"
	"time"
)

// Die Zentrale läuft nur unter Linux; anderswo gibt es keinen Ping-Check.
func pingCheck(context.Context, *Guard, Spec, time.Duration) Result {
	return Result{Unknown, "Ping wird auf diesem System nicht unterstützt", "", 0}
}
