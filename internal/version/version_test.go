// SPDX-License-Identifier: AGPL-3.0-only

package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	got := String("openwacht-agent")
	for _, want := range []string{"openwacht-agent", Version, Commit, runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, erwartet darin %q", got, want)
		}
	}
	if strings.Contains(got, "\n") {
		t.Errorf("String() muss einzeilig sein: %q", got)
	}
}
