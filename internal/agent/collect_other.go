// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package agent

import (
	"errors"
	"runtime"

	"github.com/garrulus-it/openwacht/internal/agentproto"
)

// Collector: Auf diesem Betriebssystem gibt es noch keine Messwerte. Es gibt sie
// für Linux und Windows.
type Collector struct{}

func NewCollector() *Collector { return &Collector{} }

func (c *Collector) Collect() (agentproto.Snapshot, error) {
	return agentproto.Snapshot{}, errors.New("Messwerte für " + runtime.GOOS + " werden noch nicht unterstützt")
}
