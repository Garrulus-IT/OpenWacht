// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package agent

import (
	"context"
	"errors"
	"time"

	"github.com/garrulus-it/openwacht/internal/checks"
)

func defaultSensorEnv() *sensorEnv {
	return &sensorEnv{
		docker: dockerContainerState,
		service: func(context.Context, string) checks.Result {
			return checks.Result{Status: checks.Unknown, Message: "Dienst-Sensoren gibt es auf diesem System nicht"}
		},
		processes: func(context.Context) ([]string, error) {
			return nil, errors.New("Prozess-Sensoren gibt es auf diesem System nicht")
		},
		now: time.Now,
	}
}
