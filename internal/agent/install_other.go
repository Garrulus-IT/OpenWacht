// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package agent

import "errors"

var errNoService = errors.New("Einrichtung als Dienst gibt es bisher nur unter Linux und Windows")

var DefaultDir = "/var/lib/openwacht-agent"

func IsRoot() bool                            { return false }
func CheckBinary(string) error                { return errNoService }
func EnsureUser() (int, int, error)           { return 0, 0, errNoService }
func HandOver(string, int, int) error         { return errNoService }
func InstallUnit(binary, dir string) error    { return errNoService }
func InstallUpdateUnits(string, string) error { return errNoService }
func SystemdRunning() bool                    { return false }

func SetProcVisible(bool) (bool, error) { return false, nil }
