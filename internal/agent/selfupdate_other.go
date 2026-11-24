// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !windows

package agent

import "os"

func renameOver(tmp, exe string) error { return os.Rename(tmp, exe) }

// RestartService gibt es nur unter Linux und Windows.
func RestartService() error { return errNoService }

// ReplaceBinary gibt es nur unter Linux und Windows.
func ReplaceBinary(string, []byte) error { return errNoService }
