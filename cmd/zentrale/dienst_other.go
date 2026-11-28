// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
)

func dienstStarten(ctx context.Context, args []string, out io.Writer) error {
	return cmdDienst(ctx, args, out)
}

var errNurWindows = errors.New("nur unter Windows (unter Linux: installieren, in Docker: dienst)")

func cmdDienstEinrichten(context.Context, []string, io.Writer) error { return errNurWindows }
func cmdDienstEntfernen(context.Context, []string, io.Writer) error  { return errNurWindows }
