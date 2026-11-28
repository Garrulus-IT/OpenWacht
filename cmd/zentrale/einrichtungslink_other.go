// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import (
	"context"
	"io"
	"path/filepath"
)

// cmdSetupLink: neuer Einrichtungslink außerhalb von Linux (Windows, dienst),
// mit OPENWACHT_DB_EIGENTUEMER in der Umgebung oder in zentrale.env.
func cmdSetupLink(ctx context.Context, args []string, out io.Writer) error {
	if err := ladeEnvDatei(filepath.Join(datenStandard(), "zentrale.env")); err != nil {
		return err
	}
	conn, err := connectEnv(ctx, "OPENWACHT_DB_EIGENTUEMER")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	l, err := newSetupLink(ctx, conn, 0)
	if err != nil {
		return err
	}
	neuerLinkHinweis = `openwacht-zentrale.exe einrichtungslink`
	printSetupLink(out, l, false)
	return nil
}
