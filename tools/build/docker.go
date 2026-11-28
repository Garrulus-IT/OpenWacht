// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// writeDockerContext legt dist/docker an (1.0.14): Kontext für das Image der
// Zentrale (deploy/docker/Dockerfile) mit der Zentrale je Architektur und
// denselben Downloads wie im Debian-Paket. Danach:
//
//	docker build -t openwacht-zentrale:<version> dist/docker
//
// Nach dem Signieren baut -pakete-neu den Kontext neu, wenn es ihn gibt.
func writeDockerContext(root string) error {
	dir := filepath.Join(root, "docker")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "leer"), 0o755); err != nil {
		return err
	}
	df, err := repoFile(filepath.Join("deploy", "docker", "Dockerfile"))
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"Dockerfile": df,
		// Benutzer ohne Anmeldung für die Zentrale im Image (scratch)
		"passwd":     []byte("root:x:0:0:root:/root:/sbin/nologin\nopenwacht:x:65532:65532:OpenWacht:/var/lib/openwacht:/sbin/nologin\n"),
		"group":      []byte("root:x:0:\nopenwacht:x:65532:\n"),
		"leer/.keep": nil,
	}
	for _, t := range zentraleTargets {
		name := outputName("openwacht-zentrale", t)
		b, err := os.ReadFile(filepath.Join(root, t.os, name))
		if err != nil {
			return err
		}
		files[name] = b
	}
	dl, err := downloadFiles(root, "downloads")
	if err != nil {
		return err
	}
	for _, f := range dl {
		files[f.path] = f.data
	}
	for name, b := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(name, "openwacht-zentrale_") {
			mode = 0o755
		}
		if err := os.WriteFile(p, b, mode); err != nil {
			return err
		}
	}
	return nil
}
