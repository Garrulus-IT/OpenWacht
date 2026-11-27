// SPDX-License-Identifier: AGPL-3.0-only

// citrixattrappe startet die Attrappe des Citrix Monitor Service
// (internal/citrix/citrixtest) als eigenes Programm, für das Bilder-Skript.
// Nur Testdaten, nur für Entwicklung; gehört nicht in eine Installation.
//
//	go run ./tools/citrixattrappe -adresse 127.0.20.60:18450
//
// Gibt den Fingerabdruck in einer Zeile „fingerabdruck=…“ aus.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/garrulus-it/openwacht/internal/citrix/citrixtest"
)

func main() {
	addr := flag.String("adresse", "127.0.0.1:18450", "Adresse und Port (TLS)")
	flag.Parse()
	srv, err := citrixtest.Serve(*addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("fingerabdruck=%s\n", srv.Pin)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	srv.Close()
}
