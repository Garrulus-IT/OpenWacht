// SPDX-License-Identifier: AGPL-3.0-only

// ontapattrappe startet die ONTAP-Attrappe (internal/ontap/ontaptest) als
// eigenes Programm, für das Bilder-Skript und Browsertests. Nur Testdaten,
// nur für Entwicklung; gehört nicht in eine Installation.
//
//	go run ./tools/ontapattrappe -adresse 127.0.20.30:8443
//
// Gibt den Fingerabdruck des Zertifikats in einer Zeile „fingerabdruck=…“ aus.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/garrulus-it/openwacht/internal/ontap/ontaptest"
)

func main() {
	addr := flag.String("adresse", "127.0.0.1:18447", "Adresse und Port (TLS)")
	flag.Parse()
	srv, pin, err := ontaptest.Serve(*addr, ontaptest.NewFake())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("fingerabdruck=%s\n", pin)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	srv.Close()
}
