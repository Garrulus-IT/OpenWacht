// SPDX-License-Identifier: AGPL-3.0-only

// xapiattrappe startet die XAPI-Attrappe (internal/xapi/xapitest) als eigenes
// Programm, für das Bilder-Skript und Browsertests: ein Pool mit zwei Hosts
// auf derselben Portnummer unter zwei Adressen. Nur Testdaten, nur für
// Entwicklung; gehört nicht in eine Installation.
//
//	go run ./tools/xapiattrappe -master 127.0.20.40 -host2 127.0.20.41 -port 18448
//
// Gibt den Fingerabdruck des Pool-Masters in einer Zeile „fingerabdruck=…“ aus.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/garrulus-it/openwacht/internal/xapi/xapitest"
)

func main() {
	master := flag.String("master", "127.0.0.1", "Adresse des Pool-Masters")
	host2 := flag.String("host2", "127.0.0.2", "Adresse des zweiten Hosts")
	port := flag.Int("port", 18448, "Port beider Hosts (TLS)")
	flag.Parse()
	srv, err := xapitest.Serve(*master, *host2, *port, xapitest.NewFake())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("fingerabdruck=%s\n", srv.Pin)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	srv.Close()
}
