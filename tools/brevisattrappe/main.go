// SPDX-License-Identifier: AGPL-3.0-only

// brevisattrappe startet die Attrappe eines brevis.one-SMS-Gateways
// (internal/alarm/brevistest) als eigenes Programm, für das Bilder-Skript,
// Browsertests und zum Ausprobieren. Nur Testdaten, nur für Entwicklung;
// gehört nicht in eine Installation.
//
//	go run ./tools/brevisattrappe -adresse 127.0.20.70:18449
//
// Gibt den Fingerabdruck des Zertifikats in einer Zeile „fingerabdruck=…“
// aus, danach je angenommener Anfrage eine Zeile (ohne Passwort). Benutzer
// und Passwort sind die festen Testwerte aus brevistest (openwacht-api /
// test-passwort-123). Fehlerfälle: -fehler 401|403|408|400|weiterleitung.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/garrulus-it/openwacht/internal/alarm/brevistest"
)

func main() {
	addr := flag.String("adresse", "127.0.0.1:18449", "Adresse und Port (TLS)")
	fehler := flag.String("fehler", "", "Fehlerfall: 400, 401, 403, 408 oder weiterleitung")
	flag.Parse()
	f := brevistest.NewFake()
	switch *fehler {
	case "":
	case "400":
		f.Respond(http.StatusBadRequest, "Error. See Gateway logs for more information.")
	case "401":
		f.Respond(http.StatusUnauthorized, "401 Unauthorized - Username or Password wrong.")
	case "403":
		f.NoRight(true)
	case "408":
		f.Timeout(true)
	case "weiterleitung":
		f.Redirect(true)
	default:
		log.Fatalf("unbekannter Fehlerfall %q", *fehler)
	}
	f.OnRequest = func(r brevistest.Request, code int) {
		fmt.Printf("HTTP %d modus=%s an=%s anruf=%v text=%q\n", code, r.Mode, r.To, r.Ring, r.Text)
	}
	srv, pin, err := brevistest.Serve(*addr, f)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("fingerabdruck=%s\n", pin)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	srv.Close()
}
