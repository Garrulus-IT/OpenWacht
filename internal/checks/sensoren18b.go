// SPDX-License-Identifier: AGPL-3.0-only

package checks

// Etappe 18b: TCP-Banner und NTP-Abweichung.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"
)

const maxBanner = 512

// tcpBanner liest die erste Zeile, die ein Dienst von sich aus schickt
// (SMTP, IMAP, POP3, SSH, FTP), im Klartext oder nach direktem TLS. Vom
// Inhalt wird nur gemeldet, ob der erwartete Text vorkommt (Leitprinzip 5).
func (r *Runner) tcpBanner(ctx context.Context, s Spec, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	conn, err := r.Guard.DialContext(ctx, "tcp", net.JoinHostPort(s.Host, fmt.Sprint(s.Port)))
	if err != nil {
		return describeNetErr(err, timeout, fmt.Sprintf("Port %d: ", s.Port))
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if s.TLS {
		roots, err := s.roots()
		if err != nil {
			return Result{Unknown, clean(err.Error(), 150), "", 0}
		}
		tc := tls.Client(conn, &tls.Config{ServerName: s.Host, RootCAs: roots, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			var cv *tls.CertificateVerificationError
			if errors.As(err, &cv) {
				return Result{Crit, "TLS: " + explainVerify(cv), "", 0}
			}
			return describeNetErr(err, timeout, "TLS: ")
		}
		conn = tc
	}
	buf := make([]byte, 0, maxBanner)
	tmp := make([]byte, 128)
	for len(buf) < maxBanner && !bytes.Contains(buf, []byte("\n")) {
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:min(n, maxBanner-len(buf))]...)
		if err != nil {
			break
		}
	}
	took := time.Since(start)
	line, _, _ := bytes.Cut(buf, []byte("\n"))
	line = bytes.TrimRight(line, "\r")
	if len(bytes.TrimSpace(line)) == 0 {
		return Result{Crit, fmt.Sprintf("Port %d offen, aber kein Banner", s.Port), ms(took), took}
	}
	if s.Contains != "" && !strings.Contains(string(line), s.Contains) {
		return Result{Crit, "Banner ohne erwarteten Text", ms(took), took}
	}
	return Result{OK, "Banner erhalten", ms(took), took}
}

// --- NTP ------------------------------------------------------------------------

// ntpEpoch: Sekunden von 1900 bis 1970.
const ntpEpoch = 2208988800

func toNTP(t time.Time) uint64 {
	sec := uint64(t.Unix() + ntpEpoch)
	frac := uint64(t.Nanosecond()) << 32 / 1e9
	return sec<<32 | frac
}

func fromNTP(v uint64) time.Time {
	sec := int64(v>>32) - ntpEpoch
	nsec := int64((v & 0xffffffff) * 1e9 >> 32)
	return time.Unix(sec, nsec)
}

// ntp fragt einen Server (SNTP, RFC 4330) und bewertet die Abweichung zur Uhr
// der Zentrale. Die Antwort muss den eigenen Zeitstempel zurückgeben.
func (r *Runner) ntp(ctx context.Context, s Spec, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := r.Guard.Resolve(ctx, s.Host)
	if err != nil {
		return describeNetErr(err, timeout, "")
	}
	d := net.Dialer{Control: r.Guard.control}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(addrs[0].String(), fmt.Sprint(s.Port)))
	if err != nil {
		return describeNetErr(err, timeout, "")
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	req := make([]byte, 48)
	req[0] = 0<<6 | 4<<3 | 3 // LI 0, Version 4, Client
	t1 := time.Now()
	// Sendezeit mit zufälligen unteren Bits: Eine fremde Antwort passt nicht.
	var noise [2]byte
	rand.Read(noise[:])
	origin := toNTP(t1)&^0xffff | uint64(binary.BigEndian.Uint16(noise[:]))
	binary.BigEndian.PutUint64(req[40:], origin)
	if _, err := conn.Write(req); err != nil {
		return describeNetErr(err, timeout, "")
	}
	resp := make([]byte, 128)
	for {
		n, err := conn.Read(resp)
		t4 := time.Now()
		if err != nil {
			return describeNetErr(err, timeout, "NTP: ")
		}
		if n < 48 || binary.BigEndian.Uint64(resp[24:]) != origin || resp[0]&7 != 4 {
			continue // keine Antwort auf unsere Anfrage
		}
		li, stratum := resp[0]>>6, resp[1]
		if stratum == 0 {
			return Result{Crit, "Server lehnt ab (Kiss-o'-Death)", "", 0}
		}
		t2 := fromNTP(binary.BigEndian.Uint64(resp[32:]))
		t3 := fromNTP(binary.BigEndian.Uint64(resp[40:]))
		t1n := fromNTP(origin)
		offset := (t2.Sub(t1n) + t3.Sub(t4)) / 2
		rtt := t4.Sub(t1n) - t3.Sub(t2)
		return ntpResult(s, offset, rtt, li, stratum)
	}
}

func ntpResult(s Spec, offset, rtt time.Duration, li, stratum byte) Result {
	offMS := float64(offset.Microseconds()) / 1000
	sign := "+"
	if offMS < 0 {
		sign = "−"
	}
	metric := fmt.Sprintf("%s%s ms, Stratum %d", sign, germanNum(math.Round(math.Abs(offMS)*10)/10), stratum)
	if rtt < 0 {
		rtt = 0
	}
	switch {
	case stratum >= 16 || li == 3:
		return Result{Warn, "Server nicht synchron (Stratum 16)", metric, rtt}
	case math.Abs(offMS) >= s.OffsetCritMS:
		return Result{Crit, "Abweichung über " + germanNum(s.OffsetCritMS) + " ms (kritisch)", metric, rtt}
	case math.Abs(offMS) >= s.OffsetWarnMS:
		return Result{Warn, "Abweichung über " + germanNum(s.OffsetWarnMS) + " ms (Warnung)", metric, rtt}
	}
	return Result{OK, "Zeit stimmt", metric, rtt}
}
