// SPDX-License-Identifier: AGPL-3.0-only

package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// --- Ping-Bewertung (Etappe 18: Verlust, Jitter, Antwortzeit) -----------------

func germanMS(d time.Duration) string {
	if d < 100*time.Microsecond {
		return "unter 0,1 ms"
	}
	return strings.Replace(fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000), ".", ",", 1)
}

func germanNum(v float64) string {
	return strings.Replace(strconv.FormatFloat(v, 'f', -1, 64), ".", ",", 1)
}

// pingResult bewertet die Antwortzeiten von count Anfragen (rtts: nur die
// beantworteten). Die Meldung bleibt stabil (Verlust in ganzen Prozent nur bei
// Überschreitung), Antwortzeit und Jitter stehen im Messwert.
func pingResult(s Spec, count int, rtts []time.Duration) Result {
	got := len(rtts)
	if got == 0 {
		return Result{Crit, "keine Antwort auf Ping", "", 0}
	}
	var total time.Duration
	for _, d := range rtts {
		total += d
	}
	avg := total / time.Duration(got)
	metric := germanMS(avg)
	if got >= 2 {
		var jit time.Duration
		for i := 1; i < got; i++ {
			d := rtts[i] - rtts[i-1]
			if d < 0 {
				d = -d
			}
			jit += d
		}
		metric = "Ø " + metric + ", Jitter " + germanMS(jit/time.Duration(got-1))
	}
	loss := float64(count-got) * 100 / float64(count)
	avgMS := float64(avg.Microseconds()) / 1000
	status, msg := OK, "erreichbar"
	if loss > 0 {
		msg = fmt.Sprintf("erreichbar, %.0f %% Verlust", loss)
	}
	switch {
	case s.LossCrit > 0 && loss >= s.LossCrit:
		status, msg = Crit, fmt.Sprintf("%.0f %% Verlust (kritisch ab %s %%)", loss, germanNum(s.LossCrit))
	case s.RTTCrit > 0 && avgMS >= s.RTTCrit:
		status, msg = Crit, fmt.Sprintf("Antwortzeit über %s ms (kritisch)", germanNum(s.RTTCrit))
	case s.LossWarn > 0 && loss >= s.LossWarn:
		status, msg = Warn, fmt.Sprintf("%.0f %% Verlust (Warnung ab %s %%)", loss, germanNum(s.LossWarn))
	case s.RTTWarn > 0 && avgMS >= s.RTTWarn:
		status, msg = Warn, fmt.Sprintf("Antwortzeit über %s ms (Warnung)", germanNum(s.RTTWarn))
	}
	return Result{status, msg, metric, avg}
}

// --- DNS -----------------------------------------------------------------------

const maxShownAddrs = 4

// dns löst einen Namen auf, über den Resolver der Zentrale oder einen
// angegebenen Server. Der Server muss freigegeben sein (Guard vor connect()).
// In der Meldung stehen nur Adressen, die in den freigegebenen Netzen liegen:
// Ein Mandant soll über diesen Weg nichts über fremde Netze erfahren.
func (r *Runner) dns(ctx context.Context, s Spec, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	network := map[string]string{"A": "ip4", "AAAA": "ip6"}[s.Record]
	if network == "" {
		network = "ip"
	}
	res := net.DefaultResolver
	if s.Server != "" {
		srv, err := netip.ParseAddr(s.Server)
		if err != nil {
			return Result{Unknown, "DNS-Server ungültig", "", 0}
		}
		if !r.Guard.Allowed(srv) {
			return describeNetErr(&NotAllowedError{srv.Unmap()}, timeout, "")
		}
		port := r.DNSPort
		if port == "" {
			port = "53"
		}
		res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Control: r.Guard.control}
			return d.DialContext(ctx, network, net.JoinHostPort(srv.String(), port))
		}}
	}
	start := time.Now()
	addrs, err := res.LookupNetIP(ctx, network, s.Name)
	took := time.Since(start)
	if err != nil {
		var dnsErr *net.DNSError
		var na *NotAllowedError
		switch {
		case errors.As(err, &na):
			return describeNetErr(na, timeout, "")
		case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
			return Result{Crit, "Name " + clean(s.Name, 100) + " nicht gefunden", "", 0}
		case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &dnsErr) && dnsErr.IsTimeout:
			return Result{Crit, "DNS: Zeitüberschreitung nach " + secs(timeout) + " s", "", 0}
		}
		return Result{Crit, "DNS-Fehler: " + clean(err.Error(), 150), "", 0}
	}
	var got []netip.Addr
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if !slices.Contains(got, a) {
			got = append(got, a)
		}
	}
	slices.SortFunc(got, func(a, b netip.Addr) int { return a.Compare(b) })
	if len(got) == 0 {
		return Result{Crit, "Name " + clean(s.Name, 100) + " hat keine Adresse", "", 0}
	}
	var shown []string
	hidden := 0
	for _, a := range got {
		if r.Guard.Allowed(a) && len(shown) < maxShownAddrs {
			shown = append(shown, a.String())
		} else {
			hidden++
		}
	}
	text := strings.Join(shown, ", ")
	if hidden > 0 {
		if text != "" {
			text += " und "
		}
		text += fmt.Sprintf("%d weitere", hidden)
	}
	for _, e := range s.Expect {
		want, err := netip.ParseAddr(e)
		if err != nil || !slices.Contains(got, want.Unmap()) {
			return Result{Crit, "Antwort ohne erwartete Adresse " + clean(e, 50) + " (erhalten: " + text + ")", ms(took), took}
		}
	}
	if len(s.Expect) > 0 {
		return Result{OK, "erwartete Adresse erhalten", ms(took), took}
	}
	return Result{OK, "löst auf: " + text, ms(took), took}
}

// --- HTTP-JSON-Wert ------------------------------------------------------------

// jsonValue sucht den Wert am Pfad (Schlüssel mit Punkt getrennt, Zahlen als
// Index in Listen).
func jsonValue(body []byte, p string) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("Antwort ist kein JSON")
	}
	for _, seg := range strings.Split(p, ".") {
		switch x := v.(type) {
		case map[string]any:
			next, ok := x[seg]
			if !ok {
				return nil, errors.New("Pfad " + p + " nicht gefunden")
			}
			v = next
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(x) {
				return nil, errors.New("Pfad " + p + " nicht gefunden")
			}
			v = x[i]
		default:
			return nil, errors.New("Pfad " + p + " nicht gefunden")
		}
	}
	return v, nil
}

// httpJSON liest einen Wert aus einer JSON-Antwort. Gemeldet wird nur eine
// Zahl als Messwert; Texte werden nur verglichen, nie angezeigt
// (Leitprinzip 5: keine Inhalte).
func (r *Runner) httpJSON(ctx context.Context, s Spec, timeout time.Duration) Result {
	code, body, took, fail := r.fetch(ctx, s, timeout, true)
	if fail != nil {
		return *fail
	}
	elapsed := ms(took)
	if !statusOK(s, code) {
		return Result{Crit, fmt.Sprintf("HTTP %d (unerwartet)", code), elapsed, took}
	}
	v, err := jsonValue(body, s.JSONPath)
	if err != nil {
		return Result{Crit, clean(err.Error(), 150), elapsed, took}
	}
	var num *float64
	if n, ok := v.(json.Number); ok {
		if f, err := n.Float64(); err == nil {
			num = &f
		}
	}
	metric := elapsed
	if num != nil {
		metric = clean(germanNum(*num), 40)
	}
	if s.Equals != nil {
		var text string
		switch x := v.(type) {
		case string:
			text = x
		case json.Number:
			text = x.String()
		case bool:
			text = strconv.FormatBool(x)
		case nil:
			text = "null"
		default:
			return Result{Crit, "Wert ist ein Objekt oder eine Liste", elapsed, took}
		}
		if text != *s.Equals {
			return Result{Crit, "Wert weicht vom erwarteten ab", metric, took}
		}
		return Result{OK, "Wert wie erwartet", metric, took}
	}
	numeric := s.WarnAbove != nil || s.CritAbove != nil || s.WarnBelow != nil || s.CritBelow != nil
	if !numeric {
		return Result{OK, "Wert vorhanden", metric, took}
	}
	if num == nil {
		return Result{Unknown, "Wert ist keine Zahl", elapsed, took}
	}
	x := *num
	switch {
	case s.CritAbove != nil && x > *s.CritAbove:
		return Result{Crit, "Wert über " + germanNum(*s.CritAbove) + " (kritisch)", metric, took}
	case s.CritBelow != nil && x < *s.CritBelow:
		return Result{Crit, "Wert unter " + germanNum(*s.CritBelow) + " (kritisch)", metric, took}
	case s.WarnAbove != nil && x > *s.WarnAbove:
		return Result{Warn, "Wert über " + germanNum(*s.WarnAbove) + " (Warnung)", metric, took}
	case s.WarnBelow != nil && x < *s.WarnBelow:
		return Result{Warn, "Wert unter " + germanNum(*s.WarnBelow) + " (Warnung)", metric, took}
	}
	return Result{OK, "Wert im Rahmen", metric, took}
}
