// SPDX-License-Identifier: AGPL-3.0-only

package agent

// Docker-Sensor (Etappe 18b): Der Agent fragt nur einen lokalen,
// nur-lesenden Socket-Proxy (z. B. docker-socket-proxy mit CONTAINERS=1),
// den der Admin des Rechners einrichtet und freigibt
// (openwacht-agent sensoren -arten docker -docker http://127.0.0.1:2375).
// Den Docker-Socket selbst öffnet der Agent nie: Wer ihn öffnen kann, ist
// praktisch root. Gelesen werden nur Name, Zustand und Health aus der
// Containerliste, keine Umgebungsvariablen, Labels oder Logs.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
)

const maxDockerList = 1 << 20

type dockerContainer struct {
	Names  []string `json:"Names"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
}

func dockerContainerState(ctx context.Context, base, name string) checks.Result {
	if err := agentproto.CheckDockerURL(base); err != nil {
		return checks.Result{Status: checks.Unknown, Message: err.Error()}
	}
	filter, _ := json.Marshal(map[string][]string{"name": {"^/" + regexp.QuoteMeta(name) + "$"}})
	u := strings.TrimSuffix(base, "/") + "/containers/json?all=true&filters=" + url.QueryEscape(string(filter))
	client := &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return checks.Result{Status: checks.Unknown, Message: "Adresse des Proxys ungültig"}
	}
	resp, err := client.Do(req)
	if err != nil {
		return checks.Result{Status: checks.Unknown, Message: "Socket-Proxy nicht erreichbar: " + clipText(err.Error(), 120)}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return checks.Result{Status: checks.Unknown, Message: "Socket-Proxy verweigert die Containerliste (CONTAINERS=1 setzen)"}
	}
	if resp.StatusCode != http.StatusOK {
		return checks.Result{Status: checks.Unknown, Message: "Socket-Proxy antwortet mit HTTP " + resp.Status[:3]}
	}
	var list []dockerContainer
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDockerList)).Decode(&list); err != nil {
		return checks.Result{Status: checks.Unknown, Message: "Antwort des Proxys unlesbar"}
	}
	return dockerResult(list, name)
}

// dockerResult bewertet die Liste; nur der Container mit genau diesem Namen zählt.
func dockerResult(list []dockerContainer, name string) checks.Result {
	for _, c := range list {
		match := false
		for _, n := range c.Names {
			match = match || n == "/"+name
		}
		if !match {
			continue
		}
		status := strings.ToLower(c.Status)
		switch c.State {
		case "running":
			switch {
			case strings.Contains(status, "(unhealthy)"):
				return checks.Result{Status: checks.Crit, Message: "Container läuft, Health: unhealthy", Metric: "unhealthy"}
			case strings.Contains(status, "health: starting"):
				return checks.Result{Status: checks.Warn, Message: "Container startet (Health-Prüfung läuft)", Metric: "starting"}
			case strings.Contains(status, "(healthy)"):
				return checks.Result{Status: checks.OK, Message: "Container läuft", Metric: "healthy"}
			}
			return checks.Result{Status: checks.OK, Message: "Container läuft"}
		case "restarting":
			return checks.Result{Status: checks.Warn, Message: "Container startet neu"}
		case "paused":
			return checks.Result{Status: checks.Warn, Message: "Container angehalten"}
		case "created":
			return checks.Result{Status: checks.Crit, Message: "Container angelegt, aber nicht gestartet"}
		}
		return checks.Result{Status: checks.Crit, Message: "Container gestoppt", Metric: clipText(c.State, 20)}
	}
	return checks.Result{Status: checks.Crit, Message: "Container " + name + " fehlt"}
}
