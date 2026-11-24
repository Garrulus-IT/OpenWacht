// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/checks"
)

func TestDocker(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.String())
		if r.Method != http.MethodGet || r.URL.Path != "/containers/json" {
			w.WriteHeader(403)
			return
		}
		var f map[string][]string
		json.Unmarshal([]byte(r.URL.Query().Get("filters")), &f)
		all := []map[string]any{
			{"Names": []string{"/web"}, "State": "running", "Status": "Up 2 hours (healthy)", "Labels": map[string]string{"geheim": "x"}},
			{"Names": []string{"/webapp"}, "State": "exited", "Status": "Exited (1)"},
			{"Names": []string{"/db"}, "State": "running", "Status": "Up 1 minute (unhealthy)"},
			{"Names": []string{"/neu"}, "State": "running", "Status": "Up 3 seconds (health: starting)"},
			{"Names": []string{"/batch"}, "State": "exited", "Status": "Exited (0)"},
		}
		// Der Proxy filtert per Regex; die Antwort darf trotzdem mehr enthalten.
		json.NewEncoder(w).Encode(all)
	}))
	defer srv.Close()
	rel := &agentproto.SensorRelease{Kinds: []string{"docker"}, Docker: srv.URL}
	if err := rel.Validate(); err != nil {
		t.Fatal(err)
	}
	env := testEnv(time.Now())
	env.docker = dockerContainerState
	for _, tc := range []struct{ name, status, msg string }{
		{"web", checks.OK, "läuft"},
		{"db", checks.Crit, "unhealthy"},
		{"neu", checks.Warn, "startet"},
		{"batch", checks.Crit, "gestoppt"},
		{"fehlt", checks.Crit, "fehlt"},
		{"webap", checks.Crit, "fehlt"}, // nur exakte Namen, kein Präfix
	} {
		res := env.measure(context.Background(), rel, job("docker", `{"name":"`+tc.name+`"}`))
		if res.Status != tc.status || !strings.Contains(res.Message, tc.msg) || strings.Contains(res.Message+res.Metric, "geheim") {
			t.Errorf("%s: %+v", tc.name, res)
		}
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/containers/json?all=true&filters=") {
			t.Errorf("unerwartete Anfrage %s", p)
		}
	}
	// Freigabe: nur Loopback, nur http, nur mit Art docker
	for _, bad := range []agentproto.SensorRelease{
		{Kinds: []string{"docker"}},
		{Kinds: []string{"dienst"}, Docker: "http://127.0.0.1:2375"},
		{Kinds: []string{"docker"}, Docker: "http://172.16.0.5:2375"},
		{Kinds: []string{"docker"}, Docker: "https://127.0.0.1:2375"},
		{Kinds: []string{"docker"}, Docker: "unix:///var/run/docker.sock"},
		{Kinds: []string{"docker"}, Docker: "http://127.0.0.1"},
		{Kinds: []string{"docker"}, Docker: "http://127.0.0.1:2375/v1.40"},
		{Kinds: []string{"docker"}, Docker: "http://user:pw@127.0.0.1:2375"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("angenommen: %+v", bad)
		}
	}
	// ohne Freigabe der Art: nicht gemessen
	n := len(paths)
	if res := env.measure(context.Background(), &agentproto.SensorRelease{Kinds: []string{"dienst"}}, job("docker", `{"name":"web"}`)); res.Status != checks.Unknown || len(paths) != n {
		t.Errorf("nicht freigegeben: %+v", res)
	}
}
