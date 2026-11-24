// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

// Sensoren auf dem Agent (Etappe 18): Der Agent holt die Liste seiner
// Sensoren (Art und Parameter als Daten) und schickt Ergebnisse. Leitprinzip 1
// bleibt gewahrt: Die Zentrale antwortet nur mit Daten; was der Agent misst,
// begrenzt seine lokale Freigabe (openwacht-agent sensoren …), nicht die
// Zentrale.
//
// Schutzschichten:
//   - Der Agent ergibt sich aus dem Client-Zertifikat (requireAgent). Die
//     Datenbank liefert nur Sensoren seines Geräts im selben Mandanten
//     (agent_sensor_jobs) und nimmt Ergebnisse nur dafür an
//     (agent_sensor_record, beide SECURITY DEFINER).
//   - Ergebnisse sind nicht vertrauenswürdig: Zustand aus einer festen
//     Liste, Texte bereinigt und begrenzt (SensorResult.Validate).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/alarm"
	"github.com/garrulus-it/openwacht/internal/checks"
)

func sensorState(list []agentproto.SensorJob) string {
	h := sha256.New()
	for _, j := range list {
		fmt.Fprintf(h, "%s|%d|%d\n", j.ID, j.Revision, j.IntervalSeconds)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func (s *Server) handleSensorJobs(w http.ResponseWriter, r *http.Request) {
	ident := r.Context().Value(agentKey).(agentIdentity)
	var in agentproto.SensorJobsRequest
	if !readAgentJSON(w, r, agentproto.MaxSensorListBytes, &in) {
		return
	}
	if !s.sensorListLimit.allow(ident.ID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Abrufe der Sensorliste.")
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT id::text, kind, target, revision, interval_s, due
		FROM openwacht.agent_sensor_jobs($1, $2)`, ident.ID, ident.Serial)
	if err != nil {
		internalError(w, "agent_sensor_jobs", err)
		return
	}
	type row struct {
		job agentproto.SensorJob
		due bool
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		var target []byte
		err := r.Scan(&x.job.ID, &x.job.Kind, &target, &x.job.Revision, &x.job.IntervalSeconds, &x.due)
		x.job.Target = target
		return x, err
	})
	if err != nil {
		internalError(w, "agent_sensor_jobs", err)
		return
	}
	out := agentproto.SensorJobsResponse{Sensors: []agentproto.SensorJob{}, Due: []string{}}
	for _, x := range list {
		// Auch gespeicherte Ziele erneut prüfen und bereinigt schicken.
		spec, err := checks.Parse(x.job.Kind, x.job.Target)
		if err != nil {
			slog.Warn("Sensoren: gespeichertes Ziel ungültig, nicht an den Agent geschickt", "sensor", x.job.ID, "fehler", err)
			continue
		}
		clean, err := json.Marshal(spec)
		if err != nil {
			continue
		}
		x.job.Target = clean
		out.Sensors = append(out.Sensors, x.job)
		if x.due {
			out.Due = append(out.Due, x.job.ID)
		}
	}
	out.State = sensorState(out.Sensors)
	if in.State != "" && in.State == out.State {
		out.Unchanged, out.Sensors = true, nil
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSensorResults(w http.ResponseWriter, r *http.Request) {
	ident := r.Context().Value(agentKey).(agentIdentity)
	var in agentproto.SensorResultsRequest
	if !readAgentJSON(w, r, agentproto.MaxSensorResultBytes, &in) {
		return
	}
	if len(in.Results) == 0 || len(in.Results) > agentproto.MaxSensorResults {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("1 bis %d Ergebnisse je Anfrage.", agentproto.MaxSensorResults))
		return
	}
	for i := range in.Results {
		if err := in.Results[i].Validate(); err != nil || !uuidPattern.MatchString(in.Results[i].ID) {
			writeError(w, http.StatusBadRequest, "Ergebnis abgelehnt.")
			return
		}
	}
	if !s.sensorResultLimit.allow(ident.ID, s.now()) {
		writeError(w, http.StatusTooManyRequests, "Zu viele Ergebnisse.")
		return
	}
	for _, res := range in.Results {
		var ok bool
		if err := s.pool.QueryRow(r.Context(), `SELECT openwacht.agent_sensor_record($1, $2, $3, $4, $5, $6, $7)`,
			ident.ID, ident.Serial, res.ID, res.Revision, res.Status, alarm.Clean(res.Message, 300),
			alarm.Clean(res.Metric, 50)).Scan(&ok); err != nil {
			internalError(w, "agent_sensor_record", err)
			return
		}
		// Nicht gespeichert (fremder Sensor, alte Revision): still verworfen;
		// der Agent holt beim nächsten Abgleich die neue Liste.
	}
	w.WriteHeader(http.StatusNoContent)
}
