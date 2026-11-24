// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
	"github.com/garrulus-it/openwacht/internal/pki"
)

// Wechsel der Agent-CA (Etappe 32, Befund M5). Ablauf:
//
//  1. agent-ca -neu: Eine neue CA entsteht neben der aktiven. Die Zentrale
//     verteilt beide an die Agents (Antwort auf die Meldung); die aktive
//     stellt weiter aus.
//  2. agent-ca -umstellen, sobald alle Agents die neue kennen: Die neue wird
//     aktiv (Server- und Client-Zertifikate), die bisherige „alt“. Client-
//     Zertifikate der alten gelten weiter; Agents erneuern ihr Zertifikat von
//     selbst, weil es nicht mehr von der ausstellenden CA stammt.
//  3. agent-ca -alte-entfernen, sobald kein Agent mehr ein Zertifikat der
//     alten hat.
//
// Nach jedem Schritt startet die Zentrale neu (sie lädt die CAs beim Start).

// AgentCAInfo: eine CA mit Zählern.
type AgentCAInfo struct {
	ID          int       `json:"-"`
	State       string    `json:"zustand"`
	Fingerprint string    `json:"fingerabdruck"`
	Subject     string    `json:"name"`
	NotAfter    time.Time `json:"gueltig_bis"`
	ChangedAt   time.Time `json:"geaendert"`
	Known       int       `json:"agents_kennen"`         // Agents, deren ca.pem sie enthält
	Issued      int       `json:"agents_mit_zertifikat"` // Agents mit Client-Zertifikat dieser CA
}

// AgentCAStatus: alle CAs und die Zahl der Agents, die zählen (nicht
// gesperrt, in den letzten 30 Tagen gemeldet).
type AgentCAStatus struct {
	CAs    []AgentCAInfo `json:"cas"`
	Agents int           `json:"agents"`
	Stale  int           `json:"agents_ohne_meldung"`
}

type rowQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// agentCAStatus liest den Stand; q ist der Eigentümer oder (Oberfläche) der
// Betreiber, der unter RLS alle Mandanten sieht.
func agentCAStatus(ctx context.Context, q rowQuerier) (AgentCAStatus, error) {
	var st AgentCAStatus
	rows, err := q.Query(ctx, `SELECT id, state, cert_pem, changed_at FROM openwacht.agent_ca_list()`)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var i AgentCAInfo
		var id int16
		var pemText string
		if err := rows.Scan(&id, &i.State, &pemText, &i.ChangedAt); err != nil {
			rows.Close()
			return st, err
		}
		c, err := pki.ParseCertPEM([]byte(pemText))
		if err != nil {
			rows.Close()
			return st, err
		}
		i.ID, i.Fingerprint, i.Subject, i.NotAfter = int(id), pki.Fingerprint(c), c.Subject.CommonName, c.NotAfter
		st.CAs = append(st.CAs, i)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return st, err
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE last_seen > now() - interval '30 days'),
		count(*) FILTER (WHERE last_seen IS NULL OR last_seen <= now() - interval '30 days')
		FROM openwacht.agents WHERE revoked_at IS NULL`).Scan(&st.Agents, &st.Stale); err != nil {
		return st, err
	}
	for i := range st.CAs {
		if err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE coalesce(snapshot->'cas', '[]') ? $1),
			count(*) FILTER (WHERE snapshot->>'zert_ca' = $1)
			FROM openwacht.agents WHERE revoked_at IS NULL AND last_seen > now() - interval '30 days'`,
			st.CAs[i].Fingerprint).Scan(&st.CAs[i].Known, &st.CAs[i].Issued); err != nil {
			return st, err
		}
	}
	return st, nil
}

// AgentCAStatusOwner: Stand für die Shell (Eigentümer der Datenbank).
func AgentCAStatusOwner(ctx context.Context, q rowQuerier) (AgentCAStatus, error) {
	return agentCAStatus(ctx, q)
}

func (st AgentCAStatus) find(state string) *AgentCAInfo {
	for i := range st.CAs {
		if st.CAs[i].State == state {
			return &st.CAs[i]
		}
	}
	return nil
}

func agentCAAudit(ctx context.Context, tx pgx.Tx, action string, details map[string]any) error {
	_, err := tx.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action, details)
		SELECT t.id, $1, $2 FROM openwacht.tenants t WHERE t.parent_id IS NULL`, action, details)
	return err
}

// AgentCANew legt eine neue CA neben der aktiven an (Eigentümer). master muss
// der Hauptschlüssel sein, mit dem die aktive verschlüsselt ist.
func AgentCANew(ctx context.Context, tx pgx.Tx, master []byte, now time.Time) (AgentCAInfo, error) {
	caKey := deriveKey(master, "openwacht agent-ca v1")
	var keyEnc []byte
	if err := tx.QueryRow(ctx, `SELECT key_enc FROM openwacht.agent_ca WHERE state = 'aktiv' FOR UPDATE`).Scan(&keyEnc); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AgentCAInfo{}, errors.New("es gibt noch keine Agent-CA (Zentrale einmal starten)")
		}
		return AgentCAInfo{}, err
	}
	if _, err := auth.Open(caKey, keyEnc, []byte("agent-ca")); err != nil {
		return AgentCAInfo{}, errors.New("der Hauptschlüssel passt nicht zur Agent-CA")
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM openwacht.agent_ca WHERE state = 'neu'`).Scan(&n); err != nil {
		return AgentCAInfo{}, err
	}
	if n > 0 {
		return AgentCAInfo{}, errors.New("es gibt schon eine neue Agent-CA; erst umstellen")
	}
	ca, err := pki.NewCA(fmt.Sprintf("OpenWacht Agent-CA %s", now.UTC().Format("2006-01")), now)
	if err != nil {
		return AgentCAInfo{}, err
	}
	der, err := ca.KeyDER()
	if err != nil {
		return AgentCAInfo{}, err
	}
	enc, err := auth.Seal(caKey, der, []byte("agent-ca"))
	if err != nil {
		return AgentCAInfo{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO openwacht.agent_ca (id, cert_pem, key_enc, state)
		SELECT coalesce(max(id), 0) + 1, $1, $2, 'neu' FROM openwacht.agent_ca`, string(ca.CertPEM()), enc); err != nil {
		return AgentCAInfo{}, err
	}
	info := AgentCAInfo{State: "neu", Fingerprint: pki.Fingerprint(ca.Cert), Subject: ca.Cert.Subject.CommonName, NotAfter: ca.Cert.NotAfter}
	return info, agentCAAudit(ctx, tx, "agent_ca.neu", map[string]any{"fingerabdruck": info.Fingerprint, "gueltig_bis": info.NotAfter})
}

// AgentCASwitch macht die neue CA zur aktiven (Eigentümer). Ohne force nur,
// wenn alle Agents, die sich in den letzten 30 Tagen gemeldet haben, sie kennen.
func AgentCASwitch(ctx context.Context, tx pgx.Tx, force bool) error {
	if _, err := tx.Exec(ctx, `LOCK TABLE openwacht.agent_ca IN EXCLUSIVE MODE`); err != nil {
		return err
	}
	st, err := agentCAStatus(ctx, tx)
	if err != nil {
		return err
	}
	neu, alt, akt := st.find("neu"), st.find("alt"), st.find("aktiv")
	switch {
	case neu == nil:
		return errors.New("es gibt keine neue Agent-CA (erst agent-ca -neu)")
	case alt != nil:
		return errors.New("es gibt noch eine alte Agent-CA; erst agent-ca -alte-entfernen")
	case !force && neu.Known < st.Agents:
		return fmt.Errorf("erst %d von %d Agents kennen die neue CA; warten (Meldeintervall) oder -trotzdem", neu.Known, st.Agents)
	}
	for _, q := range []string{`UPDATE openwacht.agent_ca SET state = 'alt', changed_at = now() WHERE state = 'aktiv'`,
		`UPDATE openwacht.agent_ca SET state = 'aktiv', changed_at = now() WHERE state = 'neu'`} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	return agentCAAudit(ctx, tx, "agent_ca.umgestellt", map[string]any{"aktiv": neu.Fingerprint, "alt": akt.Fingerprint,
		"agents": st.Agents, "kennen_neue": neu.Known, "trotzdem": force})
}

// AgentCARemoveOld entfernt die alte CA (Eigentümer). Ohne force nur, wenn
// kein Agent mehr ein Zertifikat von ihr hat.
func AgentCARemoveOld(ctx context.Context, tx pgx.Tx, force bool) error {
	if _, err := tx.Exec(ctx, `LOCK TABLE openwacht.agent_ca IN EXCLUSIVE MODE`); err != nil {
		return err
	}
	st, err := agentCAStatus(ctx, tx)
	if err != nil {
		return err
	}
	alt := st.find("alt")
	if alt == nil {
		return errors.New("es gibt keine alte Agent-CA")
	}
	if !force && alt.Issued > 0 {
		return fmt.Errorf("%d Agent(s) haben noch ein Zertifikat der alten CA; warten (sie erneuern von selbst) oder -trotzdem", alt.Issued)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM openwacht.agent_ca WHERE state = 'alt'`); err != nil {
		return err
	}
	return agentCAAudit(ctx, tx, "agent_ca.alte_entfernt", map[string]any{"fingerabdruck": alt.Fingerprint,
		"agents_mit_zertifikat": alt.Issued, "trotzdem": force})
}

// handleAgentCAGet: Seite Einstellungen, nur Betreiber.
func (s *Server) handleAgentCAGet(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r, "einstellungen agent-ca", func(ctx context.Context, tx pgx.Tx) (int, any, error) {
		if err := requireOperator(ctx, tx); err != nil {
			return 0, nil, err
		}
		st, err := agentCAStatus(ctx, tx)
		if err != nil {
			return 0, nil, err
		}
		// Was die laufende Zentrale geladen hat (ändert sich erst nach einem Neustart).
		st2 := struct {
			AgentCAStatus
			Geladen []string `json:"geladen"`
		}{st, s.agent.fps}
		return http.StatusOK, st2, nil
	})
}
