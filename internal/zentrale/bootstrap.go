// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/garrulus-it/openwacht/internal/auth"
)

// ErrAlreadySetUp: Es gibt schon einen Hauptmandanten.
var ErrAlreadySetUp = errors.New("die Installation ist bereits eingerichtet (Hauptmandant vorhanden)")

// Bootstrap legt bei einer leeren Installation den Hauptmandanten und den
// ersten Admin an. Läuft mit der Eigentümer-Verbindung, weil es vorher noch
// niemanden gibt, der Rechte vergeben könnte. Der Admin muss beim ersten
// Anmelden die Zwei-Faktor-Anmeldung einrichten.
func Bootstrap(ctx context.Context, conn *pgx.Conn, tenantName, email, displayName, password string, p auth.Params) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if err := auth.ValidateNewPassword(password, email); err != nil {
		return err
	}
	hash, err := auth.HashPassword(password, p)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		// Sperre gegen zwei gleichzeitige Einrichtungen.
		if _, err := tx.Exec(ctx, `LOCK TABLE openwacht.tenants IN EXCLUSIVE MODE`); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openwacht.tenants WHERE parent_id IS NULL)`).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrAlreadySetUp
		}
		var tenantID, userID string
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.tenants (name) VALUES ($1) RETURNING id::text`,
			strings.TrimSpace(tenantName)).Scan(&tenantID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO openwacht.users (tenant_id, email, display_name, password_hash)
			VALUES ($1, $2, $3, $4) RETURNING id::text`, tenantID, email, strings.TrimSpace(displayName), hash).Scan(&userID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openwacht.role_assignments (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`,
			userID, tenantID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO openwacht.audit_log (tenant_id, action, details)
			VALUES ($1, 'installation.eingerichtet', jsonb_build_object('admin', $2::text))`, tenantID, email)
		return err
	})
}
