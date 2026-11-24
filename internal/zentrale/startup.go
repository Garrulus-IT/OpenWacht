// SPDX-License-Identifier: AGPL-3.0-only

package zentrale

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckAppRole verweigert den Start, wenn die Datenbankverbindung der
// Zentrale Row-Level Security umgehen würde: als Superuser, mit BYPASSRLS oder
// als (Mitglied der) Eigentümer-Rolle der Tabellen. Das ist die wichtigste
// Betriebsregel der Mandantentrennung, deshalb prüft die Zentrale sie selbst.
func CheckAppRole(ctx context.Context, pool *pgxpool.Pool) error {
	var super, bypass, owner, member bool
	err := pool.QueryRow(ctx, `
		SELECT r.rolsuper, r.rolbypassrls,
		       EXISTS (SELECT 1 FROM pg_tables t
		                WHERE t.schemaname = 'openwacht' AND pg_has_role(current_user, t.tableowner, 'USAGE')),
		       pg_has_role(current_user, 'openwacht_app', 'MEMBER')
		  FROM pg_roles r WHERE r.rolname = current_user`).Scan(&super, &bypass, &owner, &member)
	if err != nil {
		return fmt.Errorf("Rollenprüfung: %w", err)
	}
	switch {
	case super:
		return errors.New("die Zentrale darf nicht als Superuser verbunden sein")
	case bypass:
		return errors.New("die Datenbankrolle der Zentrale hat BYPASSRLS")
	case owner:
		return errors.New("die Zentrale ist als Eigentümer der Tabellen verbunden und würde die Mandantentrennung umgehen; bitte eine Rolle in openwacht_app verwenden")
	case !member:
		return errors.New("die Datenbankrolle der Zentrale ist kein Mitglied von openwacht_app")
	}
	return nil
}
