// SPDX-License-Identifier: AGPL-3.0-only

// Wortmarke: Bildzeichen „Wachendes Auge“ und der Name (Open fett, Wacht normal).
import { Zeichen } from "./Zeichen";

export function Wortmarke({ klein = false }: { klein?: boolean }) {
  return (
    <div className={klein ? "wortmarke wortmarke-klein" : "wortmarke"}>
      <Zeichen klein={klein} className="zeichen" />
      <span>
        Open<span className="wortmarke-rest">Wacht</span>
      </span>
    </div>
  );
}
