// SPDX-License-Identifier: AGPL-3.0-only

// Führung (1.0.12): Die Oberfläche bringt den Blick dorthin, wo nach einer
// Aktion etwas passiert, statt dass man es suchen muss.
//
// - Öffnet eine Aktion einen Bereich (Klasse „einschub“, z. B. „Anwenden“
//   einer Vorlage, „Host hinzufügen“, „Bearbeiten“) außerhalb des sichtbaren
//   Teils, rollt die Seite dorthin. Mit Maus und Tastatur bekommt das erste
//   Eingabefeld den Fokus.
// - Schließt sich der Bereich wieder (Anlegen, Abbrechen, Esc), geht der Blick
//   zurück zum Knopf, der ihn geöffnet hat.
// - Esc schließt den Bereich, in dem der Fokus steht (über seinen Knopf
//   „Abbrechen“ oder „Schließen“).
//
// Das gilt nur unmittelbar nach einer Aktion des Benutzers; Bereiche, die beim
// Laden oder durch eine Aktualisierung erscheinen, bewegen nichts.

const frist = 2000; // ms nach Klick oder Taste, in denen ein neuer Bereich als Folge gilt

let letzteAktion = 0;
let ausloeser: HTMLElement | null = null;
const herkunft = new WeakMap<Element, HTMLElement>();
let aktiv = false;

function sanft(): ScrollBehavior {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth";
}

// kopfHoehe: Unterkante der klebenden Kopfleiste (verdeckt den oberen Rand).
function kopfHoehe() {
  const k = document.querySelector(".kopf");
  return k ? Math.max(0, k.getBoundingClientRect().bottom) : 0;
}

function zeigen(el: Element) {
  const r = el.getBoundingClientRect();
  const oben = kopfHoehe();
  const unten = window.innerHeight;
  if (r.top >= oben && r.bottom <= unten) return; // ganz sichtbar
  if (r.top >= oben && r.top < unten && r.height <= unten - oben) {
    el.scrollIntoView({ block: "nearest", behavior: sanft() }); // nur unten abgeschnitten
    return;
  }
  el.scrollIntoView({ block: "start", behavior: sanft() });
}

const felder =
  'input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]):not([disabled]):not([readonly]), select:not([disabled]), textarea:not([disabled]):not([readonly])';

function fokussieren(el: Element) {
  if (!window.matchMedia("(pointer: fine)").matches) return; // am Handy keine Tastatur aufklappen
  if (el.contains(document.activeElement)) return;
  const f = el.querySelector<HTMLElement>(felder);
  f?.focus({ preventScroll: true });
}

function einschubIn(n: Node): Element | null {
  if (!(n instanceof Element)) return null;
  if (n.classList.contains("einschub")) return n;
  return n.querySelector(".einschub");
}

function frisch() {
  return Date.now() - letzteAktion < frist;
}

function geoeffnet(el: Element) {
  if (ausloeser && ausloeser.isConnected && !el.contains(ausloeser)) herkunft.set(el, ausloeser);
  zeigen(el);
  fokussieren(el);
}

function geschlossen(el: Element) {
  const zurueck = herkunft.get(el);
  if (!zurueck || !zurueck.isConnected) return;
  const verloren = !document.activeElement || document.activeElement === document.body || !document.activeElement.isConnected;
  if (!verloren) return;
  zurueck.focus({ preventScroll: true });
  const r = zurueck.getBoundingClientRect();
  if (r.top < kopfHoehe() || r.bottom > window.innerHeight) zurueck.scrollIntoView({ block: "center", behavior: sanft() });
}

function merken(t: EventTarget | null) {
  letzteAktion = Date.now();
  const el = t instanceof Element ? t.closest<HTMLElement>("button, a, summary, [role='button']") : null;
  if (el) ausloeser = el;
}

// schliessen: Esc im Bereich drückt dessen „Abbrechen“ bzw. „Schließen“.
function schliessen(e: KeyboardEvent) {
  if (e.key !== "Escape" || e.defaultPrevented || document.querySelector("dialog[open]")) return;
  const a = document.activeElement;
  const ein = a instanceof Element ? a.closest(".einschub") : null;
  if (!ein) return;
  const knopf = [...ein.querySelectorAll<HTMLButtonElement>("button")].find(
    (b) => b.closest(".einschub") === ein && !b.disabled && /^(Abbrechen|Schließen)$/.test(b.textContent?.trim() ?? ""),
  );
  if (!knopf) return;
  e.preventDefault();
  letzteAktion = Date.now();
  knopf.click();
}

export function fuehrungEinschalten() {
  if (aktiv || typeof MutationObserver === "undefined") return;
  aktiv = true;
  document.addEventListener("pointerdown", (e) => merken(e.target), true);
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key === "Enter" || e.key === " ") merken(e.target);
    },
    true,
  );
  document.addEventListener("keydown", schliessen);
  new MutationObserver((liste) => {
    if (!frisch()) return;
    let erledigt = false;
    for (const m of liste) {
      for (const n of m.removedNodes) {
        const el = einschubIn(n);
        if (el) {
          geschlossen(el);
          erledigt = true;
        }
      }
    }
    outer: for (const m of liste) {
      for (const n of m.addedNodes) {
        const el = einschubIn(n);
        if (el && el.isConnected) {
          // nach dem Zeichnen, damit Größe und Lage stimmen
          requestAnimationFrame(() => geoeffnet(el));
          erledigt = true;
          break outer;
        }
      }
    }
    // Eine Aktion führt höchstens einmal: Was danach von selbst erscheint
    // (Aktualisierung), bewegt nichts mehr.
    if (erledigt) letzteAktion = 0;
  }).observe(document.body, { childList: true, subtree: true });
}
