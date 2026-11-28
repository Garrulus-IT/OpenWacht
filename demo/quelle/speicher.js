// SPDX-License-Identifier: AGPL-3.0-only

// Ein kleines Dateisystem im Arbeitsspeicher für den Server als WebAssembly.
// Go (syscall/fs_js.go) ruft dafür globalThis.fs mit der Schnittstelle von
// Node auf. Der Server legt hier nur seine Anhänge ab (Bilder, Dateien) und
// Zwischendateien beim Hochladen und Übertragen.
//
// Geänderte Dateien meldet aenderung(pfad, daten | null) zum Speichern im
// Browser (IndexedDB); laden() bringt sie nach einem Neustart zurück.

const S_IFDIR = 0o040000;
const S_IFREG = 0o100000;

const O = { O_WRONLY: 1, O_RDWR: 2, O_CREAT: 64, O_EXCL: 128, O_TRUNC: 512, O_APPEND: 1024, O_DIRECTORY: 65536 };

function fehler(code) {
  const e = new Error(code);
  e.code = code;
  return e;
}

let inodeZaehler = 1;

function knoten(typ, modus) {
  const jetzt = Date.now();
  return { typ, modus, daten: new Uint8Array(0), groesse: 0, ino: inodeZaehler++, mtime: jetzt, ctime: jetzt, links: 1 };
}

function normal(p) {
  const teile = [];
  for (const t of String(p).split("/")) {
    if (!t || t === ".") continue;
    if (t === "..") teile.pop();
    else teile.push(t);
  }
  return "/" + teile.join("/");
}

function eltern(p) {
  const i = p.lastIndexOf("/");
  return i <= 0 ? "/" : p.slice(0, i);
}

export function erzeugeSpeicher({ aenderung = () => {}, ausgabe = (fd, text) => (fd === 2 ? console.warn : console.log)(text) } = {}) {
  const baum = new Map([["/", knoten("dir", 0o755)]]);
  const fds = new Map();
  let naechsterFd = 10;
  const zeilen = { 1: "", 2: "" };
  const dec = new TextDecoder();

  const melde = (pfad, k) => {
    // Zwischendateien beim Hochladen nicht speichern, nur fertige Anhänge.
    if (/\/hoch-[^/]*$/.test(pfad)) return;
    aenderung(pfad, k ? k.daten.subarray(0, k.groesse) : null);
  };

  function stat(k) {
    return {
      dev: 1,
      ino: k.ino,
      mode: (k.typ === "dir" ? S_IFDIR : S_IFREG) | k.modus,
      nlink: k.links,
      uid: 0,
      gid: 0,
      rdev: 0,
      size: k.typ === "dir" ? 4096 : k.groesse,
      blksize: 4096,
      blocks: Math.ceil(k.groesse / 512),
      atimeMs: k.mtime,
      mtimeMs: k.mtime,
      ctimeMs: k.ctime,
      isDirectory: () => k.typ === "dir",
    };
  }

  function finde(p) {
    const k = baum.get(normal(p));
    if (!k) throw fehler("ENOENT");
    return k;
  }

  function platz(k, n) {
    if (n <= k.daten.length) return;
    const neu = new Uint8Array(Math.max(n, k.daten.length * 2, 4096));
    neu.set(k.daten.subarray(0, k.groesse));
    k.daten = neu;
  }

  const fs = {
    constants: O,

    writeSync(fd, buf) {
      return schreibeAusgabe(fd, buf);
    },

    open(pfad, flags, modus, cb) {
      try {
        const p = normal(pfad);
        let k = baum.get(p);
        if (k && flags & O.O_CREAT && flags & O.O_EXCL) throw fehler("EEXIST");
        if (!k) {
          if (!(flags & O.O_CREAT)) throw fehler("ENOENT");
          const e = baum.get(eltern(p));
          if (!e) throw fehler("ENOENT");
          if (e.typ !== "dir") throw fehler("ENOTDIR");
          k = knoten("file", modus & 0o777);
          baum.set(p, k);
        }
        if (k.typ === "dir" && flags & (O.O_WRONLY | O.O_RDWR)) throw fehler("EISDIR");
        if (flags & O.O_TRUNC && k.typ === "file") {
          k.groesse = 0;
          k.mtime = Date.now();
        }
        const fd = naechsterFd++;
        fds.set(fd, { pfad: p, k, pos: 0, flags, geaendert: !!(flags & O.O_TRUNC) });
        cb(null, fd);
      } catch (e) {
        cb(e);
      }
    },

    close(fd, cb) {
      const f = fds.get(fd);
      if (!f) return cb(fehler("EBADF"));
      fds.delete(fd);
      if (f.geaendert && baum.get(f.pfad) === f.k) melde(f.pfad, f.k);
      cb(null);
    },

    read(fd, buffer, offset, length, position, cb) {
      const f = fds.get(fd);
      if (!f) return cb(fehler("EBADF"));
      if (f.k.typ === "dir") return cb(fehler("EISDIR"));
      const von = position ?? f.pos;
      const n = Math.max(0, Math.min(length, f.k.groesse - von));
      buffer.set(f.k.daten.subarray(von, von + n), offset);
      if (position === null || position === undefined) f.pos += n;
      cb(null, n);
    },

    write(fd, buffer, offset, length, position, cb) {
      if (fd === 1 || fd === 2) return cb(null, schreibeAusgabe(fd, buffer.subarray(offset, offset + length)));
      const f = fds.get(fd);
      if (!f) return cb(fehler("EBADF"));
      const k = f.k;
      let von = position ?? f.pos;
      if (f.flags & O.O_APPEND) von = k.groesse;
      platz(k, von + length);
      k.daten.set(buffer.subarray(offset, offset + length), von);
      k.groesse = Math.max(k.groesse, von + length);
      k.mtime = Date.now();
      if (position === null || position === undefined) f.pos = von + length;
      f.geaendert = true;
      cb(null, length);
    },

    fstat(fd, cb) {
      const f = fds.get(fd);
      if (!f) return cb(fehler("EBADF"));
      cb(null, stat(f.k));
    },
    stat(p, cb) {
      try {
        cb(null, stat(finde(p)));
      } catch (e) {
        cb(e);
      }
    },
    lstat(p, cb) {
      fs.stat(p, cb);
    },
    fsync(fd, cb) {
      cb(fds.has(fd) ? null : fehler("EBADF"));
    },
    ftruncate(fd, n, cb) {
      const f = fds.get(fd);
      if (!f) return cb(fehler("EBADF"));
      platz(f.k, n);
      if (n > f.k.groesse) f.k.daten.fill(0, f.k.groesse, n);
      f.k.groesse = n;
      f.geaendert = true;
      cb(null);
    },
    truncate(p, n, cb) {
      try {
        const k = finde(p);
        platz(k, n);
        k.groesse = n;
        melde(normal(p), k);
        cb(null);
      } catch (e) {
        cb(e);
      }
    },

    mkdir(pfad, modus, cb) {
      const p = normal(pfad);
      if (baum.has(p)) return cb(fehler("EEXIST"));
      const e = baum.get(eltern(p));
      if (!e) return cb(fehler("ENOENT"));
      baum.set(p, knoten("dir", modus & 0o777));
      cb(null);
    },
    readdir(pfad, cb) {
      const p = normal(pfad);
      const k = baum.get(p);
      if (!k) return cb(fehler("ENOENT"));
      if (k.typ !== "dir") return cb(fehler("ENOTDIR"));
      const pre = p === "/" ? "/" : p + "/";
      const namen = [];
      for (const q of baum.keys()) if (q !== p && q.startsWith(pre) && !q.slice(pre.length).includes("/")) namen.push(q.slice(pre.length));
      cb(null, namen.sort());
    },
    rmdir(pfad, cb) {
      const p = normal(pfad);
      const k = baum.get(p);
      if (!k) return cb(fehler("ENOENT"));
      if (k.typ !== "dir") return cb(fehler("ENOTDIR"));
      for (const q of baum.keys()) if (q.startsWith(p + "/")) return cb(fehler("ENOTEMPTY"));
      baum.delete(p);
      cb(null);
    },
    unlink(pfad, cb) {
      const p = normal(pfad);
      const k = baum.get(p);
      if (!k) return cb(fehler("ENOENT"));
      if (k.typ === "dir") return cb(fehler("EISDIR"));
      baum.delete(p);
      k.links--;
      melde(p, null);
      cb(null);
    },
    link(alt, neu, cb) {
      const a = normal(alt);
      const n = normal(neu);
      const k = baum.get(a);
      if (!k) return cb(fehler("ENOENT"));
      if (baum.has(n)) return cb(fehler("EEXIST"));
      if (!baum.get(eltern(n))) return cb(fehler("ENOENT"));
      baum.set(n, k);
      k.links++;
      melde(n, k);
      cb(null);
    },
    rename(alt, neu, cb) {
      const a = normal(alt);
      const n = normal(neu);
      const k = baum.get(a);
      if (!k) return cb(fehler("ENOENT"));
      baum.delete(a);
      baum.set(n, k);
      melde(a, null);
      if (k.typ === "file") melde(n, k);
      cb(null);
    },
    chmod(p, modus, cb) {
      try {
        finde(p).modus = modus & 0o777;
        cb(null);
      } catch (e) {
        cb(e);
      }
    },
    fchmod(fd, modus, cb) {
      const f = fds.get(fd);
      if (!f) return cb(fehler("EBADF"));
      f.k.modus = modus & 0o777;
      cb(null);
    },
    chown(p, u, g, cb) {
      cb(null);
    },
    fchown(fd, u, g, cb) {
      cb(null);
    },
    lchown(p, u, g, cb) {
      cb(null);
    },
    utimes(p, a, m, cb) {
      try {
        finde(p).mtime = m * 1000;
        cb(null);
      } catch (e) {
        cb(e);
      }
    },
    readlink(p, cb) {
      cb(fehler("EINVAL"));
    },
    symlink(a, b, cb) {
      cb(fehler("ENOSYS"));
    },
  };

  function schreibeAusgabe(fd, buf) {
    zeilen[fd] = (zeilen[fd] ?? "") + dec.decode(buf);
    let i;
    while ((i = zeilen[fd].indexOf("\n")) >= 0) {
      ausgabe(fd, zeilen[fd].slice(0, i));
      zeilen[fd] = zeilen[fd].slice(i + 1);
    }
    return buf.length;
  }

  // laden: gespeicherte Dateien (Pfad → Uint8Array) zurück in den Baum.
  function laden(dateien) {
    for (const [pfad, daten] of dateien) {
      const p = normal(pfad);
      const teile = p.split("/").slice(1, -1);
      let d = "";
      for (const t of teile) {
        d += "/" + t;
        if (!baum.has(d)) baum.set(d, knoten("dir", 0o750));
      }
      const k = knoten("file", 0o640);
      k.daten = new Uint8Array(daten);
      k.groesse = k.daten.length;
      baum.set(p, k);
    }
  }

  return { fs, laden };
}
