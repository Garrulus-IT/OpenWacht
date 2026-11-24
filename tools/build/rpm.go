// SPDX-License-Identifier: AGPL-3.0-only

package main

// RPM-Paket nur mit der Standardbibliothek (wie deb.go). Aufbau einer
// .rpm-Datei (Format 3, wie rpm 4.x es schreibt):
//
//	Lead (96 Byte) | Signatur-Header (auf 8 Byte aufgefüllt) | Header | Nutzlast
//
// Die Nutzlast ist ein cpio-Archiv (newc, Namen mit „./“) mit gzip. Der
// Signatur-Header enthält keine Signatur, nur Prüfsummen (SHA-1, SHA-256 des
// Headers, MD5 über Header und Nutzlast, Größen); dazu kommt im Header die
// SHA-256 der Nutzlast. Die echte Signatur von OpenWacht ist die signierte
// SHA256SUMS (Etappe 32); rpm meldet das Paket deshalb als „nicht signiert“.
// Alle Zeiten sind die Commit-Zeit, Eigentümer root: reproduzierbar.

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// Datentypen im Header.
const (
	rpmInt16       = 3
	rpmInt32       = 4
	rpmString      = 6
	rpmBin         = 7
	rpmStringArray = 8
	rpmI18NString  = 9
)

// Tags (rpmtag.h).
const (
	tagHeaderSignatures = 62
	tagHeaderImmutable  = 63
	tagI18NTable        = 100

	sigSHA1        = 269
	sigSHA256      = 273
	sigSize        = 1000
	sigMD5         = 1004
	sigPayloadSize = 1007

	tagName              = 1000
	tagVersion           = 1001
	tagRelease           = 1002
	tagSummary           = 1004
	tagDescription       = 1005
	tagBuildTime         = 1006
	tagBuildHost         = 1007
	tagSize              = 1009
	tagLicense           = 1014
	tagGroup             = 1016
	tagURL               = 1020
	tagOS                = 1021
	tagArch              = 1022
	tagPostIn            = 1024
	tagPreUn             = 1025
	tagPostUn            = 1026
	tagFileSizes         = 1028
	tagFileModes         = 1030
	tagFileRdevs         = 1033
	tagFileMtimes        = 1034
	tagFileDigests       = 1035
	tagFileLinkTos       = 1036
	tagFileFlags         = 1037
	tagFileUserName      = 1039
	tagFileGroupName     = 1040
	tagFileVerifyFlags   = 1045
	tagProvideName       = 1047
	tagRequireFlags      = 1048
	tagRequireName       = 1049
	tagRequireVersion    = 1050
	tagRPMVersion        = 1064
	tagPostInProg        = 1086
	tagPreUnProg         = 1087
	tagPostUnProg        = 1088
	tagFileDevices       = 1095
	tagFileInodes        = 1096
	tagFileLangs         = 1097
	tagProvideFlags      = 1112
	tagProvideVersion    = 1113
	tagDirIndexes        = 1116
	tagBaseNames         = 1117
	tagDirNames          = 1118
	tagPayloadFormat     = 1124
	tagPayloadCompressor = 1125
	tagPayloadFlags      = 1126
	tagPlatform          = 1132
	tagFileDigestAlgo    = 5011
	tagEncoding          = 5062
	tagPayloadDigest     = 5092
	tagPayloadDigestAlgo = 5093
)

// Abhängigkeits-Kennzeichen (rpmds.h).
const (
	senseLess       = 0x02
	senseEqual      = 0x08
	senseInterp     = 0x100
	sensePost       = 0x400
	sensePreUn      = 0x800
	sensePostUn     = 0x1000
	senseRPMLib     = 0x1000000
	fileDoc         = 1 << 1 // RPMFILE_DOC
	digestAlgSHA256 = 8      // PGPHASHALGO_SHA256
)

// rpmScripts: Skripte des RPM, ausgeführt mit /bin/sh.
type rpmScripts struct{ post, preun, postun string }

type rpmEntry struct {
	tag, typ uint32
	count    uint32
	data     []byte
}

// rpmHeader sammelt Einträge und schreibt einen Header mit unveränderlicher
// Region (wie rpm selbst: Region-Eintrag zuerst, Trailer am Ende der Daten).
type rpmHeader struct {
	entries []rpmEntry
}

func (h *rpmHeader) add(tag, typ uint32, count int, data []byte) {
	h.entries = append(h.entries, rpmEntry{tag: tag, typ: typ, count: uint32(count), data: data})
}

func (h *rpmHeader) str(tag uint32, s string) { h.add(tag, rpmString, 1, append([]byte(s), 0)) }
func (h *rpmHeader) i18n(tag uint32, s string) {
	h.add(tag, rpmI18NString, 1, append([]byte(s), 0))
}

func (h *rpmHeader) strs(tag uint32, list []string) {
	var b []byte
	for _, s := range list {
		b = append(append(b, s...), 0)
	}
	h.add(tag, rpmStringArray, len(list), b)
}

func (h *rpmHeader) int32s(tag uint32, v ...uint32) {
	b := make([]byte, 4*len(v))
	for i, x := range v {
		binary.BigEndian.PutUint32(b[4*i:], x)
	}
	h.add(tag, rpmInt32, len(v), b)
}

func (h *rpmHeader) int16s(tag uint32, v ...uint16) {
	b := make([]byte, 2*len(v))
	for i, x := range v {
		binary.BigEndian.PutUint16(b[2*i:], x)
	}
	h.add(tag, rpmInt16, len(v), b)
}

func align(t uint32) int {
	switch t {
	case rpmInt16:
		return 2
	case rpmInt32:
		return 4
	}
	return 1
}

// bytes schreibt den Header. region: tagHeaderImmutable oder tagHeaderSignatures.
func (h *rpmHeader) bytes(region uint32) []byte {
	es := slices.Clone(h.entries)
	sort.SliceStable(es, func(i, j int) bool { return es[i].tag < es[j].tag })
	n := len(es) + 1
	var store bytes.Buffer
	index := make([]byte, 0, 16*n)
	put := func(tag, typ uint32, off int, count uint32) {
		index = binary.BigEndian.AppendUint32(index, tag)
		index = binary.BigEndian.AppendUint32(index, typ)
		index = binary.BigEndian.AppendUint32(index, uint32(int32(off)))
		index = binary.BigEndian.AppendUint32(index, count)
	}
	var body []byte
	for _, e := range es {
		for store.Len()%align(e.typ) != 0 {
			store.WriteByte(0)
		}
		off := store.Len()
		store.Write(e.data)
		body = binary.BigEndian.AppendUint32(body, e.tag)
		body = binary.BigEndian.AppendUint32(body, e.typ)
		body = binary.BigEndian.AppendUint32(body, uint32(off))
		body = binary.BigEndian.AppendUint32(body, e.count)
	}
	// Trailer der Region: verweist auf alle n Einträge davor.
	trailerOff := store.Len()
	tr := binary.BigEndian.AppendUint32(nil, region)
	tr = binary.BigEndian.AppendUint32(tr, rpmBin)
	tr = binary.BigEndian.AppendUint32(tr, uint32(int32(-16*n)))
	tr = binary.BigEndian.AppendUint32(tr, 16)
	store.Write(tr)
	put(region, rpmBin, trailerOff, 16)
	index = append(index, body...)

	var out bytes.Buffer
	out.Write([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0})
	binary.Write(&out, binary.BigEndian, uint32(n))
	binary.Write(&out, binary.BigEndian, uint32(store.Len()))
	out.Write(index)
	out.Write(store.Bytes())
	return out.Bytes()
}

// rpmArch: Architektur in der Schreibweise von RPM.
func rpmArch(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	}
	return "", fmt.Errorf("Architektur %s gibt es als RPM nicht", goarch)
}

// rpmVersion: RPM erlaubt kein „-“ in der Version; Vorabstände wie in debVersion mit „~“.
func rpmVersion(v string) string { return debVersion(v) }

// cpioNewc schreibt ein cpio-Archiv (newc) mit „./“ vor jedem Namen.
func cpioNewc(files []debFile, inodes []uint32, mtime time.Time) []byte {
	var b bytes.Buffer
	hdr := func(name string, ino, mode, nlink uint32, size int) {
		fmt.Fprintf(&b, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			ino, mode, 0, 0, nlink, uint32(mtime.Unix()), size, 0, 0, 0, 0, len(name)+1, 0)
		b.WriteString(name)
		b.WriteByte(0)
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	for i, f := range files {
		hdr("./"+f.path, inodes[i], 0o100000|uint32(f.mode), 1, len(f.data))
		b.Write(f.data)
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	hdr("TRAILER!!!", 0, 0, 1, 0)
	return b.Bytes()
}

// writeRPM schreibt <name>-<version>-1.<arch>.rpm.
func writeRPM(out, goarch string, mtime time.Time, p pkgSpec, sc rpmScripts) (string, error) {
	arch, err := rpmArch(goarch)
	if err != nil {
		return "", err
	}
	files := slices.Clone(p.files)
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	ver, rel := rpmVersion(p.version), "1"

	// Dateiliste: Verzeichnisse (mit „/“ am Ende) und Basisnamen.
	var dirs []string
	var dirIdx, sizes, mtimes, flags, inodes, devices, verify []uint32
	var bases, digests, links, users, groups, langs []string
	var modes, rdevs []uint16
	var total int64
	for i, f := range files {
		d, base := path.Split("/" + f.path)
		k := slices.Index(dirs, d)
		if k < 0 {
			dirs = append(dirs, d)
			k = len(dirs) - 1
		}
		sum := sha256.Sum256(f.data)
		dirIdx = append(dirIdx, uint32(k))
		bases = append(bases, base)
		sizes = append(sizes, uint32(len(f.data)))
		modes = append(modes, uint16(0o100000|f.mode))
		rdevs = append(rdevs, 0)
		mtimes = append(mtimes, uint32(mtime.Unix()))
		digests = append(digests, hex.EncodeToString(sum[:]))
		links = append(links, "")
		fl := uint32(0)
		if strings.HasPrefix(f.path, "usr/share/doc/") {
			fl = fileDoc
		}
		flags = append(flags, fl)
		users, groups, langs = append(users, "root"), append(groups, "root"), append(langs, "")
		inodes, devices = append(inodes, uint32(i+1)), append(devices, 1)
		verify = append(verify, 0xffffffff)
		total += int64(len(f.data))
	}

	cpio := cpioNewc(files, inodes, mtime)
	var gzBuf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&gzBuf, gzip.BestCompression)
	if err != nil {
		return "", err
	}
	gz.Write(cpio)
	if err := gz.Close(); err != nil {
		return "", err
	}
	payload := gzBuf.Bytes()
	payloadSum := sha256.Sum256(payload)

	h := &rpmHeader{}
	h.strs(tagI18NTable, []string{"C"})
	h.str(tagName, p.name)
	h.str(tagVersion, ver)
	h.str(tagRelease, rel)
	h.i18n(tagSummary, p.summary)
	h.i18n(tagDescription, strings.TrimSpace(p.description))
	h.int32s(tagBuildTime, uint32(mtime.Unix()))
	h.str(tagBuildHost, "openwacht-build")
	h.int32s(tagSize, uint32(total))
	h.str(tagLicense, "AGPL-3.0-only")
	h.i18n(tagGroup, "Applications/System")
	h.str(tagURL, "https://github.com/garrulus-it/openwacht")
	h.str(tagOS, "linux")
	h.str(tagArch, arch)
	h.str(tagPostIn, sc.post)
	h.str(tagPostInProg, "/bin/sh")
	h.str(tagPreUn, sc.preun)
	h.str(tagPreUnProg, "/bin/sh")
	h.str(tagPostUn, sc.postun)
	h.str(tagPostUnProg, "/bin/sh")
	h.int32s(tagFileSizes, sizes...)
	h.int16s(tagFileModes, modes...)
	h.int16s(tagFileRdevs, rdevs...)
	h.int32s(tagFileMtimes, mtimes...)
	h.strs(tagFileDigests, digests)
	h.strs(tagFileLinkTos, links)
	h.int32s(tagFileFlags, flags...)
	h.strs(tagFileUserName, users)
	h.strs(tagFileGroupName, groups)
	h.int32s(tagFileVerifyFlags, verify...)
	full := ver + "-" + rel
	h.strs(tagProvideName, []string{p.name, p.name + "(" + arch + ")"})
	h.int32s(tagProvideFlags, senseEqual, senseEqual)
	h.strs(tagProvideVersion, []string{full, full})
	h.strs(tagRequireName, []string{"/bin/sh", "rpmlib(CompressedFileNames)", "rpmlib(FileDigests)", "rpmlib(PayloadFilesHavePrefix)"})
	h.int32s(tagRequireFlags, senseInterp|sensePost|sensePreUn|sensePostUn,
		senseLess|senseEqual|senseRPMLib, senseLess|senseEqual|senseRPMLib, senseLess|senseEqual|senseRPMLib)
	h.strs(tagRequireVersion, []string{"", "3.0.4-1", "4.6.0-1", "4.0-1"})
	h.str(tagRPMVersion, "4.16.1")
	h.int32s(tagFileDevices, devices...)
	h.int32s(tagFileInodes, inodes...)
	h.strs(tagFileLangs, langs)
	h.int32s(tagDirIndexes, dirIdx...)
	h.strs(tagBaseNames, bases)
	h.strs(tagDirNames, dirs)
	h.str(tagPayloadFormat, "cpio")
	h.str(tagPayloadCompressor, "gzip")
	h.str(tagPayloadFlags, "9")
	h.str(tagPlatform, arch+"-pc-linux")
	h.int32s(tagFileDigestAlgo, digestAlgSHA256)
	h.str(tagEncoding, "utf-8")
	h.strs(tagPayloadDigest, []string{hex.EncodeToString(payloadSum[:])})
	h.int32s(tagPayloadDigestAlgo, digestAlgSHA256)
	header := h.bytes(tagHeaderImmutable)

	s1 := sha1.Sum(header)
	s256 := sha256.Sum256(header)
	m := md5.New()
	m.Write(header)
	m.Write(payload)
	sig := &rpmHeader{}
	sig.str(sigSHA1, hex.EncodeToString(s1[:]))
	sig.str(sigSHA256, hex.EncodeToString(s256[:]))
	sig.int32s(sigSize, uint32(len(header)+len(payload)))
	sig.add(sigMD5, rpmBin, 16, m.Sum(nil))
	sig.int32s(sigPayloadSize, uint32(len(cpio)))
	sigBytes := sig.bytes(tagHeaderSignatures)
	for len(sigBytes)%8 != 0 {
		sigBytes = append(sigBytes, 0)
	}

	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	binary.BigEndian.PutUint16(lead[6:], 0) // binär
	binary.BigEndian.PutUint16(lead[8:], 1)
	copy(lead[10:76], p.name+"-"+full)
	binary.BigEndian.PutUint16(lead[76:], 1) // Linux
	binary.BigEndian.PutUint16(lead[78:], 5) // Signatur-Header

	var rpm bytes.Buffer
	rpm.Write(lead)
	rpm.Write(sigBytes)
	rpm.Write(header)
	rpm.Write(payload)
	name := fmt.Sprintf("%s-%s-%s.%s.rpm", p.name, ver, rel, arch)
	fmt.Printf("baue %-40s (RPM-Paket)\n", name)
	return name, os.WriteFile(filepath.Join(out, name), rpm.Bytes(), 0o644)
}
