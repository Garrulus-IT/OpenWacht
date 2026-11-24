// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package agent

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/garrulus-it/openwacht/internal/agentproto"
	"github.com/garrulus-it/openwacht/internal/version"
)

// Nur aus System32 laden, nie aus dem Programmverzeichnis.
var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// Collector sammelt Messwerte. Er merkt sich die letzte CPU-Messung, damit
// die Auslastung über das Meldeintervall gemittelt wird.
type Collector struct {
	prev    cpuSample
	hasPrev bool
}

func NewCollector() *Collector { return &Collector{} }

func filetime(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }

// systemTimes: Die Kernel-Zeit enthält die Leerlaufzeit bereits.
func systemTimes() (cpuSample, error) {
	var idle, kernel, user windows.Filetime
	r, _, err := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return cpuSample{}, fmt.Errorf("GetSystemTimes: %w", err)
	}
	return cpuSample{idle: filetime(idle), total: filetime(kernel) + filetime(user)}, nil
}

// Collect liefert einen Snapshot. Beim ersten Aufruf wird die CPU zweimal im
// Abstand von einer Sekunde gemessen.
func (c *Collector) Collect() (agentproto.Snapshot, error) {
	var s agentproto.Snapshot
	cur, err := systemTimes()
	if err != nil {
		return s, err
	}
	if !c.hasPrev {
		c.prev, c.hasPrev = cur, true
		time.Sleep(time.Second)
		if cur, err = systemTimes(); err != nil {
			return s, err
		}
	}
	s.CPU.Percent = cpuPercent(c.prev, cur)
	c.prev = cur
	// alle Prozessorgruppen, auch bei mehr als 64 Kernen
	s.CPU.Cores = int(windows.GetActiveProcessorCount(windows.ALL_PROCESSOR_GROUPS))
	if s.CPU.Cores < 1 {
		s.CPU.Cores = runtime.NumCPU()
	}
	s.CPU.NoLoad = true // Windows kennt keine Load Average

	ms := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	if r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r == 0 {
		return s, fmt.Errorf("GlobalMemoryStatusEx: %w", err)
	}
	s.Memory.TotalBytes, s.Memory.AvailableBytes = ms.TotalPhys, ms.AvailPhys
	// „PageFile“ ist hier das Commit-Limit (RAM plus Auslagerungsdatei).
	// Die Differenz zum RAM ist die Auslagerungsdatei, als Näherung.
	if ms.TotalPageFile > ms.TotalPhys {
		s.Memory.SwapTotalBytes = ms.TotalPageFile - ms.TotalPhys
		if ms.AvailPageFile > ms.AvailPhys {
			s.Memory.SwapFreeBytes = min(ms.AvailPageFile-ms.AvailPhys, s.Memory.SwapTotalBytes)
		}
	}
	s.UptimeSec = uint64(windows.DurationSinceBoot() / time.Second)

	host, err := os.Hostname()
	if err != nil {
		return s, err
	}
	s.Hostname = strings.ToLower(host)
	product, displayVersion, ubr := readWindowsVersion()
	v := windows.RtlGetVersion()
	s.OS = clip(WindowsOSName(product, displayVersion, v.BuildNumber), 100)
	s.Kernel = fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
	if ubr > 0 {
		s.Kernel += "." + strconv.FormatUint(ubr, 10)
	}
	s.Arch = runtime.GOARCH
	s.AgentVersion = clip(version.Version, 40)
	s.Disks = fixedDisks()
	s.CollectedAt = time.Now()
	return s, nil
}

func readWindowsVersion() (product, displayVersion string, ubr uint64) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", "", 0
	}
	defer k.Close()
	product, _, _ = k.GetStringValue("ProductName")
	if displayVersion, _, _ = k.GetStringValue("DisplayVersion"); displayVersion == "" {
		displayVersion, _, _ = k.GetStringValue("ReleaseId") // vor 20H2
	}
	ubr, _, _ = k.GetIntegerValue("UBR")
	return product, displayVersion, ubr
}

// fixedDisks: nur lokale Festplatten mit Laufwerksbuchstaben, keine
// Netzlaufwerke, CD-Laufwerke oder Wechseldatenträger.
func fixedDisks() []agentproto.Disk {
	buf := make([]uint16, 512)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil || n == 0 || int(n) > len(buf) {
		return nil
	}
	var disks []agentproto.Disk
	// GetLogicalDriveStrings liefert „C:\␀D:\␀␀“.
	for i := 0; i < int(n) && len(disks) < agentproto.MaxDisks; {
		j := i
		for j < int(n) && buf[j] != 0 {
			j++
		}
		if j == i {
			break
		}
		root := windows.UTF16ToString(buf[i:j])
		i = j + 1
		p, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue
		}
		var avail, total, totalFree uint64
		if windows.GetDiskFreeSpaceEx(p, &avail, &total, &totalFree) != nil || total == 0 {
			continue // z. B. mit BitLocker gesperrt
		}
		fs := make([]uint16, windows.MAX_PATH+1)
		fsName := ""
		if windows.GetVolumeInformation(p, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))) == nil {
			fsName = windows.UTF16ToString(fs)
		}
		disks = append(disks, agentproto.Disk{
			Mount:      clip(strings.TrimSuffix(root, `\`), 256),
			FSType:     clip(strings.ToLower(fsName), 32),
			TotalBytes: total,
			FreeBytes:  min(avail, total), // für den Agent verfügbar, wie unter Linux
		})
	}
	return disks
}
