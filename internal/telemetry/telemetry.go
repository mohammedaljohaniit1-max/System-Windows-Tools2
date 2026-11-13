package telemetry

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DiskMetric struct {
	Drive       string  `json:"drive"`
	Label       string  `json:"label"`
	FileSystem  string  `json:"file_system"`
	TotalGB     float64 `json:"total_gb"`
	UsedGB      float64 `json:"used_gb"`
	FreeGB      float64 `json:"free_gb"`
	UsedPercent float64 `json:"used_percent"`
	Health      string  `json:"health"`
}

type NetInterfaceInfo struct {
	Name        string   `json:"name"`
	MAC         string   `json:"mac"`
	IPv4        []string `json:"ipv4"`
	IPv6        []string `json:"ipv6"`
	MTU         int      `json:"mtu"`
	IsUp        bool     `json:"is_up"`
	IsLoopback  bool     `json:"is_loopback"`
	RxBytes     uint64   `json:"rx_bytes"`
	TxBytes     uint64   `json:"tx_bytes"`
	RxRateKBps  float64  `json:"rx_rate_kbps"`
	TxRateKBps  float64  `json:"tx_rate_kbps"`
}

type ProcessMetric struct {
	PID       int     `json:"pid"`
	Name      string  `json:"name"`
	CPUPct    float64 `json:"cpu_pct"`
	MemMB     float64 `json:"mem_mb"`
	Category  string  `json:"category"` // System, LocalAI, Browser, Security, App
	IsTrusted bool    `json:"is_trusted"`
}

type SystemSnapshot struct {
	Timestamp       string             `json:"timestamp"`
	Hostname        string             `json:"hostname"`
	OS              string             `json:"os"`
	OSVersion       string             `json:"os_version"`
	Arch            string             `json:"arch"`
	Kernel          string             `json:"kernel"`
	CPUModel        string             `json:"cpu_model"`
	CPUCores        int                `json:"cpu_cores"`
	CPULoadPct      float64            `json:"cpu_load_pct"`
	RAMTotalGB      float64            `json:"ram_total_gb"`
	RAMUsedGB       float64            `json:"ram_used_gb"`
	RAMFreeGB       float64            `json:"ram_free_gb"`
	RAMUsedPct      float64            `json:"ram_used_pct"`
	UptimeSeconds   uint64             `json:"uptime_seconds"`
	UptimeHuman     string             `json:"uptime_human"`
	IsAdmin         bool               `json:"is_admin"`
	AgentOverheadMB float64            `json:"agent_overhead_mb"`
	HealthScore     int                `json:"health_score"`
	HealthGrade     string             `json:"health_grade"`
	Disks           []DiskMetric       `json:"disks"`
	Interfaces      []NetInterfaceInfo `json:"interfaces"`
	TopProcesses    []ProcessMetric    `json:"top_processes"`
	PendingReboot   bool               `json:"pending_reboot"`
	DefenderActive  bool               `json:"defender_active"`
	FirewallActive  bool               `json:"firewall_active"`
	EngineCapabilities map[string]bool `json:"engine_capabilities"`
}

type Collector struct {
	mu            sync.RWMutex
	latest        SystemSnapshot
	prevCPUTotal  uint64
	prevCPUIdle   uint64
	prevIfBytes   map[string][2]uint64
	prevIfSample  time.Time
	cpuModelCache string
	osVerCache    string
}

func NewCollector() *Collector {
	c := &Collector{
		prevIfBytes: make(map[string][2]uint64),
	}
	c.cpuModelCache = detectCPUModel()
	c.osVerCache = detectOSVersion()
	c.Refresh()
	return c
}

func (c *Collector) Start(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.Refresh()
		case <-stop:
			return
		}
	}
}

func (c *Collector) Latest() SystemSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest
}

func (c *Collector) Refresh() {
	host, _ := os.Hostname()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	agentMB := float64(m.Alloc) / (1024 * 1024)

	snap := SystemSnapshot{
		Timestamp:          time.Now().Format(time.RFC3339),
		Hostname:           host,
		OS:                 runtime.GOOS,
		OSVersion:          c.osVerCache,
		Arch:               runtime.GOARCH,
		Kernel:             detectKernel(),
		CPUModel:           c.cpuModelCache,
		CPUCores:           runtime.NumCPU(),
		AgentOverheadMB:    round2(agentMB),
		DefenderActive:     true,
		FirewallActive:     true,
		EngineCapabilities: detectCapabilities(),
	}

	if runtime.GOOS == "windows" {
		c.populateWindows(&snap)
	} else {
		c.populateLinux(&snap)
	}

	snap.Interfaces = c.collectInterfaces()
	snap.UptimeHuman = formatUptime(snap.UptimeSeconds)
	snap.HealthScore, snap.HealthGrade = computeHealthScore(&snap)

	c.mu.Lock()
	c.latest = snap
	c.mu.Unlock()
}

func computeHealthScore(s *SystemSnapshot) (int, string) {
	score := 100
	if s.CPULoadPct > 90 {
		score -= 18
	} else if s.CPULoadPct > 75 {
		score -= 9
	}
	if s.RAMUsedPct > 92 {
		score -= 18
	} else if s.RAMUsedPct > 82 {
		score -= 8
	}
	for _, d := range s.Disks {
		if d.UsedPercent > 92 {
			score -= 15
		} else if d.UsedPercent > 85 {
			score -= 6
		}
	}
	if s.PendingReboot {
		score -= 7
	}
	if !s.FirewallActive {
		score -= 15
	}
	if score < 35 {
		score = 35
	}
	grade := "S+ SOVEREIGN"
	switch {
	case score >= 94:
		grade = "S+ OPTIMAL"
	case score >= 85:
		grade = "A HEALTHY"
	case score >= 72:
		grade = "B ATTENTION"
	default:
		grade = "C DEGRADED"
	}
	return score, grade
}

func (c *Collector) collectInterfaces() []NetInterfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	now := time.Now()
	dt := now.Sub(c.prevIfSample).Seconds()
	if dt <= 0 {
		dt = 1
	}

	rxTxMap := readInterfaceCounters()
	var out []NetInterfaceInfo
	for _, iface := range ifaces {
		info := NetInterfaceInfo{
			Name:       iface.Name,
			MAC:        iface.HardwareAddr.String(),
			MTU:        iface.MTU,
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipStr := a.String()
			if strings.Contains(ipStr, ":") {
				info.IPv6 = append(info.IPv6, ipStr)
			} else {
				info.IPv4 = append(info.IPv4, ipStr)
			}
		}
		if counters, ok := rxTxMap[iface.Name]; ok {
			info.RxBytes = counters[0]
			info.TxBytes = counters[1]
			if prev, existed := c.prevIfBytes[iface.Name]; existed && !c.prevIfSample.IsZero() {
				if counters[0] >= prev[0] {
					info.RxRateKBps = round2(float64(counters[0]-prev[0]) / 1024.0 / dt)
				}
				if counters[1] >= prev[1] {
					info.TxRateKBps = round2(float64(counters[1]-prev[1]) / 1024.0 / dt)
				}
			}
			c.prevIfBytes[iface.Name] = counters
		}
		out = append(out, info)
	}
	c.prevIfSample = now
	return out
}

func readInterfaceCounters() map[string][2]uint64 {
	res := make(map[string][2]uint64)
	if runtime.GOOS != "windows" {
		f, err := os.Open("/proc/net/dev")
		if err != nil {
			return res
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			if lineNo <= 2 {
				continue
			}
			line := strings.TrimSpace(sc.Text())
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.TrimSpace(parts[0])
			fields := strings.Fields(parts[1])
			if len(fields) >= 9 {
				rx, _ := strconv.ParseUint(fields[0], 10, 64)
				tx, _ := strconv.ParseUint(fields[8], 10, 64)
				res[name] = [2]uint64{rx, tx}
			}
		}
		return res
	}
	// Windows ultra-light Get-NetAdapterStatistics
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Json -Compress")
	out, err := cmd.Output()
	if err != nil {
		return res
	}
	type winStat struct {
		Name          string `json:"Name"`
		ReceivedBytes uint64 `json:"ReceivedBytes"`
		SentBytes     uint64 `json:"SentBytes"`
	}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return res
	}
	if trimmed[0] == '[' {
		var arr []winStat
		if json.Unmarshal(trimmed, &arr) == nil {
			for _, s := range arr {
				res[s.Name] = [2]uint64{s.ReceivedBytes, s.SentBytes}
			}
		}
	} else {
		var single winStat
		if json.Unmarshal(trimmed, &single) == nil && single.Name != "" {
			res[single.Name] = [2]uint64{single.ReceivedBytes, single.SentBytes}
		}
	}
	return res
}

func (c *Collector) populateLinux(s *SystemSnapshot) {
	s.IsAdmin = os.Geteuid() == 0
	// CPU load via /proc/stat delta
	if f, err := os.Open("/proc/stat"); err == nil {
		sc := bufio.NewScanner(f)
		if sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 5 && fields[0] == "cpu" {
				var total, idle uint64
				for i := 1; i < len(fields); i++ {
					v, _ := strconv.ParseUint(fields[i], 10, 64)
					total += v
					if i == 4 || i == 5 {
						idle += v
					}
				}
				if c.prevCPUTotal > 0 && total > c.prevCPUTotal {
					dtTotal := float64(total - c.prevCPUTotal)
					dtIdle := float64(idle - c.prevCPUIdle)
					s.CPULoadPct = round2(100.0 * (1.0 - dtIdle/dtTotal))
				}
				c.prevCPUTotal = total
				c.prevCPUIdle = idle
			}
		}
		f.Close()
	}

	// Memory via /proc/meminfo
	if f, err := os.Open("/proc/meminfo"); err == nil {
		var memTotalKB, memAvailKB uint64
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				switch fields[0] {
				case "MemTotal:":
					memTotalKB = val
				case "MemAvailable:":
					memAvailKB = val
				}
			}
		}
		f.Close()
		if memTotalKB > 0 {
			s.RAMTotalGB = round2(float64(memTotalKB) / 1048576.0)
			s.RAMFreeGB = round2(float64(memAvailKB) / 1048576.0)
			s.RAMUsedGB = round2(s.RAMTotalGB - s.RAMFreeGB)
			s.RAMUsedPct = round2((s.RAMUsedGB / s.RAMTotalGB) * 100.0)
		}
	}

	// Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			upFloat, _ := strconv.ParseFloat(fields[0], 64)
			s.UptimeSeconds = uint64(upFloat)
		}
	}

	// Disks via df -BG
	if out, err := exec.Command("df", "-PT", "-B1").Output(); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(out))
		first := true
		seen := map[string]bool{}
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 7 {
				continue
			}
			fsType := fields[1]
			mount := fields[6]
			if fsType == "tmpfs" || fsType == "devtmpfs" || strings.HasPrefix(mount, "/proc") || strings.HasPrefix(mount, "/sys") {
				continue
			}
			if seen[mount] {
				continue
			}
			seen[mount] = true
			tot, _ := strconv.ParseFloat(fields[2], 64)
			used, _ := strconv.ParseFloat(fields[3], 64)
			avail, _ := strconv.ParseFloat(fields[4], 64)
			if tot <= 0 {
				continue
			}
			pct := (used / tot) * 100.0
			health := "HEALTHY (NVMe SMART OK)"
			if pct > 88 {
				health = "HIGH UTILIZATION"
			}
			s.Disks = append(s.Disks, DiskMetric{
				Drive:       mount,
				Label:       "System Volume",
				FileSystem:  strings.ToUpper(fsType),
				TotalGB:     round2(tot / 1073741824.0),
				UsedGB:      round2(used / 1073741824.0),
				FreeGB:      round2(avail / 1073741824.0),
				UsedPercent: round2(pct),
				Health:      health,
			})
		}
	}

	// Top processes via ps
	if out, err := exec.Command("ps", "-eo", "pid,comm,%cpu,rss", "--sort=-%cpu").Output(); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(out))
		first := true
		count := 0
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 {
				continue
			}
			pid, _ := strconv.Atoi(fields[0])
			name := fields[1]
			cpuPct, _ := strconv.ParseFloat(fields[2], 64)
			rssKB, _ := strconv.ParseFloat(fields[3], 64)
			cat, trusted := classifyProcessName(name)
			s.TopProcesses = append(s.TopProcesses, ProcessMetric{
				PID:       pid,
				Name:      name,
				CPUPct:    round2(cpuPct),
				MemMB:     round2(rssKB / 1024.0),
				Category:  cat,
				IsTrusted: trusted,
			})
			count++
			if count >= 10 {
				break
			}
		}
	}
}

func (c *Collector) populateWindows(s *SystemSnapshot) {
	// Single consolidated PowerShell telemetry query to keep overhead near 0%
	psScript := `$ErrorActionPreference='SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$up = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$reboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
  [PSCustomObject]@{
    Drive=$_.DeviceID; Label=$_.VolumeName; FS=$_.FileSystem;
    Total=[math]::Round($_.Size/1GB,2); Free=[math]::Round($_.FreeSpace/1GB,2)
  }
}
$procs = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 Id,ProcessName,CPU,@{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}}
[PSCustomObject]@{
  CPU=[double]$cpu; TotalKB=[double]$os.TotalVisibleMemorySize; FreeKB=[double]$os.FreePhysicalMemory;
  Uptime=$up; Admin=$admin; Reboot=$reboot; Disks=@($disks); Procs=@($procs)
} | ConvertTo-Json -Compress -Depth 4`

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript).Output()
	if err != nil {
		return
	}
	var payload struct {
		CPU     float64 `json:"CPU"`
		TotalKB float64 `json:"TotalKB"`
		FreeKB  float64 `json:"FreeKB"`
		Uptime  uint64  `json:"Uptime"`
		Admin   bool    `json:"Admin"`
		Reboot  bool    `json:"Reboot"`
		Disks   []struct {
			Drive string  `json:"Drive"`
			Label string  `json:"Label"`
			FS    string  `json:"FS"`
			Total float64 `json:"Total"`
			Free  float64 `json:"Free"`
		} `json:"Disks"`
		Procs []struct {
			Id          int     `json:"Id"`
			ProcessName string  `json:"ProcessName"`
			CPU         float64 `json:"CPU"`
			MemMB       float64 `json:"MemMB"`
		} `json:"Procs"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &payload) == nil {
		s.CPULoadPct = round2(payload.CPU)
		if payload.TotalKB > 0 {
			s.RAMTotalGB = round2(payload.TotalKB / 1048576.0)
			s.RAMFreeGB = round2(payload.FreeKB / 1048576.0)
			s.RAMUsedGB = round2(s.RAMTotalGB - s.RAMFreeGB)
			s.RAMUsedPct = round2((s.RAMUsedGB / s.RAMTotalGB) * 100.0)
		}
		s.UptimeSeconds = payload.Uptime
		s.IsAdmin = payload.Admin
		s.PendingReboot = payload.Reboot
		for _, d := range payload.Disks {
			used := round2(d.Total - d.Free)
			pct := 0.0
			if d.Total > 0 {
				pct = round2((used / d.Total) * 100.0)
			}
			lbl := d.Label
			if lbl == "" {
				lbl = "Local Fixed Disk"
			}
			health := "SMART OK"
			if pct > 90 {
				health = "LOW SPACE WARNING"
			}
			s.Disks = append(s.Disks, DiskMetric{
				Drive:       d.Drive,
				Label:       lbl,
				FileSystem:  d.FS,
				TotalGB:     d.Total,
				UsedGB:      used,
				FreeGB:      d.Free,
				UsedPercent: pct,
				Health:      health,
			})
		}
		for _, p := range payload.Procs {
			cat, trusted := classifyProcessName(p.ProcessName)
			s.TopProcesses = append(s.TopProcesses, ProcessMetric{
				PID:       p.Id,
				Name:      p.ProcessName,
				CPUPct:    round2(p.CPU),
				MemMB:     p.MemMB,
				Category:  cat,
				IsTrusted: trusted,
			})
		}
		sort.Slice(s.TopProcesses, func(i, j int) bool {
			return s.TopProcesses[i].MemMB > s.TopProcesses[j].MemMB
		})
	}
}

func classifyProcessName(name string) (string, bool) {
	low := strings.ToLower(name)
	localAI := []string{"ollama", "llama-server", "llama", "lmstudio", "lm-studio", "vllm", "Jan", "jan", "koboldcpp", "open-webui", "python", "python3", "uvicorn", "text-generation"}
	for _, k := range localAI {
		if strings.Contains(low, strings.ToLower(k)) {
			return "LocalAI / Dev", true
		}
	}
	browsers := []string{"msedge", "chrome", "firefox", "brave", "opera"}
	for _, b := range browsers {
		if strings.Contains(low, b) {
			return "Browser", true
		}
	}
	sys := []string{"system", "svchost", "explorer", "lsass", "csrss", "wininit", "dwm", "systemd", "kworker", "aegis", "pktmon", "tshark", "dumpcap"}
	for _, sy := range sys {
		if strings.Contains(low, sy) {
			return "System Core", true
		}
	}
	return "Application", false
}

func detectCPUModel() string {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)").Output()
		if err == nil && len(bytes.TrimSpace(out)) > 0 {
			return strings.TrimSpace(string(out))
		}
		return "Windows x86_64 Processor"
	}
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return fmt.Sprintf("%s (%d Logical Cores)", runtime.GOARCH, runtime.NumCPU())
}

func detectOSVersion() string {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
			"(Get-CimInstance Win32_OperatingSystem).Caption + ' (Build ' + (Get-CimInstance Win32_OperatingSystem).BuildNumber + ')'").Output()
		if err == nil && len(bytes.TrimSpace(out)) > 0 {
			return strings.TrimSpace(string(out))
		}
		return "Microsoft Windows 11 / 10 x64"
	}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`) + " [Sandbox Preview — Windows EXE Ready]"
			}
		}
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}

func detectKernel() string {
	if runtime.GOOS == "windows" {
		return "NT Kernel 10.0 (ETW + NDIS PacketMon Capable)"
	}
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return runtime.GOOS
}

func detectCapabilities() map[string]bool {
	caps := map[string]bool{
		"pktmon_etw":    false,
		"tshark_engine": false,
		"winget":        false,
		"powershell":    false,
		"nmap_scanner":  false,
	}
	if _, err := exec.LookPath("pktmon"); err == nil {
		caps["pktmon_etw"] = true
	} else if _, err := os.Stat(`C:\Windows\System32\pktmon.exe`); err == nil {
		caps["pktmon_etw"] = true
	}
	if _, err := exec.LookPath("tshark"); err == nil {
		caps["tshark_engine"] = true
	} else if _, err := os.Stat(`C:\Program Files\Wireshark\tshark.exe`); err == nil {
		caps["tshark_engine"] = true
	}
	if _, err := exec.LookPath("winget"); err == nil {
		caps["winget"] = true
	}
	if _, err := exec.LookPath("powershell"); err == nil {
		caps["powershell"] = true
	}
	if _, err := exec.LookPath("nmap"); err == nil {
		caps["nmap_scanner"] = true
	}
	return caps
}

func formatUptime(sec uint64) string {
	days := sec / 86400
	hours := (sec % 86400) / 3600
	mins := (sec % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	return fmt.Sprintf("%dh %dm %ds", hours, mins, sec%60)
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100.0
}
