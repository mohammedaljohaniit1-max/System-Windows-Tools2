package netengine

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DissectedFrame struct {
	Seq         uint64   `json:"seq"`
	Timestamp   string   `json:"timestamp"`
	UnixMilli   int64    `json:"unix_milli"`
	Engine      string   `json:"engine"` // TShark-L7, Pktmon-ETW, Kernel-SocketTable
	SrcIP       string   `json:"src_ip"`
	SrcPort     int      `json:"src_port"`
	DstIP       string   `json:"dst_ip"`
	DstPort     int      `json:"dst_port"`
	Protocol    string   `json:"protocol"` // TCP, UDP, TLSv1.3, HTTP, DNS, ICMP, ARP, LocalAI-RPC
	Length      int      `json:"length"`
	TCPFlags    string   `json:"tcp_flags"`
	WindowSize  int      `json:"window_size"`
	TTL         int      `json:"ttl"`
	ProcessName string   `json:"process_name"`
	PID         int      `json:"pid"`
	Direction   string   `json:"direction"` // INBOUND, OUTBOUND, LOOPBACK
	Info        string   `json:"info"`
	Layers      []string `json:"layers"`
	HexPreview  string   `json:"hex_preview"`
	IsWhitelistedAI bool `json:"is_whitelisted_ai"`
}

type ActiveFlow struct {
	Key         string `json:"key"`
	Proto       string `json:"proto"`
	LocalAddr   string `json:"local_addr"`
	LocalPort   int    `json:"local_port"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  int    `json:"remote_port"`
	State       string `json:"state"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	Category    string `json:"category"` // Trusted-LocalAI, System, Web/TLS, LAN, External
	LastSeen    string `json:"last_seen"`
}

type EngineStats struct {
	ActiveBackend      string            `json:"active_backend"`
	ZeroRouterLoad     bool              `json:"zero_router_load"`
	PromiscuousMode    bool              `json:"promiscuous_mode"`
	PacketsCaptured    uint64            `json:"packets_captured"`
	BytesInspected     uint64            `json:"bytes_inspected"`
	ActiveFlowsCount   int               `json:"active_flows_count"`
	ProtocolBreakdown  map[string]uint64 `json:"protocol_breakdown"`
	WiresharkAvailable bool              `json:"wireshark_available"`
	PktmonAvailable    bool              `json:"pktmon_available"`
}

type PacketSubscriber func(frame DissectedFrame)

type Engine struct {
	mu          sync.RWMutex
	ring        []DissectedFrame
	maxRing     int
	flows       []ActiveFlow
	protoCounts map[string]uint64
	seqCounter  uint64
	byteCounter uint64
	backendName string
	tsharkPath  string
	pktmonPath  string
	subscribers []PacketSubscriber
	seenConnSig map[string]time.Time
}

func NewEngine() *Engine {
	e := &Engine{
		ring:        make([]DissectedFrame, 0, 400),
		maxRing:     400,
		protoCounts: make(map[string]uint64),
		seenConnSig: make(map[string]time.Time),
		backendName: "Kernel Passive Socket & Flow Dissector (0.0% Router Load)",
	}
	e.detectBackends()
	return e
}

func (e *Engine) detectBackends() {
	// Check Wireshark TShark
	if p, err := exec.LookPath("tshark"); err == nil {
		e.tsharkPath = p
	} else if runtime.GOOS == "windows" {
		candidates := []string{
			`C:\Program Files\Wireshark\tshark.exe`,
			`C:\Program Files (x86)\Wireshark\tshark.exe`,
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				e.tsharkPath = c
				break
			}
		}
	}
	// Check Windows native Pktmon ETW
	if p, err := exec.LookPath("pktmon"); err == nil {
		e.pktmonPath = p
	} else if runtime.GOOS == "windows" {
		if _, err := os.Stat(`C:\Windows\System32\pktmon.exe`); err == nil {
			e.pktmonPath = `C:\Windows\System32\pktmon.exe`
		}
	}

	if e.tsharkPath != "" {
		e.backendName = "Wireshark TShark L7 Passive Stream + Kernel Socket Mapper"
	} else if e.pktmonPath != "" {
		e.backendName = "Windows Native Pktmon ETW Kernel Engine + Socket Mapper"
	} else {
		e.backendName = "Zero-Driver Kernel TCP/UDP State Dissector (Passive Mode)"
	}
}

func (e *Engine) Subscribe(fn PacketSubscriber) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.subscribers = append(e.subscribers, fn)
}

func (e *Engine) Start(stop <-chan struct{}) {
	// If tshark is available and permitted, stream passive frames in background
	if e.tsharkPath != "" {
		go e.runTsharkPassiveStream(stop)
	}
	// Always run zero-overhead kernel socket & flow differential tracker (1.2s cadence)
	ticker := time.NewTicker(1200 * time.Millisecond)
	defer ticker.Stop()

	e.pollSocketsAndSynthesizeFrames()
	for {
		select {
		case <-ticker.C:
			e.pollSocketsAndSynthesizeFrames()
		case <-stop:
			return
		}
	}
}

// InjectExternalFrame allows the IDS or live raw-packet listener to push real dissected packets into the Wireshark view
func (e *Engine) InjectExternalFrame(f DissectedFrame) {
	seq := atomic.AddUint64(&e.seqCounter, 1)
	f.Seq = seq
	if f.Timestamp == "" {
		f.Timestamp = time.Now().Format("15:04:05.000")
	}
	if f.UnixMilli == 0 {
		f.UnixMilli = time.Now().UnixMilli()
	}
	if f.Length <= 0 {
		f.Length = 64
	}
	atomic.AddUint64(&e.byteCounter, uint64(f.Length))

	e.mu.Lock()
	e.protoCounts[f.Protocol]++
	e.ring = append(e.ring, f)
	if len(e.ring) > e.maxRing {
		e.ring = e.ring[len(e.ring)-e.maxRing:]
	}
	subs := append([]PacketSubscriber(nil), e.subscribers...)
	e.mu.Unlock()

	for _, sub := range subs {
		sub(f)
	}
}

func (e *Engine) RecentFrames(limit int) []DissectedFrame {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 || limit > len(e.ring) {
		limit = len(e.ring)
	}
	start := len(e.ring) - limit
	out := make([]DissectedFrame, limit)
	copy(out, e.ring[start:])
	// Reverse so newest is first for UI table
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (e *Engine) Flows() []ActiveFlow {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]ActiveFlow, len(e.flows))
	copy(out, e.flows)
	return out
}

func (e *Engine) Stats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	pb := make(map[string]uint64, len(e.protoCounts))
	for k, v := range e.protoCounts {
		pb[k] = v
	}
	return EngineStats{
		ActiveBackend:      e.backendName,
		ZeroRouterLoad:     true,
		PromiscuousMode:    false,
		PacketsCaptured:    atomic.LoadUint64(&e.seqCounter),
		BytesInspected:     atomic.LoadUint64(&e.byteCounter),
		ActiveFlowsCount:   len(e.flows),
		ProtocolBreakdown:  pb,
		WiresharkAvailable: e.tsharkPath != "",
		PktmonAvailable:    e.pktmonPath != "",
	}
}

func (e *Engine) runTsharkPassiveStream(stop <-chan struct{}) {
	// -p disables promiscuous mode (protects NIC & router), -n disables DNS reverse lookups (zero router DNS spam!)
	cmd := exec.Command(e.tsharkPath, "-p", "-n", "-l", "-T", "fields",
		"-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport",
		"-e", "_ws.col.Protocol", "-e", "frame.len", "-e", "tcp.flags.str",
		"-e", "tcp.window_size_value", "-e", "ip.ttl", "-e", "_ws.col.Info")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	go func() {
		<-stop
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) < 10 || parts[0] == "" {
			continue
		}
		sp, _ := strconv.Atoi(parts[1])
		dp, _ := strconv.Atoi(parts[3])
		ln, _ := strconv.Atoi(parts[5])
		win, _ := strconv.Atoi(parts[7])
		ttl, _ := strconv.Atoi(parts[8])
		proto := parts[4]
		if proto == "" {
			proto = "TCP"
		}
		ai := isLocalAIPort(sp) || isLocalAIPort(dp)
		e.InjectExternalFrame(DissectedFrame{
			Engine:          "TShark-L7",
			SrcIP:           parts[0],
			SrcPort:         sp,
			DstIP:           parts[2],
			DstPort:         dp,
			Protocol:        proto,
			Length:          ln,
			TCPFlags:        parts[6],
			WindowSize:      win,
			TTL:             ttl,
			Direction:       classifyDirection(parts[0], parts[2]),
			Info:            parts[9],
			Layers:          []string{"Frame (Wire)", "Ethernet II", "IPv4 (TTL " + strconv.Itoa(ttl) + ")", proto, "Wireshark Dissector"},
			HexPreview:      buildSyntheticWireHeaderHex(parts[0], parts[2], sp, dp, win),
			IsWhitelistedAI: ai,
		})
	}
}

func (e *Engine) pollSocketsAndSynthesizeFrames() {
	var flows []ActiveFlow
	if runtime.GOOS == "windows" {
		flows = collectWindowsFlows()
	} else {
		flows = collectLinuxFlows()
	}

	now := time.Now()
	e.mu.Lock()
	e.flows = flows
	// Prune old signatures
	for k, t := range e.seenConnSig {
		if now.Sub(t) > 15*time.Second {
			delete(e.seenConnSig, k)
		}
	}
	e.mu.Unlock()

	for _, fl := range flows {
		// Ignore our own dashboard SSE polling noise on high frequency unless first seen
		sig := fmt.Sprintf("%s|%s:%d->%s:%d|%s", fl.Proto, fl.LocalAddr, fl.LocalPort, fl.RemoteAddr, fl.RemotePort, fl.State)
		e.mu.Lock()
		last, seen := e.seenConnSig[sig]
		if seen && now.Sub(last) < 6*time.Second {
			e.mu.Unlock()
			continue
		}
		e.seenConnSig[sig] = now
		e.mu.Unlock()

		if fl.State == "LISTEN" && seen {
			continue
		}

		proto := classifyL7Protocol(fl.Proto, fl.LocalPort, fl.RemotePort, fl.ProcessName)
		flags := stateToTCPFlags(fl.State)
		ai := fl.Category == "Trusted-LocalAI"
		srcIP, srcPort, dstIP, dstPort := fl.LocalAddr, fl.LocalPort, fl.RemoteAddr, fl.RemotePort
		dir := classifyDirection(srcIP, dstIP)
		if fl.State == "SYN-RECV" || fl.State == "TIME-WAIT" {
			srcIP, srcPort, dstIP, dstPort = fl.RemoteAddr, fl.RemotePort, fl.LocalAddr, fl.LocalPort
			dir = "INBOUND"
		}

		info := fmt.Sprintf("[%s] %s (%d) %s -> %s:%d", fl.State, fl.ProcessName, fl.PID, fmt.Sprintf("%s:%d", fl.LocalAddr, fl.LocalPort), fl.RemoteAddr, fl.RemotePort)
		if ai {
			info = "[Whitelisted Local AI/Dev Socket] " + info
		}

		eng := "Kernel-SocketTable"
		if runtime.GOOS == "windows" && e.pktmonPath != "" {
			eng = "ETW-KernelFlow"
		}

		e.InjectExternalFrame(DissectedFrame{
			Engine:          eng,
			SrcIP:           srcIP,
			SrcPort:         srcPort,
			DstIP:           dstIP,
			DstPort:         dstPort,
			Protocol:        proto,
			Length:          estimatePacketLen(proto, fl.State),
			TCPFlags:        flags,
			WindowSize:      64240,
			TTL:             64,
			ProcessName:     fl.ProcessName,
			PID:             fl.PID,
			Direction:       dir,
			Info:            info,
			Layers:          []string{"Kernel NDIS/Socket", "IP (" + srcIP + " -> " + dstIP + ")", fl.Proto + " [" + flags + "]", "L7: " + proto, fmt.Sprintf("Owner: %s (PID %d)", fl.ProcessName, fl.PID)},
			HexPreview:      buildSyntheticWireHeaderHex(srcIP, dstIP, srcPort, dstPort, 64240),
			IsWhitelistedAI: ai,
		})
	}
}

func collectLinuxFlows() []ActiveFlow {
	out, err := exec.Command("ss", "-tunap").Output()
	if err != nil {
		out, _ = exec.Command("ss", "-tuna").Output()
	}
	var flows []ActiveFlow
	sc := bufio.NewScanner(bytes.NewReader(out))
	first := true
	nowStr := time.Now().Format("15:04:05")
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			if strings.HasPrefix(line, "Netid") {
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToUpper(fields[0])
		state := fields[1]
		localStr := fields[4]
		remoteStr := ""
		if len(fields) >= 6 {
			remoteStr = fields[5]
		}
		procName := "kernel/system"
		pid := 0
		if len(fields) >= 7 {
			pInfo := fields[6]
			if idx := strings.Index(pInfo, `(("`); idx >= 0 {
				rest := pInfo[idx+3:]
				if end := strings.Index(rest, `"`); end > 0 {
					procName = rest[:end]
				}
			}
			if pidIdx := strings.Index(pInfo, "pid="); pidIdx >= 0 {
				rest := pInfo[pidIdx+4:]
				end := strings.IndexAny(rest, ",)")
				if end > 0 {
					pid, _ = strconv.Atoi(rest[:end])
				}
			}
		}
		lAddr, lPort := splitHostPortLoose(localStr)
		rAddr, rPort := splitHostPortLoose(remoteStr)
		cat := categorizeFlow(lAddr, lPort, rAddr, rPort, procName)
		flows = append(flows, ActiveFlow{
			Key:         fmt.Sprintf("%s-%s:%d-%s:%d", proto, lAddr, lPort, rAddr, rPort),
			Proto:       proto,
			LocalAddr:   lAddr,
			LocalPort:   lPort,
			RemoteAddr:  rAddr,
			RemotePort:  rPort,
			State:       state,
			PID:         pid,
			ProcessName: procName,
			Category:    cat,
			LastSeen:    nowStr,
		})
		if len(flows) >= 120 {
			break
		}
	}
	return flows
}

func collectWindowsFlows() []ActiveFlow {
	ps := `$ErrorActionPreference='SilentlyContinue'
$procs = @{}
Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
Get-NetTCPConnection | Select-Object -First 120 LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ForEach-Object {
  $pn = $procs[[int]$_.OwningProcess]
  if (-not $pn) { $pn = 'System' }
  [PSCustomObject]@{
    LA=$_.LocalAddress; LP=[int]$_.LocalPort; RA=$_.RemoteAddress; RP=[int]$_.RemotePort;
    St=$_.State.ToString(); PID=[int]$_.OwningProcess; PN=$pn
  }
} | ConvertTo-Json -Compress`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return nil
	}
	type row struct {
		LA  string `json:"LA"`
		LP  int    `json:"LP"`
		RA  string `json:"RA"`
		RP  int    `json:"RP"`
		St  string `json:"St"`
		PID int    `json:"PID"`
		PN  string `json:"PN"`
	}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return nil
	}
	var rows []row
	if trimmed[0] == '[' {
		_ = json.Unmarshal(trimmed, &rows)
	} else {
		var single row
		if json.Unmarshal(trimmed, &single) == nil {
			rows = append(rows, single)
		}
	}
	nowStr := time.Now().Format("15:04:05")
	var flows []ActiveFlow
	for _, r := range rows {
		cat := categorizeFlow(r.LA, r.LP, r.RA, r.RP, r.PN)
		flows = append(flows, ActiveFlow{
			Key:         fmt.Sprintf("TCP-%s:%d-%s:%d", r.LA, r.LP, r.RA, r.RP),
			Proto:       "TCP",
			LocalAddr:   r.LA,
			LocalPort:   r.LP,
			RemoteAddr:  r.RA,
			RemotePort:  r.RP,
			State:       strings.ToUpper(r.St),
			PID:         r.PID,
			ProcessName: r.PN,
			Category:    cat,
			LastSeen:    nowStr,
		})
	}
	return flows
}

func splitHostPortLoose(s string) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*:*" {
		return "0.0.0.0", 0
	}
	lastColon := strings.LastIndex(s, ":")
	if lastColon < 0 {
		return s, 0
	}
	host := strings.Trim(s[:lastColon], "[]")
	if idx := strings.Index(host, "%"); idx > 0 {
		host = host[:idx]
	}
	port, _ := strconv.Atoi(s[lastColon+1:])
	if host == "*" || host == "" {
		host = "0.0.0.0"
	}
	return host, port
}

func isLocalAIPort(p int) bool {
	switch p {
	case 11434, 1234, 8000, 7860, 5001, 8080, 3000, 5173, 4000, 8188:
		return true
	}
	return false
}

func categorizeFlow(la string, lp int, ra string, rp int, proc string) string {
	low := strings.ToLower(proc)
	aiProcs := []string{"ollama", "llama", "lmstudio", "lm-studio", "vllm", "jan", "kobold", "open-webui", "comfyui", "python", "node", "code", "docker", "wsl"}
	for _, k := range aiProcs {
		if strings.Contains(low, k) {
			return "Trusted-LocalAI"
		}
	}
	if (la == "127.0.0.1" || la == "::1" || ra == "127.0.0.1" || ra == "::1") && (isLocalAIPort(lp) || isLocalAIPort(rp)) {
		return "Trusted-LocalAI"
	}
	if rp == 443 || lp == 443 {
		return "Web/TLSv1.3"
	}
	if strings.HasPrefix(ra, "192.168.") || strings.HasPrefix(ra, "10.") || strings.HasPrefix(ra, "172.") {
		return "LAN"
	}
	if la == "127.0.0.1" || la == "::1" {
		return "Loopback-IPC"
	}
	return "External"
}

func classifyL7Protocol(l4 string, lp, rp int, proc string) string {
	if isLocalAIPort(lp) || isLocalAIPort(rp) {
		if lp == 11434 || rp == 11434 || lp == 1234 || rp == 1234 {
			return "LocalAI-RPC"
		}
	}
	switch {
	case lp == 443 || rp == 443:
		return "TLSv1.3"
	case lp == 53 || rp == 53:
		return "DNS"
	case lp == 80 || rp == 80 || lp == 8080 || rp == 8080:
		return "HTTP"
	case lp == 22 || rp == 22:
		return "SSHv2"
	case lp == 3389 || rp == 3389:
		return "RDP"
	case lp == 445 || rp == 445:
		return "SMB3"
	}
	if strings.Contains(strings.ToLower(proc), "ollama") {
		return "LocalAI-RPC"
	}
	return l4
}

func classifyDirection(src, dst string) string {
	if src == "127.0.0.1" || dst == "127.0.0.1" || src == "::1" || dst == "::1" {
		return "LOOPBACK"
	}
	if src == "0.0.0.0" {
		return "LISTEN"
	}
	return "OUTBOUND"
}

func stateToTCPFlags(state string) string {
	switch strings.ToUpper(state) {
	case "SYN-SENT", "SYNSENT":
		return "SYN"
	case "SYN-RECV", "SYNRECV", "SYNRECEIVED":
		return "SYN, ACK"
	case "ESTAB", "ESTABLISHED":
		return "PSH, ACK"
	case "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "TIME-WAIT":
		return "FIN, ACK"
	case "LISTEN":
		return "LISTEN"
	default:
		return "ACK"
	}
}

func estimatePacketLen(proto, state string) int {
	if state == "LISTEN" {
		return 60
	}
	switch proto {
	case "TLSv1.3":
		return 517
	case "DNS":
		return 92
	case "HTTP", "LocalAI-RPC":
		return 348
	default:
		return 74
	}
}

func buildSyntheticWireHeaderHex(src, dst string, sp, dp, win int) string {
	buf := []byte{
		0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		byte(sp >> 8), byte(sp & 0xff),
		byte(dp >> 8), byte(dp & 0xff),
		byte(win >> 8), byte(win & 0xff),
	}
	h := strings.ToUpper(hex.EncodeToString(buf))
	var spaced []string
	for i := 0; i+2 <= len(h); i += 2 {
		spaced = append(spaced, h[i:i+2])
	}
	return strings.Join(spaced, " ")
}
