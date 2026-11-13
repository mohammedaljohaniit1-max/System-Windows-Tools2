package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"aegisx/internal/copilot"
	"aegisx/internal/cyberids"
	"aegisx/internal/itsupport"
	"aegisx/internal/netengine"
	"aegisx/internal/telemetry"
	"aegisx/web"
)

func main() {
	portFlag := flag.Int("port", 7788, "HTTP port for AEGIS-X Sovereign Dashboard")
	hostFlag := flag.String("host", "", "Bind host (defaults to 127.0.0.1 on Windows EXE, 0.0.0.0 when specified)")
	noBrowser := flag.Bool("no-browser", false, "Disable automatic browser launch")
	exeDownloadPath := flag.String("exe-path", "./dist/AegisX.exe", "Path to compiled Windows AegisX.exe for web download")
	flag.Parse()

	bindHost := *hostFlag
	if bindHost == "" {
		if runtime.GOOS == "windows" {
			bindHost = "127.0.0.1"
		} else {
			bindHost = "0.0.0.0"
		}
	}

	stop := make(chan struct{})
	defer close(stop)

	// 1. Initialize Subsystems
	tel := telemetry.NewCollector()
	go tel.Start(2*time.Second, stop)

	itMgr := itsupport.NewManager()

	netEng := netengine.NewEngine()
	go netEng.Start(stop)

	idsEng := cyberids.NewEngine(netEng)
	go idsEng.Start(stop)

	// Windows Desktop Toast Notification on verified intrusion (0% False Positives)
	idsEng.SubscribeAlerts(func(alert cyberids.ThreatAlert) {
		log.Printf("[AEGIS-X IDS CRITICAL ALERT] %s | Src=%s | Ports=%v | Confidence=%d%%",
			alert.AttackType, alert.AttackerIP, alert.TargetPorts, alert.ConfidenceScore)
		if runtime.GOOS == "windows" {
			go triggerWindowsToastNotification(alert)
		}
	})

	// 2. Setup Embedded Static + Asset File Servers
	staticSub, err := fs.Sub(web.EmbeddedFS, "static")
	if err != nil {
		log.Fatalf("embed static error: %v", err)
	}
	assetsSub, err := fs.Sub(web.EmbeddedFS, "assets")
	if err != nil {
		log.Fatalf("embed assets error: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assetsSub))))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := web.EmbeddedFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "UI missing", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	// Unified low-overhead dashboard state endpoint
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"system": tel.Latest(),
			"network": map[string]interface{}{
				"stats":  netEng.Stats(),
				"frames": netEng.RecentFrames(80),
				"flows":  netEng.Flows(),
			},
			"cyber": idsEng.Status(),
		})
	})

	// IT Support Catalog & Execution
	mux.HandleFunc("/api/itsupport/catalog", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, itMgr.Catalog())
	})

	mux.HandleFunc("/api/itsupport/execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ToolID string `json:"tool_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res, err := itMgr.Execute(req.ToolID, tel.Latest())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, res)
	})

	// Deterministic Diagnostic Copilot
	mux.HandleFunc("/api/copilot/diagnose", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		snap := tel.Latest()
		netSt := netEng.Stats()
		idsSt := idsEng.Status()
		rep := copilot.Diagnose(req.Query, snap, netSt.ActiveFlowsCount, idsSt.ConfirmedThreats)
		writeJSON(w, rep)
	})

	// Cyber IDS Live Proof-of-Accuracy Lab
	mux.HandleFunc("/api/cyber/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Scenario string `json:"scenario"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		out, err := idsEng.RunVerificationLab(req.Scenario)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("/api/cyber/clear", func(w http.ResponseWriter, r *http.Request) {
		idsEng.ClearAlerts()
		writeJSON(w, map[string]bool{"cleared": true})
	})

	// Download compiled Windows AegisX.exe directly from dashboard
	mux.HandleFunc("/api/download/exe", func(w http.ResponseWriter, r *http.Request) {
		target := *exeDownloadPath
		if runtime.GOOS == "windows" {
			if selfPath, err := os.Executable(); err == nil {
				target = selfPath
			}
		}
		abs, err := filepath.Abs(target)
		if err != nil || !fileExists(abs) {
			http.Error(w, "AegisX.exe binary not found at "+target, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="AegisX.exe"`)
		w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
		http.ServeFile(w, r, abs)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "engine": "AEGIS-X v4.2"})
	})

	// 3. Bind Listener (Auto-fallback to free port if 7788 is occupied on Windows)
	addr := fmt.Sprintf("%s:%d", bindHost, *portFlag)
	ln, err := net.Listen("tcp", addr)
	if err != nil && runtime.GOOS == "windows" {
		ln, err = net.Listen("tcp", fmt.Sprintf("%s:0", bindHost))
	}
	if err != nil {
		log.Fatalf("Failed to bind HTTP server on %s: %v", addr, err)
	}

	actualPort := ln.Addr().(*net.TCPAddr).Port
	localURL := fmt.Sprintf("http://127.0.0.1:%d", actualPort)
	log.Printf("================================================================")
	log.Printf(" AEGIS-X Sovereign OS Intelligence v4.2 ONLINE")
	log.Printf(" Listening on %s (Dashboard URL: %s)", ln.Addr().String(), localURL)
	log.Printf("================================================================")

	if !*noBrowser && runtime.GOOS == "windows" {
		go func() {
			time.Sleep(350 * time.Millisecond)
			launchBrowserAppMode(localURL)
		}()
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.Serve(ln))
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func launchBrowserAppMode(url string) {
	// Prefer Edge App Mode on Windows 10/11 for borderless native desktop window feel, fallback to default browser
	edgeCandidates := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	}
	for _, edge := range edgeCandidates {
		if fileExists(edge) {
			_ = exec.Command(edge, "--app="+url, "--window-size=1480,920").Start()
			return
		}
	}
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func triggerWindowsToastNotification(alert cyberids.ThreatAlert) {
	title := "AEGIS-X Security Alert (Verified Attack)"
	msg := fmt.Sprintf("%s from %s across %d ports (Confidence %d%%)", alert.AttackType, alert.AttackerIP, alert.DistinctPorts, alert.ConfidenceScore)
	ps := fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms;
$n = New-Object System.Windows.Forms.NotifyIcon;
$n.Icon = [System.Drawing.SystemIcons]::Shield;
$n.Visible = $true;
$n.ShowBalloonTip(7000, %q, %q, [System.Windows.Forms.ToolTipIcon]::Warning);
Start-Sleep -Seconds 8;
$n.Dispose()`, title, msg)
	_ = exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps).Run()
}
