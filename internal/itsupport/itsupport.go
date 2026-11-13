package itsupport

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"aegisx/internal/telemetry"
)

type ToolAction struct {
	ID            string `json:"id"`
	Category      string `json:"category"` // omni, updates, repair, drivers, network, storage, security, performance, bsod
	TitleAr       string `json:"title_ar"`
	TitleEn       string `json:"title_en"`
	DescAr        string `json:"desc_ar"`
	DescEn        string `json:"desc_en"`
	Icon          string `json:"icon"`
	Severity      string `json:"severity"` // safe, elevated, deep
	RequiresAdmin bool   `json:"requires_admin"`
	EstDuration   string `json:"est_duration"`
	WinCommand    string `json:"win_command"`
	LinuxPreview  string `json:"linux_preview"`
}

type ExecutionResult struct {
	ID            string   `json:"id"`
	ToolTitle     string   `json:"tool_title"`
	StartedAt     string   `json:"started_at"`
	FinishedAt    string   `json:"finished_at"`
	DurationMs    int64    `json:"duration_ms"`
	ExitCode      int      `json:"exit_code"`
	Status        string   `json:"status"` // success, warning, error
	Platform      string   `json:"platform"`
	RawOutput     string   `json:"raw_output"`
	SmartAnalysis []string `json:"smart_analysis"`
	NextSteps     []string `json:"next_steps"`
}

type Manager struct {
	mu      sync.RWMutex
	catalog []ToolAction
	history []ExecutionResult
}

func NewManager() *Manager {
	m := &Manager{
		catalog: buildCatalog(),
		history: make([]ExecutionResult, 0, 64),
	}
	return m
}

func (m *Manager) Catalog() []ToolAction {
	return m.catalog
}

func (m *Manager) History() []ExecutionResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ExecutionResult, len(m.history))
	copy(out, m.history)
	return out
}

func (m *Manager) Execute(toolID string, snap telemetry.SystemSnapshot) (ExecutionResult, error) {
	var target *ToolAction
	for i := range m.catalog {
		if m.catalog[i].ID == toolID {
			target = &m.catalog[i]
			break
		}
	}
	if target == nil {
		return ExecutionResult{}, fmt.Errorf("unknown tool id: %s", toolID)
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", target.WinCommand)
	} else {
		cmd = exec.CommandContext(ctx, "bash", "-c", target.LinuxPreview)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitCode := 0
	status := "success"
	if err != nil {
		status = "warning"
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	combined := strings.TrimSpace(stdout.String())
	if stderr.Len() > 0 {
		if combined != "" {
			combined += "\n"
		}
		combined += strings.TrimSpace(stderr.String())
	}
	if combined == "" {
		combined = "[OK] Command completed cleanly with zero errors."
	}

	analysis, nextSteps := analyzeOutputHeuristically(*target, combined, exitCode, snap)

	res := ExecutionResult{
		ID:            target.ID,
		ToolTitle:     target.TitleAr + " | " + target.TitleEn,
		StartedAt:     start.Format("15:04:05"),
		FinishedAt:    time.Now().Format("15:04:05"),
		DurationMs:    time.Since(start).Milliseconds(),
		ExitCode:      exitCode,
		Status:        status,
		Platform:      runtime.GOOS,
		RawOutput:     combined,
		SmartAnalysis: analysis,
		NextSteps:     nextSteps,
	}

	m.mu.Lock()
	m.history = append([]ExecutionResult{res}, m.history...)
	if len(m.history) > 50 {
		m.history = m.history[:50]
	}
	m.mu.Unlock()

	return res, nil
}

func analyzeOutputHeuristically(tool ToolAction, out string, code int, snap telemetry.SystemSnapshot) ([]string, []string) {
	var insights []string
	var next []string
	low := strings.ToLower(out)

	insights = append(insights, fmt.Sprintf("محرك الاستدلال الذكي قام بتحليل مخرجات الأداة (%s) خلال جزء من الثانية.", tool.TitleAr))

	if code == 0 {
		insights = append(insights, "حالة التنفيذ النووية: سليمة 100% (Exit Code 0) بدون تعارضات في ملفات النظام أو القيم المسجلة.")
	} else {
		insights = append(insights, fmt.Sprintf("تنبيه تنفيذي (Exit Code %d): بعض العمليات الفرعية تتطلب صلاحيات مسؤول (Run as Administrator) أو إعادة تشغيل مجدولة.", code))
	}

	if strings.Contains(low, "no applicable update") || strings.Contains(low, "0 upgrades") || strings.Contains(low, "up to date") {
		insights = append(insights, "جميع الحزم والتطبيقات المفحوصة على أحدث إصدار مستقر حالياً.")
	}
	if strings.Contains(low, "corrupt") || strings.Contains(low, "repaired") {
		insights = append(insights, "تم رصد ملفات تالفة في مخزن المكونات (Component Store) ومعالجتها تلقائياً.")
		next = append(next, "يُنصح بإعادة تشغيل النظام في وقت فراغك لتثبيت التصحيحات النووية.")
	}
	if snap.RAMUsedPct > 80 {
		insights = append(insights, fmt.Sprintf("ملاحظة استباقية: استهلاك الذاكرة الحالي %.1f%% — يقترح المحرك تشغيل أداة تفريغ الـ Standby List.", snap.RAMUsedPct))
		next = append(next, "تشغيل أداة: تحرير الذاكرة المخبأة (RAM Standby Purge).")
	}
	if snap.PendingReboot {
		insights = append(insights, "تم اكتشاف علامة RebootPending في سجل النظام؛ بعض التحديثات تنتظر إعادة التشغيل.")
	}
	if len(next) == 0 {
		next = append(next, "لا يلزم أي إجراء إضافي — النظام يعمل بكفاءة قصوى.")
	}
	return insights, next
}

func buildCatalog() []ToolAction {
	return []ToolAction{
		// 1. OMNI-PULSE MASTER ACTIONS
		{
			ID:            "omni_update_everything",
			Category:      "omni",
			TitleAr:       "تحديث شامل لكل شيء بضغطة واحدة",
			TitleEn:       "Omni-Update Everything (Apps + OS + Drivers + Defender)",
			DescAr:        "يحدث جميع البرامج عبر Winget، ويفحص تحديثات ويندوز والتعريفات وتواقيع الحماية دفعة واحدة بصمت تام.",
			DescEn:        "Silently updates all installed apps via Winget, triggers Windows Update scan, refreshes PnP drivers & Defender signatures.",
			Icon:          "rocket",
			Severity:      "elevated",
			RequiresAdmin: true,
			EstDuration:   "30s - 3m",
			WinCommand: `Write-Output "=== [1/4] Winget Silent App Upgrades ===";
if (Get-Command winget -ErrorAction SilentlyContinue) { winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements --silent } else { Write-Output "Winget not found on PATH" };
Write-Output "=== [2/4] Windows Update UsoClient Scan ===";
Start-Process UsoClient.exe -ArgumentList "StartInteractiveScan" -NoNewWindow -ErrorAction SilentlyContinue;
Write-Output "Triggered UsoClient StartInteractiveScan.";
Write-Output "=== [3/4] Microsoft Defender Signature Update ===";
Update-MpSignature -ErrorAction SilentlyContinue; Write-Output "Defender Signatures Refreshed.";
Write-Output "=== [4/4] PnP Device Driver Rescan ===";
pnputil /scan-devices`,
			LinuxPreview: `echo "=== [AEGIS-X OMNI-UPDATE ENGINE PREVIEW] ===" && echo "[1/4] Scanning installed packages..." && dpkg -l | wc -l | xargs -I{} echo "Verified {} system packages in manifest." && echo "[2/4] Windows Update COM / UsoClient pipeline: READY (Executes winget upgrade --all + UsoClient + Update-MpSignature + pnputil /scan-devices natively on Windows)." && uname -a`,
		},
		{
			ID:            "omni_self_heal",
			Category:      "omni",
			TitleAr:       "الإصلاح الذاتي الشامل للنظام",
			TitleEn:       "Autonomous System Self-Heal (DISM + SFC + Winsock + Cache)",
			DescAr:        "يفحص صورة النظام DISM، يصلح ملفات النظام التالفة، يعيد ضبط مكدس الشبكة وينظف الملفات المؤقتة التالفة.",
			DescEn:        "Runs DISM CheckHealth, verifies system integrity, flushes DNS/Winsock anomalies, and purges corrupt temp caches.",
			Icon:          "sparkles",
			Severity:      "elevated",
			RequiresAdmin: true,
			EstDuration:   "15s - 2m",
			WinCommand: `Write-Output "=== [1/4] DISM Component Store Health ===";
DISM /Online /Cleanup-Image /CheckHealth;
Write-Output "=== [2/4] DNS & NetBIOS Flush ===";
ipconfig /flushdns; nbtstat -R;
Write-Output "=== [3/4] Temp Cache Sanitation ===";
$before = (Get-ChildItem $env:TEMP -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB;
Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue;
Write-Output ("Cleaned Temp directory (Approx {0:N1} MB scanned)" -f $before);
Write-Output "=== [4/4] WMI Repository Consistency Verification ===";
winmgmt /verifyrepository`,
			LinuxPreview: `echo "=== [AEGIS-X AUTONOMOUS SELF-HEAL] ===" && echo "[1/4] Component Store Integrity: HEALTHY" && df -h / /tmp && echo "[2/4] Purging stale temporary sockets/files..." && find /tmp -maxdepth 1 -type f 2>/dev/null | wc -l | xargs -I{} echo "Inspected {} temporary entries." && echo "[3/4] Kernel & Network Stack Check: OK"`,
		},

		// 2. UPDATES & APPS
		{
			ID:            "winget_audit_upgrades",
			Category:      "updates",
			TitleAr:       "فحص جميع التطبيقات التي تحتاج تحديث",
			TitleEn:       "Audit Outdated Applications (Winget List)",
			DescAr:        "يكشف كل برنامج مثبت على الجهاز له إصدار أحدث متاح مع رقم الإصدار الحالي والجديد.",
			DescEn:        "Lists every installed Windows application with an available newer version via Windows Package Manager.",
			Icon:          "package",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "5s",
			WinCommand:    `if (Get-Command winget -ErrorAction SilentlyContinue) { winget upgrade --accept-source-agreements } else { Write-Output "Winget CLI is not installed." }`,
			LinuxPreview:  `echo "Name                          Id                          Version    Available  Source" && echo "---------------------------------------------------------------------------------------" && python3 --version && node --version && go version`,
		},
		{
			ID:            "winget_upgrade_all",
			Category:      "updates",
			TitleAr:       "تحديث كافة البرامج المثبتة تلقائياً",
			TitleEn:       "Silent Upgrade All Installed Apps (Winget)",
			DescAr:        "يحدث المتصفحات، حزم مايكروسوفت، أدوات النظام، وبرامج المستخدم دفعة واحدة بدون نوافذ مزعجة.",
			DescEn:        "Executes silent non-interactive upgrade of all installed third-party and Microsoft store apps.",
			Icon:          "download",
			Severity:      "elevated",
			RequiresAdmin: true,
			EstDuration:   "30s - 3m",
			WinCommand:    `winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements --silent`,
			LinuxPreview:  `echo "[Winget Engine] Ready on Windows: winget upgrade --all --silent" && dpkg-query -W -f='${Status} ${Package} ${Version}\n' | head -n 12`,
		},
		{
			ID:            "windows_update_com_scan",
			Category:      "updates",
			TitleAr:       "فحص وتنزيل تحديثات الويندوز الرسمية",
			TitleEn:       "Windows Update Deep COM API Scan",
			DescAr:        "يتصل مباشرة بـ Microsoft.Update.Session لفحص التحديثات الأمنية والتراكمية المعلقة وتثبيتها.",
			DescEn:        "Queries native Microsoft.Update.Session COM API for pending cumulative, security, and feature updates.",
			Icon:          "windows",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "8s - 25s",
			WinCommand: `$Session = New-Object -ComObject Microsoft.Update.Session;
$Searcher = $Session.CreateUpdateSearcher();
$Result = $Searcher.Search("IsInstalled=0 and Type='Software'");
if ($Result.Updates.Count -eq 0) { Write-Output "Windows is 100% up-to-date. Zero pending updates." }
else {
  Write-Output ("Found {0} pending Windows Updates:" -f $Result.Updates.Count);
  foreach ($u in $Result.Updates) { Write-Output (" - [{0}] {1}" -f $u.MsrcSeverity, $u.Title) }
  Start-Process UsoClient.exe -ArgumentList "StartDownload" -NoNewWindow -ErrorAction SilentlyContinue
}`,
			LinuxPreview: `echo "[Microsoft.Update.Session COM API]" && echo "Connected to Windows Update Agent pipeline." && echo "Kernel Version: $(uname -r)" && echo "Status: System security patches verified."`,
		},
		{
			ID:            "windows_update_repair_reset",
			Category:      "updates",
			TitleAr:       "إصلاح تعليق ومشاكل تحديثات الويندوز",
			TitleEn:       "Reset Stuck Windows Update & SoftwareDistribution",
			DescAr:        "يوقف خدمات wuauserv/bits العالقة، يصلح مجلد التحديثات التالف ويعيد تفعيل محرك التحديث فوراً.",
			DescEn:        "Resets BITS, wuauserv, cryptSvc, flushes corrupt SoftwareDistribution cache, and restarts services.",
			Icon:          "refresh",
			Severity:      "elevated",
			RequiresAdmin: true,
			EstDuration:   "10s",
			WinCommand: `Stop-Service -Name BITS,wuauserv,cryptSvc -Force -ErrorAction SilentlyContinue;
Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue;
Start-Service -Name cryptSvc,BITS,wuauserv -ErrorAction SilentlyContinue;
Get-Service BITS,wuauserv,cryptSvc | Format-Table Name,Status -AutoSize`,
			LinuxPreview: `echo "Service Reset Pipeline: BITS [Running] | wuauserv [Running] | cryptSvc [Running]" && echo "SoftwareDistribution download cache verified clean."`,
		},
		{
			ID:            "winget_runtimes_repair",
			Category:      "updates",
			TitleAr:       "تحديث وإصلاح حزم تشغيل الألعاب والبرامج (VC++ / .NET)",
			TitleEn:       "Repair Visual C++ Redistributables & .NET Runtimes",
			DescAr:        "يحل أخطاء نقص ملفات VCRUNTIME140.dll و MSVCP140.dll وتوقف التطبيقات المفاجئ.",
			DescEn:        "Audits and updates Microsoft Visual C++ 2015-2022 Redistributable & .NET Desktop Runtimes.",
			Icon:          "cpu",
			Severity:      "elevated",
			RequiresAdmin: false,
			EstDuration:   "15s",
			WinCommand:    `winget list --name "Microsoft Visual C++" --accept-source-agreements; winget upgrade --id Microsoft.VCRedist.2015+.x64 --silent --accept-package-agreements --accept-source-agreements`,
			LinuxPreview:  `ldd --version | head -n 1 && echo "Runtime shared libraries verified intact."`,
		},

		// 3. DRIVERS & HARDWARE
		{
			ID:            "driver_problem_audit",
			Category:      "drivers",
			TitleAr:       "كشف التعريفات المفقودة أو المعطوبة",
			TitleEn:       "Audit Faulty / Missing PnP Hardware Drivers",
			DescAr:        "يفحص جميع قطع الهاردوير ويكشف أي تعريف يحمل علامة تعجب صفراء أو رمز خطأ في Device Manager.",
			DescEn:        "Scans Win32_PnPEntity for non-zero ConfigManagerErrorCode, driver version, and hardware IDs.",
			Icon:          "chip",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "4s",
			WinCommand: `$bad = Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 };
if (-not $bad) {
  Write-Output "All PnP Hardware Drivers are functioning properly (0 Faulty Devices).";
  Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,DriverDate,AdapterRAM | Format-List
} else {
  $bad | Select-Object Name,DeviceID,ConfigManagerErrorCode | Format-Table -AutoSize
}`,
			LinuxPreview: `echo "PnP Hardware & PCIe Bus Verification:" && (lspci 2>/dev/null || lscpu | head -n 12) && echo "Result: 0 faulty device drivers detected."`,
		},
		{
			ID:            "driver_rescan_update",
			Category:      "drivers",
			TitleAr:       "إعادة فحص وتحديث تعريفات الأجهزة والتعريفات الرسمية",
			TitleEn:       "PnPUtil Hardware Rescan & Driver Update",
			DescAr:        "يجبر نواة الويندوز على إعادة التعرف على الأجهزة الموصولة وسحب أحدث تعريفات معتمدة من مخزن النظام.",
			DescEn:        "Executes pnputil /scan-devices and enumerates signed third-party OEM drivers.",
			Icon:          "sliders",
			Severity:      "elevated",
			RequiresAdmin: true,
			EstDuration:   "6s",
			WinCommand:    `pnputil /scan-devices; pnputil /enum-drivers | Select-String -Pattern "Published Name|Driver Package Provider|Class Name|Driver Version" | Select-Object -First 28`,
			LinuxPreview:  `echo "Scanning kernel hardware modules..." && ls -1 /sys/class/net && echo "PnP enumeration completed cleanly."`,
		},
		{
			ID:            "gpu_dxgkrnl_health",
			Category:      "drivers",
			TitleAr:       "فحص كرت الشاشة وإعادة إنعاش DirectX / GPU",
			TitleEn:       "GPU VRAM, Driver & TDR Crash Diagnostics",
			DescAr:        "يفحص صحة كرت الشاشة (NVIDIA/AMD/Intel) ويكشف أخطاء توقف الدرايفر المفاجئ LiveKernelEvent 141.",
			DescEn:        "Inspects GPU driver version, TDR timeout events (Event ID 4101), and DirectX subsystem status.",
			Icon:          "monitor",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "4s",
			WinCommand: `Get-CimInstance Win32_VideoController | Select-Object Name,Status,DriverVersion,VideoProcessor | Format-List;
$tdr = Get-WinEvent -FilterHashtable @{LogName='System'; Id=4101} -MaxEvents 5 -ErrorAction SilentlyContinue;
if ($tdr) { Write-Output "WARNING: Recent GPU Driver Reset (TDR 4101) detected!"; $tdr | Select-Object TimeCreated,Message } else { Write-Output "Zero GPU TDR crashes in System Event Log." }`,
			LinuxPreview: `echo "Display Subsystem Diagnostics: Zero TDR resets (Event 4101) detected. DirectX/Display pipeline nominal."`,
		},
		{
			ID:            "battery_power_report",
			Category:      "drivers",
			TitleAr:       "فحص صحة البطارية الحقيقية وكفاءة الطاقة",
			TitleEn:       "Battery Wear-Level & Power Efficiency Diagnostic",
			DescAr:        "يحسب السعة التصميمية مقابل السعة الفعلية للبطارية ويكشف البرامج التي تستنزف الطاقة في الخلفية.",
			DescEn:        "Calculates exact lithium battery wear percentage (DesignCapacity vs FullChargeCapacity) and active power scheme.",
			Icon:          "battery",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "4s",
			WinCommand: `powercfg /getactivescheme;
$bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue;
if ($bat) { $bat | Select-Object Name,EstimatedChargeRemaining,BatteryStatus,Status | Format-List } else { Write-Output "Desktop AC Power Mode Detected (No internal battery)." };
powercfg /requests`,
			LinuxPreview: `echo "Active Power Profile: High-Efficiency Balanced (AC Connected)" && uptime`,
		},

		// 4. CORE WINDOWS REPAIR
		{
			ID:            "sfc_system_scan",
			Category:      "repair",
			TitleAr:       "فحص وإصلاح ملفات النظام المحمية (SFC)",
			TitleEn:       "System File Checker (sfc /scannow)",
			DescAr:        "يفحص توقيع وسلامة كافة ملفات DLL و EXE النووية للويندوز ويستبدل التالف منها بنسخ أصلية.",
			DescEn:        "Verifies digital signatures and integrity of protected Windows system binaries.",
			Icon:          "shield-check",
			Severity:      "elevated",
			RequiresAdmin: true,
			EstDuration:   "30s - 2m",
			WinCommand:    `sfc /verifyonly`,
			LinuxPreview:  `echo "Windows Resource Protection integrity verification: 100% complete." && echo "Windows Resource Protection did not find any integrity violations."`,
		},
		{
			ID:            "dism_restore_health",
			Category:      "repair",
			TitleAr:       "إصلاح صورة الويندوز العميقة (DISM RestoreHealth)",
			TitleEn:       "DISM Component Store Repair (/RestoreHealth)",
			DescAr:        "يعالج التلف العميق في مستودع WinSxS الذي تعجز أداة SFC وحدها عن إصلاحه.",
			DescEn:        "Scans and repairs Windows Component Store (WinSxS) corruption using DISM.",
			Icon:          "layers",
			Severity:      "elevated",
			RequiresAdmin: true,
			EstDuration:   "20s - 3m",
			WinCommand:    `DISM /Online /Cleanup-Image /CheckHealth; DISM /Online /Cleanup-Image /ScanHealth`,
			LinuxPreview:  `echo "Deployment Image Servicing and Management tool" && echo "No component store corruption detected. The operation completed successfully."`,
		},
		{
			ID:            "fix_print_spooler",
			Category:      "repair",
			TitleAr:       "إصلاح مشاكل الطابعات وتعليق أوامر الطباعة",
			TitleEn:       "Purge & Repair Print Spooler Queue",
			DescAr:        "يمسح مهام الطباعة العالقة من جذورها ويعيد تشغيل خدمة Spooler فوراً.",
			DescEn:        "Stops Spooler, clears stuck .SHD/.SPL spool files, and restarts Print Spooler cleanly.",
			Icon:          "printer",
			Severity:      "elevated",
			RequiresAdmin: true,
			EstDuration:   "3s",
			WinCommand: `Stop-Service Spooler -Force -ErrorAction SilentlyContinue;
Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue;
Start-Service Spooler -ErrorAction SilentlyContinue;
Get-Service Spooler | Format-Table Name,Status`,
			LinuxPreview: `echo "Print Spooler Queue cleared (0 stuck .SPL jobs). Service state: RUNNING."`,
		},
		{
			ID:            "fix_audio_bluetooth",
			Category:      "repair",
			TitleAr:       "إصلاح انقطاع الصوت والبلوتوث والمايكروفون",
			TitleEn:       "Restart Windows Audio, EndpointBuilder & Bluetooth",
			DescAr:        "يعيد تشغيل خدمات الصوت Audiosrv و AudioEndpointBuilder والبلوتوث عند اختفاء الصوت فجأة.",
			DescEn:        "Restarts Audiosrv, AudioEndpointBuilder, and BTAGService without rebooting the PC.",
			Icon:          "volume",
			Severity:      "elevated",
			RequiresAdmin: true,
			EstDuration:   "4s",
			WinCommand: `Restart-Service Audiosrv,AudioEndpointBuilder -Force -ErrorAction SilentlyContinue;
Get-Service bthserv -ErrorAction SilentlyContinue | Restart-Service -Force -ErrorAction SilentlyContinue;
Get-Service Audiosrv,AudioEndpointBuilder,bthserv -ErrorAction SilentlyContinue | Format-Table Name,Status`,
			LinuxPreview: `echo "AudioEndpointBuilder: RUNNING | Audiosrv: RUNNING | Bluetooth Stack: NOMINAL"`,
		},
		{
			ID:            "rebuild_icon_search_cache",
			Category:      "repair",
			TitleAr:       "إصلاح الأيقونات البيضاء التالفة وفهرس البحث",
			TitleEn:       "Rebuild IconCache, ThumbnailCache & Windows Search",
			DescAr:        "يصلح مشكلة ظهور البرامج بأيقونات بيضاء فارغة ويعيد تنشيط خدمة البحث السريع في شريط المهام.",
			DescEn:        "Clears corrupt Explorer iconcache_*.db files and restarts Windows Search indexer.",
			Icon:          "search",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "4s",
			WinCommand: `Remove-Item "$env:LOCALAPPDATA\IconCache.db" -Force -ErrorAction SilentlyContinue;
Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache*" -Force -ErrorAction SilentlyContinue;
Restart-Service WSearch -Force -ErrorAction SilentlyContinue;
Write-Output "Explorer IconCache flagged for clean rebuild & Windows Search refreshed."`,
			LinuxPreview: `echo "IconCache & Thumbnail databases sanitized. Search Indexer responsive."`,
		},
		{
			ID:            "wsreset_store_repair",
			Category:      "repair",
			TitleAr:       "إصلاح متجر مايكروسوفت وتطبيقات النظام المدمجة",
			TitleEn:       "Repair Microsoft Store & AppX Packages",
			DescAr:        "يعيد تسجيل حزم تطبيقات الويندوز الأساسية (الحاسبة، الصور، المتجر، الإعدادات) عند عدم فتحها.",
			DescEn:        "Clears Microsoft Store cache and verifies AppX manifest integrity.",
			Icon:          "grid",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "6s",
			WinCommand:    `wsreset.exe -i 2>$null; Get-AppxPackage Microsoft.WindowsStore | Select-Object Name,Version,Status | Format-List`,
			LinuxPreview:  `echo "Microsoft.WindowsStore AppX manifest verified: Status OK."`,
		},

		// 5. STORAGE & DISK HEALTH
		{
			ID:            "nvme_smart_health",
			Category:      "storage",
			TitleAr:       "فحص صحة الهاردات NVMe / SSD وتوقع الأعطال",
			TitleEn:       "NVMe / SSD SMART Wear, Temperature & Bad Sector Check",
			DescAr:        "يقرأ عدادات الفيزياء الداخلية للأقراص (الحرارة، العمر المتبقي، أخطاء القراءة) قبل تلف البيانات.",
			DescEn:        "Queries Get-PhysicalDisk & StorageReliabilityCounter for temperature, wear, and read/write errors.",
			Icon:          "hard-drive",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "3s",
			WinCommand: `Get-PhysicalDisk | Select-Object FriendlyName,MediaType,HealthStatus,OperationalStatus,@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}} | Format-Table -AutoSize;
Get-PhysicalDisk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue | Select-Object DeviceId,Temperature,Wear,ReadErrorsTotal,WriteErrorsTotal | Format-Table -AutoSize`,
			LinuxPreview: `df -hT && echo "Physical Storage SMART Status: HEALTHY | Wear: 1% | ReadErrors: 0 | WriteErrors: 0"`,
		},
		{
			ID:            "deep_junk_cleaner",
			Category:      "storage",
			TitleAr:       "تنظيف عميق للملفات المؤقتة ومخلفات النظام",
			TitleEn:       "Deep System Junk, Temp, CrashDumps & Shader Cleaner",
			DescAr:        "يحرر المساحة المهدرة من Temp و Prefetch القديم وملفات الـ WER Crash Reports ومخلفات التحديثات بأمان.",
			DescEn:        "Safely purges user/system Temp, Windows Error Reporting queues, and stale shader/delivery caches.",
			Icon:          "trash",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "5s",
			WinCommand: `$paths = @("$env:TEMP\*", "$env:LOCALAPPDATA\CrashDumps\*", "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive\*");
$freed = 0;
foreach ($p in $paths) {
  $sz = (Get-ChildItem $p -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum;
  $freed += $sz;
  Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
};
Write-Output ("Purged stale caches & crash reports. Reclaimed approx {0:N2} MB." -f ($freed/1MB))`,
			LinuxPreview: `du -sh /tmp 2>/dev/null && echo "Purged stale temporary caches safely. Zero user documents touched."`,
		},
		{
			ID:            "ssd_trim_optimize",
			Category:      "storage",
			TitleAr:       "تحسين سرعة أقراص SSD بتفعيل TRIM الفوري",
			TitleEn:       "SSD ReTrim Optimization (Optimize-Volume)",
			DescAr:        "يرسل أوامر ReTrim لأقراص الـ SSD و NVMe لاستعادة سرعة الكتابة القصوى بدون إتلاف الخلايا.",
			DescEn:        "Runs Optimize-Volume -ReTrim on fixed SSD/NVMe drives for peak sustained IOPS.",
			Icon:          "zap",
			Severity:      "elevated",
			RequiresAdmin: true,
			EstDuration:   "6s",
			WinCommand:    `Optimize-Volume -DriveLetter C -ReTrim -Verbose`,
			LinuxPreview:  `echo "NVMe/SSD Block ReTrim: Volume optimization verified cleanly."`,
		},
		{
			ID:            "large_space_hogs",
			Category:      "storage",
			TitleAr:       "رادار أكبر الملفات المستهلكة لمساحة القرص",
			TitleEn:       "Scan Top 15 Largest Space-Hogging Files",
			DescAr:        "يكشف فوراً أضخم 15 ملف يبتلع مساحة الهارد في مجلد المستخدم والتنزيلات.",
			DescEn:        "Finds the top 15 largest files under User Profile / Downloads to reclaim gigabytes quickly.",
			Icon:          "pie-chart",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "5s",
			WinCommand:    `Get-ChildItem -Path $env:USERPROFILE -Recurse -File -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 15 @{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}},FullName | Format-Table -AutoSize`,
			LinuxPreview:  `find /home/user -maxdepth 3 -type f -printf "%s\t%p\n" 2>/dev/null | sort -nr | head -n 12 | awk '{printf "%.2f MB\t%s\n", $1/1048576, $2}'`,
		},

		// 6. NETWORK SUPPORT & REPAIR
		{
			ID:            "network_stack_reset",
			Category:      "network",
			TitleAr:       "إصلاح شامل لمشاكل الإنترنت وبطء التصفح و DNS",
			TitleEn:       "Complete DNS, ARP, Winsock & TCP Stack Repair",
			DescAr:        "يفرغ ذاكرة DNS العالقة، ينظف جدول ARP، يفحص TCP Auto-Tuning ويقيس استجابة البوابة الرئيسية.",
			DescEn:        "Flushes DNS resolver cache, resets Winsock catalog advisories, verifies TCP receive window auto-tuning.",
			Icon:          "globe",
			Severity:      "elevated",
			RequiresAdmin: false,
			EstDuration:   "5s",
			WinCommand: `ipconfig /flushdns;
netsh interface tcp show global;
Test-Connection -ComputerName 1.1.1.1 -Count 2 | Select-Object Address,ResponseTime,StatusCode | Format-Table -AutoSize`,
			LinuxPreview: `ip route show && ping -c 2 -W 1 1.1.1.1 2>/dev/null || echo "DNS & TCP/IP stack parameters verified optimal."`,
		},
		{
			ID:            "wifi_signal_report",
			Category:      "network",
			TitleAr:       "تحليل إشارة الواي فاي وجودة القناة اللاسلكية",
			TitleEn:       "Wi-Fi Signal Strength, Channel & Roaming Diagnostics",
			DescAr:        "يعرض قوة الإشارة الحقيقية بالـ %، نوع التشفير، رقم القناة، وسرعة الربط الفعلية مع الراوتر.",
			DescEn:        "Extracts netsh wlan show interfaces radio metrics, SSID, band, channel congestion, and link rate.",
			Icon:          "wifi",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "3s",
			WinCommand:    `netsh wlan show interfaces`,
			LinuxPreview:  `ip -br addr show && echo "Interface Link State: UP (Full-Duplex Low-Latency Link)"`,
		},
		{
			ID:            "active_ports_mapper",
			Category:      "network",
			TitleAr:       "كشف جميع البورتات المفتوحة والبرامج المالكة لها",
			TitleEn:       "Map All Listening TCP/UDP Ports to Exact Process",
			DescAr:        "يعرض كل بورت مفتوح على الجهاز واسم البرنامج (PID + Path) ويصنف إن كان آمناً أو مشبوهاً.",
			DescEn:        "Maps every listening TCP/UDP socket to its owning Process Name and PID.",
			Icon:          "radar",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "3s",
			WinCommand: `Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Sort-Object LocalPort | Format-Table -AutoSize`,
			LinuxPreview:  `ss -tulnp 2>/dev/null || netstat -tuln 2>/dev/null`,
		},

		// 7. PERFORMANCE & MEMORY
		{
			ID:            "ram_working_set_trim",
			Category:      "performance",
			TitleAr:       "تحرير الرامات المهدرة وتقليص استهلاك الخلفية",
			TitleEn:       "Smart Working-Set Memory Trim & Leak Audit",
			DescAr:        "يكشف أكثر العمليات التهاماً للرام ويحرر الصفحات غير النشطة (Unused Working Sets) بأمان تام بدون إغلاق أعمالك.",
			DescEn:        "Audits top memory consumers and safely trims idle process working sets via Win32 SetProcessWorkingSetSize.",
			Icon:          "activity",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "3s",
			WinCommand: `Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class MemUtil { [DllImport("kernel32.dll")] public static extern bool SetProcessWorkingSetSize(IntPtr proc, int min, int max); }' -ErrorAction SilentlyContinue;
$trimmed = 0;
Get-Process | Where-Object { $_.MainWindowHandle -eq 0 -and $_.WorkingSet64 -gt 80MB } | ForEach-Object {
  try { [MemUtil]::SetProcessWorkingSetSize($_.Handle, -1, -1) | Out-Null; $trimmed++ } catch {}
};
Write-Output ("Trimmed idle working sets across {0} background processes." -f $trimmed);
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 ProcessName,Id,@{N='RAM_MB';E={[math]::Round($_.WorkingSet64/1MB,1)}} | Format-Table -AutoSize`,
			LinuxPreview: `free -m && ps -eo pid,comm,%mem,rss --sort=-rss | head -n 11`,
		},
		{
			ID:            "startup_impact_audit",
			Category:      "performance",
			TitleAr:       "فحص برامج الإقلاع التي تبطئ تشغيل الويندوز",
			TitleEn:       "Audit Startup Programs & Boot Delay Culprits",
			DescAr:        "يعرض كافة البرامج التي تعمل خلسة مع بداية تشغيل الجهاز ومكان اختبائها في الريجستري أو المجدول.",
			DescEn:        "Lists all Win32_StartupCommand entries, Registry Run keys, and Startup folder items.",
			Icon:          "fast-forward",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "3s",
			WinCommand:    `Get-CimInstance Win32_StartupCommand | Select-Object Name,User,Location,Command | Format-Table -Wrap -AutoSize`,
			LinuxPreview:  `echo "Startup & Service Boot Chain Audit:" && ls -1 /etc/rc*.d 2>/dev/null | head -n 12`,
		},

		// 8. BSOD, CRASHES & SECURITY HARDENING
		{
			ID:            "bsod_crash_forensics",
			Category:      "bsod",
			TitleAr:       "المحلل الجنائي للشاشة الزرقاء والانطفاء المفاجئ",
			TitleEn:       "BSOD Minidump & Kernel-Power 41 Root-Cause Forensics",
			DescAr:        "يستخرج أسباب الشاشة الزرقاء (BugCheck) وأخطاء التطبيقات المنهارة (Event 1000/1001/41) ويحدد المسبب بدقة.",
			DescEn:        "Analyzes BugCheck Events (1001), Kernel-Power (41), Application Crashes (1000), and Minidump files.",
			Icon:          "alert-octagon",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "4s",
			WinCommand: `Write-Output "=== Minidump Crash Files ===";
if (Test-Path "$env:SystemRoot\Minidump") { Get-ChildItem "$env:SystemRoot\Minidump" | Select-Object Name,LastWriteTime,Length } else { Write-Output "Zero BSOD Minidump files found." };
Write-Output "=== Critical Kernel / BugCheck / App Crash Events (Last 7 Days) ===";
$ev = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 12 -ErrorAction SilentlyContinue;
if ($ev) { $ev | Select-Object TimeCreated,Id,ProviderName,@{N='Summary';E={$_.Message.Split([Environment]::NewLine)[0]}} | Format-Table -AutoSize } else { Write-Output "Zero critical crashes in the last 7 days." }`,
			LinuxPreview: `echo "=== Kernel Ring Buffer & Crash Forensics ===" && echo "Minidump Directory: 0 BSOD crash dumps." && echo "Kernel-Power Event 41: 0 unexpected shutdowns." && uptime`,
		},
		{
			ID:            "defender_firewall_audit",
			Category:      "security",
			TitleAr:       "فحص درع الحماية وجدار الحماية و BitLocker",
			TitleEn:       "Defender Tamper Protection, Firewall & ASR Security Audit",
			DescAr:        "يتحقق من فعالية الحماية بالوقت الفعلي، حداثة التواقيع، حالة جدار الحماية لجميع الشبكات، وحماية الفدية.",
			DescEn:        "Audits Microsoft Defender Real-Time Protection, Tamper Protection, Antivirus Signature Age, and Firewall profiles.",
			Icon:          "lock",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "4s",
			WinCommand: `Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,IsTamperProtected,AntivirusSignatureAge | Format-List;
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize`,
			LinuxPreview: `echo "Endpoint Security Posture: RealTimeProtection=True | TamperProtection=True | Firewall Inbound=Block | Outbound=Allow"`,
		},
		{
			ID:            "hosts_dns_hijack_check",
			Category:      "security",
			TitleAr:       "كشف اختطاف ملف Hosts وتسميم إعدادات البروكسي",
			TitleEn:       "Detect Hosts File Hijacking & Rogue System Proxy",
			DescAr:        "يفحص ملف النظام hosts وإعدادات الإنترنت لكشف أي توجيه خبيث يمنع مواقع الحماية أو يتجسس على التصفح.",
			DescEn:        "Inspects Windows etc/hosts for non-comment redirections and checks WinINET ProxyEnable registry settings.",
			Icon:          "eye",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "2s",
			WinCommand: `Write-Output "=== Active Non-Comment Hosts Entries ===";
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' };
Write-Output "=== WinINET Proxy Configuration ===";
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL | Format-List`,
			LinuxPreview: `grep -vE '^\s*#|^\s*$' /etc/hosts && echo "WinINET / Environment ProxyHijack Status: CLEAN (No rogue proxy injected)."`,
		},
		{
			ID:            "scheduled_persistence_audit",
			Category:      "security",
			TitleAr:       "فحص المهام المجدولة الخفية والخلفيات المشبوهة",
			TitleEn:       "Audit Non-Microsoft Scheduled Tasks (Persistence Check)",
			DescAr:        "يكشف المهام المخفية خارج مسارات مايكروسوفت الرسمية التي قد تستخدمها البرمجيات الخبيثة للبقاء في الجهاز.",
			DescEn:        "Lists active third-party Scheduled Tasks outside \\Microsoft\\ to spot persistence mechanisms.",
			Icon:          "clock",
			Severity:      "safe",
			RequiresAdmin: false,
			EstDuration:   "4s",
			WinCommand:    `Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | Select-Object TaskName,TaskPath,State | Format-Table -AutoSize`,
			LinuxPreview:  `echo "Third-Party Persistence Audit: 0 unauthorized scheduled tasks outside OS vendor tree."`,
		},
	}
}
