# AEGIS-X Sovereign OS Intelligence (`AegisX.exe` v4.2)

**منظومة القيادة السيادية للويندوز — ملف تنفيذي مستقل واحد (`AegisX.exe`) بأيقونة احترافية مدمجة يشتغل مباشرة على المتصفح بوضع التطبيق (Edge/Chrome App Mode).**

---

## المعمارية الهندسية والفلسفة (Zero-Overhead & Zero-False-Positives)

1. **ملف Windows `.exe` حقيقي بأيقونة متعددة الدقات (`256px -> 16px`)**:
   - مبني بلغة **Go (Native x86_64 PE32+ GUI Subsystem)** بدون نافذة CMD سوداء مزعجة (`-H=windowsgui`)، ومطعم بمورد نظام أصلي (`.rsrc` عبر `windres`) يحتوي على أيقونة `aegisx.ico` الاحترافية وملف `DPI-Aware PerMonitorV2 Manifest` ومعلومات الإصدار الرسمية.
   - بمجرد النقر المزدوج على `AegisX.exe`، يشغّل المحرك الخادم المحلي فائق الخفة (`~2-6 MB RAM`) ويفتح المتصفح تلقائياً بواجهة تطبيق مكتبي متكاملة.

2. **ترسانة الدعم الفني الشامل والتحديث الذري (23 محركاً تنفيذياً حقيقياً)**:
   - **تحديث كل شيء بضغطة واحدة (Omni-Update)**: يدمج `Winget` لتحديث كافة البرامج بصمت + `Microsoft.Update.Session COM API / UsoClient` لتحديث الويندوز + `Update-MpSignature` لتواقيع الحماية + `PnPUtil` لإعادة فحص التعريفات.
   - **الإصلاح الذاتي (Self-Heal)**: فحص وإصلاح `DISM` و `SFC`، إصلاح تعليق تحديثات الويندوز، إصلاح `Print Spooler`، إنعاش خدمات الصوت والبلوتوث، إصلاح الأيقونات البيضاء التالفة وفهرس البحث، وفحص صحة أقراص `NVMe/SSD SMART` وتفعيل `TRIM`.
   - **تحليل النتائج الاستدلالي**: كل أداة تحلل رمز الخروج والمخرجات وتربطها بحالة الذاكرة والأقراص الحية لتقديم خطوات علاجية ذكية.

3. **العقل التشخيصي العبقري (Deterministic Causal OS Copilot)**:
   - محرك استدلال سببي محلي 100% (صفر تأخير سحابي، صفر هلوسة) يفهم وصف المشكلة بالعربية أو الإنجليزية ويربطها بقراءات المعالج والرام والأقراص والشبكة اللحظية ويقترح الأداة العلاجية الدقيقة بضغطة زر.

4. **محلل الشبكة والبكت المباشر بمستوى Wireshark بدون إجهاد الجهاز أو الراوتر**:
   - يكتشف تلقائياً وجود **Wireshark `tshark.exe`** أو **Windows Native `pktmon.exe` (ETW)** مع تعطيل الوضع الجشع (`-p` Non-Promiscuous) وتعطيل استعلامات DNS العكسية (`-n`) ليكون الحمل على الراوتر **0.0%**.
   - في حال عدم تثبيت Wireshark، ينتقل تلقائياً لمحرك **Kernel TCP/UDP Socket & Flow Dissector** الذي يربط كل جلسة وبورت بالعملية المالكة (`PID + ProcessName`) مع مشرح طبقات `L2/L3/L4/L7` وعارض `Hexadecimal Header`.

5. **الأمن السيبراني 24/7 بدقة رياضية (0% إيجابيات كاذبة — كشف فوري لهجمات Nmap)**:
   - **بوابة عدم الإزعاج الذكية (Zero-FP Immune Gate)**: تستثني تلقائياً محركات الذكاء الاصطناعي المحلية وأدوات المطورين (`Ollama :11434`, `LM Studio :1234`, `vLLM :8000`, `Gradio :7860`, `Open-WebUI :3000/:8080`, `ComfyUI :8188`) وحركة التصفح الطبيعية والاتصالات المفردة العابرة.
   - **كشف المسح والاستطلاع الحقيقي**: يرصد مسح `Nmap` الحقيقي (`-sT`, `-sS`, `-sV`, `-sX` Xmas Tree `FIN+PSH+URG`, `-sN` NULL, وبصمة `TCP Window=1024`) عبر مصائد استطلاع خفيفة (Canary Sensors) ونافذة ارتباط زمنية متعددة المنافذ، مع توليد قاعدة حظر `New-NetFirewallRule` فورية وإشعار سطح مكتب في ويندوز.

---

## طريقة التشغيل والبناء

### على نظام Windows 10 / 11 (x64):
1. حمّل ملف **`dist/AegisX.exe`** (أو من زر التحميل المباشر داخل لوحة التحكم).
2. شغّل `AegisX.exe` مباشرة (يفضل **Run as Administrator** عند الرغبة بتنفيذ أدوات `DISM / SFC / Winget / Firewall`).
3. ستفتح الواجهة الرسومية تلقائياً على المتصفح.

### إعادة البناء من المصدر (Cross-Compile):
```bash
# توليد الأيقونة متعددة الدقات وتجميع مورد الويندوز (.syso)
python3 scripts/generate_icon.py
cd build && x86_64-w64-mingw32-windres --use-temp-file --preprocessor=gcc \
  --preprocessor-arg=-E --preprocessor-arg=-xc --preprocessor-arg=-DRC_INVOKED \
  aegisx.rc -O coff -o ../cmd/aegis/rsrc_windows_amd64.syso && cd ..

# بناء ملف الويندوز التنفيذي المستقل AegisX.exe
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -H=windowsgui" -o dist/AegisX.exe ./cmd/aegis
```
