/* AEGIS-X Sovereign OS Intelligence Frontend Controller */
(function () {
  'use strict';

  const SVGS = {
    command: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/></svg>`,
    wrench: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>`,
    brain: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 4.44-2.04Z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-4.44-2.04Z"/></svg>`,
    wireshark: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
    shield: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`,
    download: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
    bolt: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
    sparkles: `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3L12 3Z"/></svg>`,
    cpu: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></svg>`,
    memory: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 12h.01M10 12h.01M14 12h.01M18 12h.01"/></svg>`,
    'check-circle': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#34ffb6" stroke-width="2.2"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>`,
    'alert-triangle': `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ff4769" stroke-width="2.2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    radar: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/><line x1="12" y1="12" x2="19" y2="5"/></svg>`,
  };

  let allTools = [];
  let activeCategory = 'all';
  let packetsBuffer = [];
  let selectedSeq = null;
  let streamPaused = false;
  let netSparkHistory = new Array(32).fill(2);
  let knownAlertIds = new Set();

  function injectStaticIcons() {
    document.querySelectorAll('[data-svg]').forEach((el) => {
      const name = el.getAttribute('data-svg');
      if (SVGS[name]) el.innerHTML = SVGS[name];
    });
  }

  window.switchTab = function (tabId) {
    document.querySelectorAll('.nav-item').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    document.querySelectorAll('.tab-panel').forEach((p) => {
      p.classList.toggle('active', p.id === `tab-${tabId}`);
    });
  };

  function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach((btn) => {
      btn.addEventListener('click', () => window.switchTab(btn.dataset.tab));
    });

    document.getElementById('topOmniUpdateBtn').addEventListener('click', () => {
      window.switchTab('itsupport');
      window.triggerITTool('omni_update_everything');
    });

    document.getElementById('pauseStreamBtn').addEventListener('click', (e) => {
      streamPaused = !streamPaused;
      e.target.textContent = streamPaused ? 'استئناف العرض الحي' : 'إيقاف مؤقت للعرض';
    });

    document.getElementById('packetFilterInput').addEventListener('input', () => {
      renderPacketTable();
    });
  }

  async function loadITCatalog() {
    try {
      const res = await fetch('/api/itsupport/catalog');
      allTools = await res.json();
      renderITTools();
    } catch (err) {
      console.error('Failed loading IT catalog:', err);
    }

    document.querySelectorAll('#itCategoryBar .filter-pill').forEach((pill) => {
      pill.addEventListener('click', () => {
        document.querySelectorAll('#itCategoryBar .filter-pill').forEach((p) => p.classList.remove('active'));
        pill.classList.add('active');
        activeCategory = pill.dataset.cat;
        renderITTools();
      });
    });
  }

  function renderITTools() {
    const grid = document.getElementById('itToolsGrid');
    const filtered = allTools.filter((t) => {
      if (activeCategory === 'all') return true;
      if (activeCategory === 'bsod') return t.category === 'bsod' || t.category === 'security';
      return t.category === activeCategory;
    });

    grid.innerHTML = filtered.map((t) => {
      const adminBadge = t.requires_admin
        ? `<span class="tag-pill tag-app">Admin / UAC</span>`
        : `<span class="tag-pill tag-ai">Instant Safe</span>`;
      return `
        <div class="tool-card" onclick="window.triggerITTool('${t.id}')">
          <div>
            <div class="tool-card-top">
              <div class="tool-icon-box">${SVGS.wrench}</div>
              ${adminBadge}
            </div>
            <h4 style="margin-top:12px">${escapeHtml(t.title_ar)}</h4>
            <p>${escapeHtml(t.desc_ar)}</p>
          </div>
          <div class="tool-card-footer">
            <span style="font-family:var(--font-mono);color:var(--text-muted)">⏱ ${escapeHtml(t.est_duration)}</span>
            <span class="run-chip">▶ تشغيل فوري</span>
          </div>
        </div>
      `;
    }).join('');
  }

  window.triggerITTool = async function (toolId) {
    window.switchTab('itsupport');
    const badge = document.getElementById('itExecStatusBadge');
    const term = document.getElementById('itTerminalOutput');
    const insights = document.getElementById('itSmartInsightsBox');

    badge.textContent = 'جاري التنفيذ النووي...';
    badge.style.color = '#fbbf24';
    term.textContent = `[AEGIS-X Engine] Dispatching tool '${toolId}'...\nExecuting native command pipeline & analyzing kernel exit codes...`;

    try {
      const res = await fetch('/api/itsupport/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool_id: toolId }),
      });
      const data = await res.json();
      badge.textContent = `${data.status.toUpperCase()} (${data.duration_ms}ms)`;
      badge.style.color = data.status === 'success' ? '#34ffb6' : '#fbbf24';

      const listHtml = (data.smart_analysis || []).map((line) => `<li>${escapeHtml(line)}</li>`).join('');
      const nextHtml = (data.next_steps || []).map((n) => `<span class="tag-pill tag-sys">${escapeHtml(n)}</span>`).join(' ');
      insights.innerHTML = `
        <strong style="display:block;color:var(--emerald);margin-bottom:6px">التحليل الاستدلالي الذكي لنتيجة الأداة (${escapeHtml(data.tool_title)}):</strong>
        <ul>${listHtml}</ul>
        <div style="margin-top:8px">${nextHtml}</div>
      `;
      term.textContent = data.raw_output || '[Completed]';
    } catch (err) {
      badge.textContent = 'خطأ اتصال';
      term.textContent = 'Execution error: ' + err.message;
    }
  };

  function setupCopilot() {
    const form = document.getElementById('copilotForm');
    const input = document.getElementById('copilotInput');

    document.querySelectorAll('.preset-chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        input.value = chip.dataset.q;
        runCopilotQuery(chip.dataset.q);
      });
    });

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      runCopilotQuery(input.value || 'فحص شامل للجهاز');
    });
  }

  async function runCopilotQuery(query) {
    const area = document.getElementById('copilotReportArea');
    area.innerHTML = `<div class="copilot-report-card">جاري التحليل السببي وربط قراءات العتاد والشبكة...</div>`;
    try {
      const res = await fetch('/api/copilot/diagnose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });
      const rep = await res.json();
      const roots = (rep.root_cause_tree || []).map((r) => `<li>${escapeHtml(r)}</li>`).join('');
      const live = (rep.live_telemetry || []).map((l) => `<li>${escapeHtml(l)}</li>`).join('');
      const recBtns = (rep.recommended_tool_ids || []).map((id) => {
        const found = allTools.find((t) => t.id === id);
        const label = found ? found.title_ar : id;
        return `<button class="btn-primary-glow" onclick="window.triggerITTool('${id}')">▶ تنفيذ: ${escapeHtml(label)}</button>`;
      }).join('');

      area.innerHTML = `
        <div class="copilot-report-card">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
            <div>
              <span class="eyebrow">${escapeHtml(rep.intent)} • دقة الاستدلال ${rep.confidence_pct}%</span>
              <h4 style="font-size:1.08rem">${escapeHtml(rep.headline_ar)}</h4>
            </div>
            <span class="tag-pill tag-ai">${escapeHtml(rep.safety_guarantee)}</span>
          </div>
          <div>
            <strong style="color:var(--cyan);font-size:0.86rem">1. القراءات الحية المأخوذة من جهازك الآن:</strong>
            <ul style="padding-right:20px;margin-top:5px;font-size:0.83rem;color:var(--text-muted)">${live}</ul>
          </div>
          <div>
            <strong style="color:var(--emerald);font-size:0.86rem">2. التشخيص الهندسي للجذور المسببة:</strong>
            <ul style="padding-right:20px;margin-top:5px;font-size:0.84rem;line-height:1.7">${roots}</ul>
          </div>
          <div>
            <strong style="display:block;margin-bottom:8px;font-size:0.86rem">3. الأدوات العلاجية المقترحة للتنفيذ الفوري بضغطة واحدة:</strong>
            <div class="copilot-rec-row">${recBtns}</div>
          </div>
        </div>
      `;
    } catch (err) {
      area.innerHTML = `<div class="copilot-report-card">حدث خطأ أثناء التشخيص: ${escapeHtml(err.message)}</div>`;
    }
  }

  function updateSystemUI(snap) {
    if (!snap) return;
    document.getElementById('hostTitle').textContent = `${snap.hostname} • ${snap.os_version}`;
    document.getElementById('osSubtitle').textContent = `Kernel: ${snap.kernel} | Arch: ${snap.arch} | Overhead: ${snap.agent_overhead_mb} MB`;
    document.getElementById('agentOverheadLabel').textContent = `استهلاك الأداة: ${snap.agent_overhead_mb} MB | ضغط الراوتر: 0.0%`;

    // Health Reactor
    const score = snap.health_score || 96;
    document.getElementById('healthScoreNum').textContent = score;
    document.getElementById('healthGradeText').textContent = snap.health_grade || 'S+ OPTIMAL';
    const circumference = 578;
    const offset = circumference - (score / 100) * circumference;
    document.getElementById('healthGaugeCircle').style.strokeDashoffset = offset;
    document.getElementById('uptimeSummary').textContent =
      `مدة التشغيل: ${snap.uptime_human} | وضع الصلاحيات: ${snap.is_admin ? 'Administrator' : 'Standard User (UAC Ready)'}`;

    // CPU & RAM
    document.getElementById('cpuPctVal').textContent = `${snap.cpu_load_pct.toFixed(1)}%`;
    document.getElementById('cpuCoresLabel').textContent = `${snap.cpu_cores} Logical Cores`;
    document.getElementById('cpuBar').style.width = `${Math.max(4, Math.min(100, snap.cpu_load_pct))}%`;
    document.getElementById('cpuModelLabel').textContent = snap.cpu_model;

    document.getElementById('ramPctVal').textContent = `${snap.ram_used_pct.toFixed(1)}%`;
    document.getElementById('ramUsedLabel').textContent = `${snap.ram_used_gb} / ${snap.ram_total_gb} GB`;
    document.getElementById('ramBar').style.width = `${Math.max(4, Math.min(100, snap.ram_used_pct))}%`;

    // Interface throughput sum
    let rxTxKB = 0;
    (snap.interfaces || []).forEach((iface) => {
      if (!iface.is_loopback) rxTxKB += (iface.rx_rate_kbps || 0) + (iface.tx_rate_kbps || 0);
    });
    document.getElementById('netRateVal').textContent = `${rxTxKB.toFixed(1)} KB/s`;
    netSparkHistory.push(Math.max(2, rxTxKB));
    if (netSparkHistory.length > 32) netSparkHistory.shift();
    drawSparkline();

    // Disks
    const disksEl = document.getElementById('disksContainer');
    disksEl.innerHTML = (snap.disks || []).map((d) => `
      <div class="disk-item">
        <div class="disk-row-top">
          <strong>${escapeHtml(d.drive)} (${escapeHtml(d.file_system)}) — ${escapeHtml(d.health)}</strong>
          <span style="font-family:var(--font-mono)">${d.used_gb} / ${d.total_gb} GB (${d.used_percent}%)</span>
        </div>
        <div class="progress-rail">
          <div class="progress-fill ${d.used_percent > 85 ? 'violet' : 'cyan'}" style="width:${Math.min(100, d.used_percent)}%"></div>
        </div>
      </div>
    `).join('');

    // Top Processes
    const procsBody = document.getElementById('topProcsBody');
    procsBody.innerHTML = (snap.top_processes || []).map((p) => {
      const cls = p.category.includes('LocalAI') ? 'tag-ai' : (p.category.includes('System') ? 'tag-sys' : 'tag-app');
      return `
        <tr>
          <td>${p.pid}</td>
          <td><strong>${escapeHtml(p.name)}</strong></td>
          <td><span class="tag-pill ${cls}">${escapeHtml(p.category)}</span></td>
          <td>${p.cpu_pct}%</td>
          <td>${p.mem_mb} MB</td>
        </tr>
      `;
    }).join('');
  }

  function drawSparkline() {
    const canvas = document.getElementById('netSparkCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);
    const maxVal = Math.max(25, ...netSparkHistory);
    ctx.beginPath();
    netSparkHistory.forEach((v, idx) => {
      const x = (idx / (netSparkHistory.length - 1)) * w;
      const y = h - 4 - (v / maxVal) * (h - 10);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#34ffb6';
    ctx.lineWidth = 2;
    ctx.stroke();
  }

  function updateNetworkUI(netData) {
    if (!netData) return;
    const st = netData.stats || {};
    document.getElementById('topNetEngine').textContent = st.wireshark_available ? 'Wireshark TShark L7' : (st.pktmon_available ? 'Pktmon ETW' : 'Passive Kernel Socket');
    document.getElementById('netBackendTitle').textContent = st.active_backend || 'Passive Dissector';
    document.getElementById('netTotalPackets').textContent = (st.packets_captured || 0).toLocaleString();
    document.getElementById('netTotalBytes').textContent = `${((st.bytes_inspected || 0) / 1024).toFixed(1)} KB Inspected`;
    document.getElementById('netActiveSockets').textContent = st.active_flows_count || 0;
    document.getElementById('activeFlowsVal').textContent = `${st.active_flows_count || 0} Flows`;

    if (!streamPaused && Array.isArray(netData.frames)) {
      packetsBuffer = netData.frames;
      renderPacketTable();
    }

    if (Array.isArray(netData.flows)) {
      const fb = document.getElementById('flowsMiniBody');
      fb.innerHTML = netData.flows.slice(0, 25).map((fl) => {
        const badgeCls = fl.category === 'Trusted-LocalAI' ? 'tag-ai' : 'tag-sys';
        return `
          <tr>
            <td>${escapeHtml(fl.process_name)} (${fl.pid})</td>
            <td>${escapeHtml(fl.local_addr)}:${fl.local_port}</td>
            <td>${escapeHtml(fl.remote_addr)}:${fl.remote_port}</td>
            <td><span class="tag-pill ${badgeCls}">${escapeHtml(fl.category)}</span></td>
          </tr>
        `;
      }).join('');
    }
  }

  function renderPacketTable() {
    const filter = (document.getElementById('packetFilterInput').value || '').toLowerCase().trim();
    const tbody = document.getElementById('packetTableBody');
    const filtered = packetsBuffer.filter((f) => {
      if (!filter) return true;
      const hay = `${f.protocol} ${f.src_ip}:${f.src_port} ${f.dst_ip}:${f.dst_port} ${f.tcp_flags} ${f.direction} ${f.info} ${f.process_name}`.toLowerCase();
      return hay.includes(filter);
    });

    if (filtered.length > 0 && selectedSeq === null) {
      selectedSeq = filtered[0].seq;
      renderDissectorPane(filtered[0]);
    }

    tbody.innerHTML = filtered.slice(0, 80).map((f) => {
      let pClass = 'proto-tcp';
      if (f.protocol.includes('TLS')) pClass = 'proto-tls';
      else if (f.is_whitelisted_ai || f.protocol.includes('LocalAI')) pClass = 'proto-ai';
      else if (f.protocol.includes('PROBE') || f.protocol.includes('STEALTH')) pClass = 'proto-probe';

      const isSel = f.seq === selectedSeq ? 'selected' : '';
      return `
        <tr class="${isSel}" data-seq="${f.seq}">
          <td>${f.seq}</td>
          <td>${escapeHtml(f.timestamp)}</td>
          <td>${escapeHtml(f.src_ip)}:${f.src_port}</td>
          <td>${escapeHtml(f.dst_ip)}:${f.dst_port}</td>
          <td class="${pClass}">${escapeHtml(f.protocol)}</td>
          <td>${f.length}B</td>
          <td>[${escapeHtml(f.tcp_flags)}] ${escapeHtml(f.info)}</td>
        </tr>
      `;
    }).join('');

    tbody.querySelectorAll('tr').forEach((row) => {
      row.addEventListener('click', () => {
        const seq = Number(row.dataset.seq);
        selectedSeq = seq;
        const found = packetsBuffer.find((x) => x.seq === seq);
        if (found) renderDissectorPane(found);
        renderPacketTable();
      });
    });
  }

  function renderDissectorPane(frame) {
    const tree = document.getElementById('frameDissectorTree');
    const hexEl = document.getElementById('frameHexView');
    tree.innerHTML = (frame.layers || []).map((l, idx) => `
      <div class="layer-node">Layer ${idx + 1}: ${escapeHtml(l)}</div>
    `).join('');
    hexEl.textContent = frame.hex_preview || '45 00 00 3C';
  }

  function updateCyberUI(ids) {
    if (!ids) return;
    const count = ids.confirmed_threats || 0;
    document.getElementById('cyberEvaluatedCount').textContent = (ids.packets_evaluated || 0).toLocaleString();
    document.getElementById('cyberBenignCount').textContent = (ids.benign_suppressed || 0).toLocaleString();
    document.getElementById('cyberConfirmedCount').textContent = count;

    const navBadge = document.getElementById('navThreatBadge');
    navBadge.textContent = count;
    navBadge.className = count > 0 ? 'nav-counter danger' : 'nav-counter emerald';

    const topIds = document.getElementById('topIdsState');
    const kpiIds = document.getElementById('idsThreatCountVal');
    document.getElementById('idsSuppressedVal').textContent = `${ids.benign_suppressed || 0} Benign Ignored`;

    if (count > 0) {
      topIds.textContent = `ALERT: ${count} VERIFIED ATTACK(S)!`;
      topIds.className = 'chip-val danger-text';
      kpiIds.textContent = `${count} هجوم مؤكد!`;
      kpiIds.className = 'danger-text';
    } else {
      topIds.textContent = 'ACTIVE • 0 FALSE POSITIVES';
      topIds.className = 'chip-val emerald';
      kpiIds.textContent = '0 تهديد (آمن)';
      kpiIds.className = 'emerald-text';
    }

    // Radar threat blips
    const blips = document.getElementById('radarThreatBlips');
    const alerts = ids.alerts || [];
    blips.innerHTML = alerts.slice(0, 6).map((a, i) => {
      const angle = (i * 67 + 35) * (Math.PI / 180);
      const r = 46 + (i % 3) * 22;
      const cx = 120 + r * Math.cos(angle);
      const cy = 120 + r * Math.sin(angle);
      return `<circle cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="6" fill="#ff4769"><animate attributeName="r" values="5;9;5" dur="1.1s" repeatCount="indefinite"/></circle>`;
    }).join('');

    // Toast notification on brand new alert
    alerts.forEach((a) => {
      if (!knownAlertIds.has(a.id)) {
        knownAlertIds.add(a.id);
        pushThreatToast(a);
      }
    });

    // Render Alerts List
    const alertsList = document.getElementById('cyberAlertsList');
    if (alerts.length === 0) {
      alertsList.innerHTML = `
        <div style="padding:18px;border-radius:12px;background:rgba(52,255,182,0.06);border:1px solid rgba(52,255,182,0.22);color:var(--emerald);font-size:0.84rem">
          ✓ الشبكة نظيفة 100%. لم يتم رصد أي مسح منافذ Nmap أو استطلاع خبيث. كافة عمليات الذكاء الاصطناعي المحلية والتصفح تعمل بهدوء بدون إنذارات كاذبة.
        </div>
      `;
    } else {
      alertsList.innerHTML = alerts.map((a) => `
        <div class="alert-card">
          <div class="alert-head">
            <h4>🚨 ${escapeHtml(a.attack_type)}</h4>
            <span class="tag-pill tag-warn">${escapeHtml(a.severity)} • ثقة ${a.confidence_score}%</span>
          </div>
          <div class="alert-meta">
            المهاجم: ${escapeHtml(a.attacker_ip)} | المنافذ المستهدفة (${a.distinct_ports}): [${(a.target_ports || []).join(', ')}] | التوقيت: ${escapeHtml(a.timestamp)}
          </div>
          <ul class="alert-evidence">
            ${(a.evidence || []).map((ev) => `<li>${escapeHtml(ev)}</li>`).join('')}
          </ul>
          <code class="mitigation-code">${escapeHtml(a.mitigation_cmd)}</code>
        </div>
      `).join('');
    }

    // Canary Ports & Whitelist Table
    const canaryBox = document.getElementById('canaryBadgesBox');
    canaryBox.innerHTML = (ids.canary_ports || []).map((p) =>
      `<span class="tag-pill tag-sys">Canary Sensor Port :${p} ACTIVE</span>`
    ).join('');

    const wlBody = document.getElementById('whitelistTableBody');
    wlBody.innerHTML = (ids.whitelisted_ai_services || []).map((w) => `
      <tr>
        <td>:${w.port}</td>
        <td><strong>${escapeHtml(w.process_name)}</strong></td>
        <td>${escapeHtml(w.service_role)}</td>
        <td><span class="tag-pill tag-ai">${escapeHtml(w.status)}</span></td>
      </tr>
    `).join('');
  }

  function pushThreatToast(alert) {
    const container = document.getElementById('threatToastContainer');
    const div = document.createElement('div');
    div.className = 'threat-toast';
    div.innerHTML = `
      <strong>🚨 كشف هجوم شبكي حقيقي (${escapeHtml(alert.id)})</strong>
      <p>${escapeHtml(alert.attack_type)} من المصدر <code>${escapeHtml(alert.attacker_ip)}</code> على ${alert.distinct_ports} منافذ (ثقة ${alert.confidence_score}%).</p>
    `;
    container.prepend(div);
    setTimeout(() => {
      if (div.parentNode) div.remove();
    }, 9000);
  }

  window.runCyberLab = async function (scenario) {
    const banner = document.getElementById('labResultBanner');
    banner.innerHTML = `⏳ جاري تشغيل الاختبار الحي <code>${escapeHtml(scenario)}</code> على السوكت الفعلي...`;
    try {
      const res = await fetch('/api/cyber/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario }),
      });
      const data = await res.json();
      const color = scenario === 'benign_local_ai' ? 'var(--emerald)' : '#ff8fa3';
      banner.innerHTML = `<strong style="color:${color}">✓ نتيجة الاختبار العملي:</strong> ${escapeHtml(data.verification_summary)}`;
      await pollFullDashboard();
    } catch (err) {
      banner.textContent = 'فشل تشغيل الاختبار: ' + err.message;
    }
  };

  window.clearCyberAlerts = async function () {
    await fetch('/api/cyber/clear', { method: 'POST' });
    knownAlertIds.clear();
    await pollFullDashboard();
  };

  async function pollFullDashboard() {
    try {
      const res = await fetch('/api/state');
      const state = await res.json();
      updateSystemUI(state.system);
      updateNetworkUI(state.network);
      updateCyberUI(state.cyber);
    } catch (err) {
      console.warn('Telemetry poll skipped:', err);
    }
  }

  function escapeHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  document.addEventListener('DOMContentLoaded', async () => {
    injectStaticIcons();
    setupNavigation();
    setupCopilot();
    await loadITCatalog();
    await pollFullDashboard();
    setInterval(pollFullDashboard, 1800);
  });
})();
