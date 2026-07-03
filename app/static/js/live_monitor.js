let sessionId = null;
let pollTimer = null;
let alertSince = 0;
let totalAlertsShown = 0;
let liveConfig = {};
let captureStoppable = false;
let actionModalInst = null;
const actionBusy = { capture: false, suricata: false, ml: false, rules: false };

const MODAL_ICONS = {
    success: '<i class="bi bi-check-circle text-success"></i>',
    danger: '<i class="bi bi-exclamation-octagon text-danger"></i>',
    warning: '<i class="bi bi-exclamation-triangle text-warning"></i>',
    info: '<i class="bi bi-info-circle text-info"></i>',
};

function initActionModal() {
    const el = document.getElementById('actionModal');
    if (el) actionModalInst = new bootstrap.Modal(el);
}

function showNotice(title, message, variant = 'danger') {
    return new Promise((resolve) => {
        const titleEl = document.getElementById('actionModalTitle');
        const bodyEl = document.getElementById('actionModalBody');
        const cancelBtn = document.getElementById('actionModalCancel');
        const confirmBtn = document.getElementById('actionModalConfirm');
        if (!titleEl || !bodyEl || !confirmBtn || !actionModalInst) {
            window.alert(`${title}\n\n${message}`);
            resolve();
            return;
        }
        titleEl.innerHTML = `${MODAL_ICONS[variant] || MODAL_ICONS.info} ${esc(title)}`;
        bodyEl.textContent = message;
        cancelBtn?.classList.add('d-none');
        confirmBtn.textContent = 'OK';
        confirmBtn.className = variant === 'danger' ? 'btn btn-danger' : variant === 'success' ? 'btn btn-success' : 'btn btn-primary';
        const onConfirm = () => {
            confirmBtn.removeEventListener('click', onConfirm);
            actionModalInst.hide();
            resolve();
        };
        confirmBtn.addEventListener('click', onConfirm);
        actionModalInst.show();
    });
}

function confirmAction(title, message, variant = 'warning') {
    return new Promise((resolve) => {
        const titleEl = document.getElementById('actionModalTitle');
        const bodyEl = document.getElementById('actionModalBody');
        const cancelBtn = document.getElementById('actionModalCancel');
        const confirmBtn = document.getElementById('actionModalConfirm');
        if (!titleEl || !bodyEl || !confirmBtn || !actionModalInst) {
            resolve(window.confirm(`${title}\n\n${message}`));
            return;
        }
        titleEl.innerHTML = `${MODAL_ICONS[variant] || MODAL_ICONS.warning} ${esc(title)}`;
        bodyEl.textContent = message;
        cancelBtn?.classList.remove('d-none');
        confirmBtn.textContent = 'Confirm';
        confirmBtn.className = 'btn btn-danger';
        const cleanup = (result) => {
            confirmBtn.removeEventListener('click', onConfirm);
            cancelBtn?.removeEventListener('click', onCancel);
            actionModalInst.hide();
            resolve(result);
        };
        const onConfirm = () => cleanup(true);
        const onCancel = () => cleanup(false);
        confirmBtn.addEventListener('click', onConfirm);
        cancelBtn?.addEventListener('click', onCancel);
        actionModalInst.show();
    });
}

async function apiAction({ url, method = 'POST', body, busyKey, btn, busyLabel, confirmTitle, confirmMessage, successTitle, successMessage, errorTitle, showError = true }) {
    if (busyKey && actionBusy[busyKey]) return null;
    if (confirmTitle) {
        const ok = await confirmAction(confirmTitle, confirmMessage || '', 'warning');
        if (!ok) return null;
    }
    if (busyKey) actionBusy[busyKey] = true;
    const originalHtml = btn?.innerHTML;
    if (btn) {
        btn.disabled = true;
        if (busyLabel) btn.innerHTML = busyLabel;
    }
    try {
        const res = await fetch(url, {
            method,
            headers: body != null ? { 'Content-Type': 'application/json' } : undefined,
            body: body != null ? JSON.stringify(body) : undefined,
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            if (showError) {
                await showNotice(errorTitle || 'Action failed', data.error || data.message || `Request failed (${res.status})`, 'danger');
            }
            return { ok: false, data, status: res.status };
        }
        if (successMessage) {
            await showNotice(successTitle || 'Success', successMessage, 'success');
        }
        return { ok: true, data };
    } catch {
        if (showError) {
            await showNotice(errorTitle || 'Network error', 'Could not reach the server. Check that the app is running.', 'danger');
        }
        return { ok: false, data: null };
    } finally {
        if (busyKey) actionBusy[busyKey] = false;
        if (btn && originalHtml) btn.innerHTML = originalHtml;
    }
}

const els = {
    evePath: document.getElementById('evePath'),
    iface: document.getElementById('iface'),
    btnStart: document.getElementById('btnStart'),
    btnStop: document.getElementById('btnStop'),
    btnUseDefault: document.getElementById('btnUseDefault'),
    liveStatus: document.getElementById('liveStatus'),
    livePulse: document.getElementById('livePulse'),
    sessionId: document.getElementById('sessionId'),
    flowCount: document.getElementById('flowCount'),
    alertCount: document.getElementById('alertCount'),
    alertFeed: document.getElementById('alertFeed'),
    feedCount: document.getElementById('feedCount'),
    pathFeedback: document.getElementById('pathFeedback'),
};

function setStatus(text, badgeClass, running = false) {
    if (!els.liveStatus) return;
    els.liveStatus.textContent = text;
    els.liveStatus.className = `badge ${badgeClass}`;
    if (els.livePulse) {
        els.livePulse.classList.toggle('running', running);
    }
}

function updateFeedCount() {
    if (els.feedCount) {
        els.feedCount.textContent = `${totalAlertsShown} alert${totalAlertsShown === 1 ? '' : 's'}`;
    }
}

function showPathFeedback(message, type = 'muted') {
    if (!els.pathFeedback) return;
    els.pathFeedback.className = `small text-${type}`;
    els.pathFeedback.textContent = message;
    els.pathFeedback.classList.remove('d-none');
}

async function loadConfig() {
    const root = document.getElementById('live-monitor-data');
    if (root) {
        try {
            liveConfig = JSON.parse(root.textContent || '{}');
        } catch {
            liveConfig = {};
        }
    }

    try {
        const res = await fetch('/api/live/config');
        if (res.ok) {
            liveConfig = { ...liveConfig, ...(await res.json()) };
        }
    } catch {
        /* use template defaults */
    }

    if (liveConfig.default_eve_path && els.evePath && !els.evePath.value.trim()) {
        els.evePath.value = liveConfig.default_eve_path;
    }

    if (liveConfig.active_session) {
        resumeSession(liveConfig.active_session);
    }
}

function resumeSession(status) {
    sessionId = status.session_id;
    if (els.sessionId) {
        els.sessionId.textContent = `${sessionId.slice(0, 8)}…`;
        els.sessionId.title = sessionId;
    }
    if (els.flowCount) els.flowCount.textContent = (status.total_flows || 0).toLocaleString();
    if (els.alertCount) els.alertCount.textContent = (status.total_findings || 0).toLocaleString();
    if (els.btnStart) els.btnStart.disabled = true;
    if (els.btnStop) els.btnStop.disabled = false;
    setStatus('running', 'bg-success', true);
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(pollLive, 2000);
}

async function startMonitor() {
    const evePath = (els.evePath?.value || '').trim();
    const captureIface = (cap.iface?.value || sur.iface?.value || '').trim();
    const captureMode = (cap.mode?.value || liveConfig.capture_mode || 'suricata').trim();

    if (!evePath && captureMode !== 'tcpdump') {
        // Will try auto-start capture below; still need interface.
        if (!captureIface) {
            showPathFeedback('Pick a network interface under Traffic Capture first.', 'warning');
            document.getElementById('section-capture')?.scrollIntoView({ behavior: 'smooth' });
            cap.iface?.focus();
            return;
        }
    }

    showPathFeedback('Starting ML live monitor…', 'info');
    if (els.btnStart) {
        els.btnStart.disabled = true;
        els.btnStart.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Starting…';
    }

    const body = {
        eve_path: evePath || undefined,
        interface: captureIface || (els.iface?.value || '').trim() || undefined,
        mode: captureMode,
        auto_start_capture: captureMode === 'suricata',
    };

    try {
        const res = await fetch('/api/live/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();

        if (!res.ok) {
            const msg = data.hint ? `${data.error} — ${data.hint}` : (data.error || 'Failed to start live monitor');
            showPathFeedback(msg, 'danger');
            await showNotice('ML monitor failed', msg, 'danger');
            if (els.btnStart) {
                els.btnStart.disabled = false;
                els.btnStart.innerHTML = '<i class="bi bi-play-fill"></i> Start ML Live Monitor';
            }
            return;
        }

        if (data.mode === 'tcpdump') {
            showPathFeedback(data.note || 'tcpdump capture started — chunks appear under Analyses.', 'success');
            refreshCapture();
            if (els.btnStart) {
                els.btnStart.disabled = false;
                els.btnStart.innerHTML = '<i class="bi bi-play-fill"></i> Start ML Live Monitor';
            }
            document.getElementById('section-capture')?.scrollIntoView({ behavior: 'smooth' });
            return;
        }

        sessionId = data.session_id;
        if (data.eve_path && els.evePath) els.evePath.value = data.eve_path;
        if (els.sessionId) {
            els.sessionId.textContent = `${sessionId.slice(0, 8)}…`;
            els.sessionId.title = sessionId;
        }
        if (els.btnStop) els.btnStop.disabled = false;
        if (els.btnStart) {
            els.btnStart.innerHTML = '<i class="bi bi-play-fill"></i> Start ML Live Monitor';
        }
        setStatus('running', 'bg-success', true);
        showPathFeedback(`Monitoring: ${data.eve_path}${data.capture_started ? ' (capture auto-started)' : ''}`, 'success');
        alertSince = 0;
        totalAlertsShown = 0;
        updateFeedCount();
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(pollLive, 2000);
        pollLive();
        refreshCapture();
        document.getElementById('section-alerts')?.scrollIntoView({ behavior: 'smooth' });
    } catch {
        showPathFeedback('Network error — could not start monitor.', 'danger');
        if (els.btnStart) {
            els.btnStart.disabled = false;
            els.btnStart.innerHTML = '<i class="bi bi-play-fill"></i> Start ML Live Monitor';
        }
    }
}

async function stopMonitor() {
    if (!sessionId || actionBusy.ml) return;
    const ok = await confirmAction('Stop ML live monitor?', 'Scoring will stop for this session.', 'warning');
    if (!ok) return;
    actionBusy.ml = true;
    if (els.btnStop) els.btnStop.disabled = true;
    try {
        await fetch('/api/live/stop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId }),
        });
        if (pollTimer) clearInterval(pollTimer);
        if (els.btnStart) els.btnStart.disabled = false;
        setStatus('stopped', 'bg-secondary', false);
        showPathFeedback('Monitor stopped.', 'muted');
        await showNotice('Monitor stopped', 'ML live scoring has been stopped.', 'success');
    } catch {
        await showNotice('Stop failed', 'Could not stop the live monitor.', 'danger');
        if (els.btnStop) els.btnStop.disabled = false;
    } finally {
        actionBusy.ml = false;
    }
}

async function pollLive() {
    if (!sessionId) return;
    const [statusRes, alertsRes] = await Promise.all([
        fetch(`/api/live/status?session_id=${sessionId}`),
        fetch(`/api/live/alerts?session_id=${sessionId}&since=${alertSince}`),
    ]);
    if (statusRes.ok) {
        const status = await statusRes.json();
        if (els.flowCount) els.flowCount.textContent = (status.total_flows || 0).toLocaleString();
        if (els.alertCount) els.alertCount.textContent = (status.total_findings || 0).toLocaleString();
        if (status.running) setStatus('running', 'bg-success', true);
        else if (sessionId) setStatus('stopped', 'bg-secondary', false);
    }
    if (alertsRes.ok) {
        const { alerts } = await alertsRes.json();
        if (alerts.length) {
            renderAlerts(alerts);
            alertSince = Math.max(...alerts.map((a) => a.timestamp));
        }
    }
}

function esc(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
}

function severityMeta(severity) {
    const map = {
        critical: { badge: 'danger', label: 'CRITICAL' },
        high: { badge: 'warning', label: 'HIGH' },
        medium: { badge: 'info', label: 'MEDIUM' },
        info: { badge: 'info', label: 'INFO' },
    };
    return map[severity] || map.info;
}

function renderAlerts(alerts) {
    const empty = els.alertFeed?.querySelector('.empty-state');
    if (empty) els.alertFeed.innerHTML = '';

    alerts.slice().reverse().forEach((a) => {
        const meta = severityMeta(a.severity);
        const isSuricata = a.type === 'suricata';
        const sourceBadge = isSuricata
            ? '<span class="badge bg-warning text-dark"><i class="bi bi-shield-exclamation"></i> SURICATA</span>'
            : '<span class="badge bg-info text-dark"><i class="bi bi-cpu"></i> ML</span>';
        const detailBadge = isSuricata
            ? `<span class="badge text-bg-light border">${esc(a.category || 'signature')}</span>`
            : `<span class="badge text-bg-light border">score ${a.anomaly_score}</span>`;
        const detailText = isSuricata ? (a.signature || a.explanation) : a.explanation;
        const item = document.createElement('div');
        item.className = `list-group-item alert-feed-item severity-${a.severity || 'info'}`;
        item.innerHTML = `
            <div class="d-flex justify-content-between align-items-start gap-2 mb-1">
                <span class="badge bg-${meta.badge}">${meta.label}</span>
                ${sourceBadge}
                ${detailBadge}
                <small class="text-muted ms-auto">${new Date(a.timestamp * 1000).toLocaleTimeString()}</small>
            </div>
            <div class="font-monospace small">
                ${esc(a.src_ip)}:${a.src_port || '*'} → ${esc(a.dst_ip)}:${a.dst_port || '*'}
                <span class="text-muted">(${esc(a.protocol) || '?'})</span>
            </div>
            ${detailText ? `<small class="text-muted d-block mt-1">${esc(detailText)}</small>` : ''}
            ${a.finding_id ? `<button class="btn btn-outline-info btn-sm mt-2 btn-investigate" data-finding-id="${esc(a.finding_id)}">
                <i class="bi bi-search"></i> Investigate</button>` : ''}
        `;
        const invBtn = item.querySelector('.btn-investigate');
        if (invBtn) invBtn.addEventListener('click', () => investigateFinding(invBtn.dataset.findingId));
        els.alertFeed?.prepend(item);
        totalAlertsShown += 1;
    });
    updateFeedCount();
}

if (els.btnStart) els.btnStart.addEventListener('click', startMonitor);
if (els.btnStop) els.btnStop.addEventListener('click', stopMonitor);
if (els.btnUseDefault) {
    els.btnUseDefault.addEventListener('click', () => {
        if (liveConfig.default_eve_path && els.evePath) {
            els.evePath.value = liveConfig.default_eve_path;
            showPathFeedback('Reset to .env default path.', 'info');
        }
    });
}

// ---------------------------------------------------------------------------
// Suricata management panel
// ---------------------------------------------------------------------------
const sur = {
    badge: document.getElementById('suricataStatusBadge'),
    installed: document.getElementById('surInstalled'),
    running: document.getElementById('surRunning'),
    version: document.getElementById('surVersion'),
    eps: document.getElementById('surEps'),
    eveSize: document.getElementById('surEveSize'),
    eveAge: document.getElementById('surEveAge'),
    iface: document.getElementById('surIface'),
    btnStart: document.getElementById('btnSuricataStart'),
    btnStop: document.getElementById('btnSuricataStop'),
    btnUseEve: document.getElementById('btnUseEve'),
    btnRefresh: document.getElementById('btnSuricataRefresh'),
    feedback: document.getElementById('suricataFeedback'),
    rules: document.getElementById('surRules'),
    rulesPath: document.getElementById('surRulesPath'),
    rulesStatus: document.getElementById('surRulesStatus'),
    btnRulesSave: document.getElementById('btnRulesSave'),
    btnRulesReload: document.getElementById('btnRulesReload'),
};

let suricataEvePath = '';
let suricataTimer = null;

function surFeedback(message, type = 'muted') {
    if (!sur.feedback) return;
    sur.feedback.className = `small mt-2 text-${type}`;
    sur.feedback.textContent = message;
    sur.feedback.classList.remove('d-none');
}

function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
    return `${(bytes / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

async function refreshSuricata() {
    if (!sur.badge) return;
    try {
        const res = await fetch('/api/suricata/status');
        if (!res.ok) throw new Error();
        const s = await res.json();

        sur.badge.textContent = s.running ? 'running' : s.installed ? 'stopped' : 'not installed';
        sur.badge.className = `badge ${s.running ? 'bg-success' : s.installed ? 'bg-secondary' : 'bg-danger'}`;
        if (sur.installed) sur.installed.textContent = s.installed ? 'yes' : 'no';
        if (sur.running) {
            sur.running.textContent = s.running
                ? (s.managed ? `running (pid ${s.managed_pid}, managed)` : `running (pid ${s.pids[0] || '?'})`)
                : 'stopped';
        }
        if (sur.version) {
            sur.version.textContent = s.version || '—';
            sur.version.title = s.version || '';
        }
        const eve = s.eve || {};
        if (sur.eps) sur.eps.textContent = eve.events_per_second != null ? eve.events_per_second : '—';
        if (sur.eveSize) sur.eveSize.textContent = eve.exists ? formatBytes(eve.size_bytes) : 'missing';
        if (sur.eveAge) {
            sur.eveAge.textContent = eve.age_seconds != null ? `${Math.round(eve.age_seconds)}s ago` : '—';
        }
        suricataEvePath = eve.path || '';
        if (sur.btnUseEve) sur.btnUseEve.disabled = !eve.exists;
        if (sur.btnStart) sur.btnStart.disabled = !s.installed || s.running;
        if (sur.btnStop) sur.btnStop.disabled = !s.managed;
        if (sur.rulesPath && s.custom_rules?.path) {
            sur.rulesPath.textContent = s.custom_rules.path.split(/[\\/]/).pop();
            sur.rulesPath.title = s.custom_rules.path;
        }
    } catch {
        sur.badge.textContent = 'unavailable';
        sur.badge.className = 'badge bg-danger';
    }
}

async function loadInterfaces() {
    await populateInterfaceSelect(sur.iface, liveConfig.capture_interface);
    await populateInterfaceSelect(cap.iface, liveConfig.capture_interface);
}

async function populateInterfaceSelect(selectEl, preferred) {
    if (!selectEl) return;
    const placeholder = preferred
        ? `(default: ${preferred})`
        : '(select interface)';
    selectEl.innerHTML = `<option value="">${placeholder}</option>`;
    try {
        const res = await fetch('/api/suricata/interfaces');
        if (!res.ok) return;
        const { interfaces } = await res.json();
        if (!interfaces.length) {
            selectEl.innerHTML = '<option value="">No interfaces found — set CAPTURE_INTERFACE in .env</option>';
            return;
        }
        let defaultName = (preferred || '').trim();
        interfaces.forEach((i) => {
            const opt = document.createElement('option');
            opt.value = i.name;
            const addr = i.addresses?.length ? ` — ${i.addresses[0]}` : '';
            opt.textContent = `${i.name}${addr}${i.up === false ? ' (down)' : ''}`;
            selectEl.appendChild(opt);
        });
        if (!defaultName) {
            const up = interfaces.find((i) => i.up !== false);
            defaultName = up?.name || interfaces[0].name;
        }
        if (defaultName && [...selectEl.options].some((o) => o.value === defaultName)) {
            selectEl.value = defaultName;
        }
    } catch {
        selectEl.innerHTML = '<option value="">Could not load interfaces</option>';
    }
}

function selectedInterface() {
    return (cap.iface?.value || sur.iface?.value || liveConfig.capture_interface || '').trim();
}

async function startSuricata() {
    const iface = selectedInterface();
    if (!iface) {
        capFeedback('Pick a capture interface first.', 'warning');
        await showNotice('Interface required', 'Pick a network interface before starting Suricata.', 'warning');
        return;
    }
    surFeedback('Starting Suricata…', 'info');
    const result = await apiAction({
        url: '/api/suricata/start',
        body: { interface: iface },
        busyKey: 'suricata',
        btn: sur.btnStart,
        busyLabel: '<span class="spinner-border spinner-border-sm"></span> Starting…',
        errorTitle: 'Suricata start failed',
    });
    if (result?.ok) {
        const data = result.data;
        surFeedback(`Suricata started (pid ${data.pid}). EVE output: ${data.eve_hint}`, 'success');
        if (data.eve_hint) suricataEvePath = data.eve_hint;
        if (data.eve_hint && els.evePath) els.evePath.value = data.eve_hint;
        await showNotice('Suricata started', `Process running (pid ${data.pid}).`, 'success');
    }
    refreshSuricata();
    refreshCapture();
}

async function stopSuricata() {
    surFeedback('Stopping Suricata…', 'info');
    const result = await apiAction({
        url: '/api/suricata/stop',
        busyKey: 'suricata',
        btn: sur.btnStop,
        busyLabel: '<span class="spinner-border spinner-border-sm"></span> Stopping…',
        confirmTitle: 'Stop Suricata?',
        confirmMessage: 'This stops the Suricata process started from packetEye.',
        errorTitle: 'Suricata stop failed',
    });
    if (result?.ok) {
        surFeedback('Suricata stopped.', 'muted');
        await showNotice('Suricata stopped', 'The managed Suricata process has been stopped.', 'success');
    } else if (result) {
        surFeedback(result.data?.error || 'Failed to stop Suricata.', 'danger');
    }
    refreshSuricata();
    refreshCapture();
}

async function loadRules() {
    if (!sur.rules) return;
    try {
        const res = await fetch('/api/suricata/rules');
        const data = await res.json();
        if (res.ok) {
            sur.rules.value = data.content || '';
            if (sur.rulesStatus) sur.rulesStatus.textContent = data.exists ? '' : '(new file)';
        } else if (sur.rulesStatus) {
            sur.rulesStatus.textContent = data.error || '';
        }
    } catch {
        /* leave editor empty */
    }
}

async function saveRules() {
    if (!sur.rules || actionBusy.rules) return;
    if (sur.rulesStatus) sur.rulesStatus.textContent = 'saving…';
    actionBusy.rules = true;
    if (sur.btnRulesSave) sur.btnRulesSave.disabled = true;
    try {
        const res = await fetch('/api/suricata/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: sur.rules.value }),
        });
        const data = await res.json();
        if (!res.ok) {
            if (sur.rulesStatus) sur.rulesStatus.textContent = data.error || 'save failed';
            surFeedback(data.error || 'Failed to save rules.', 'danger');
            await showNotice('Save rules failed', data.error || 'Could not save rules.', 'danger');
        } else {
            if (sur.rulesStatus) sur.rulesStatus.textContent = data.reloaded ? 'saved + reloaded' : 'saved';
            const msg = data.hint || 'Rules saved successfully.';
            surFeedback(msg, data.hint ? 'warning' : 'success');
            await showNotice('Rules saved', msg, data.hint ? 'warning' : 'success');
        }
    } catch {
        surFeedback('Network error — could not save rules.', 'danger');
        await showNotice('Save rules failed', 'Network error — could not save rules.', 'danger');
    } finally {
        actionBusy.rules = false;
        if (sur.btnRulesSave) sur.btnRulesSave.disabled = false;
    }
}

if (sur.btnStart) sur.btnStart.addEventListener('click', startSuricata);
if (sur.btnStop) sur.btnStop.addEventListener('click', stopSuricata);
if (sur.btnRefresh) sur.btnRefresh.addEventListener('click', refreshSuricata);
if (sur.btnRulesSave) sur.btnRulesSave.addEventListener('click', saveRules);
if (sur.btnRulesReload) sur.btnRulesReload.addEventListener('click', loadRules);
if (sur.btnUseEve) {
    sur.btnUseEve.addEventListener('click', () => {
        if (suricataEvePath && els.evePath) {
            els.evePath.value = suricataEvePath;
            showPathFeedback('Using Suricata EVE output path.', 'info');
        }
    });
}

// ---------------------------------------------------------------------------
// Capture control (Suricata / tcpdump) — start/stop from the browser
// ---------------------------------------------------------------------------
const cap = {
    badge: document.getElementById('captureBadge'),
    mode: document.getElementById('captureMode'),
    iface: document.getElementById('captureIface'),
    btnStart: document.getElementById('btnCaptureStart'),
    btnStop: document.getElementById('btnCaptureStop'),
    btnRefresh: document.getElementById('btnCaptureRefresh'),
    feedback: document.getElementById('captureFeedback'),
    capMode: document.getElementById('capMode'),
    capPid: document.getElementById('capPid'),
    capChunks: document.getElementById('capChunks'),
    capWatcher: document.getElementById('capWatcher'),
};
let captureTimer = null;

function capFeedback(message, type = 'muted') {
    if (!cap.feedback) return;
    cap.feedback.className = `small mt-2 text-${type}`;
    cap.feedback.textContent = message;
    cap.feedback.classList.remove('d-none');
}

async function refreshCapture() {
    if (!cap.badge) return;
    try {
        const res = await fetch('/api/capture/status');
        if (!res.ok) throw new Error();
        const s = await res.json();
        captureStoppable = Boolean(s.running && s.stoppable);

        if (s.external_suricata && !s.running) {
            cap.badge.textContent = 'external suricata';
            cap.badge.className = 'badge bg-warning text-dark';
            capFeedback(
                'A Suricata process is running outside packetEye. Stop it from the host before starting capture here.',
                'warning',
            );
        } else if (s.running) {
            cap.badge.textContent = `capturing (${s.mode})`;
            cap.badge.className = 'badge bg-success';
        } else {
            cap.badge.textContent = 'stopped';
            cap.badge.className = 'badge bg-secondary';
        }

        if (cap.capMode) cap.capMode.textContent = s.mode || '—';
        if (cap.capPid) cap.capPid.textContent = s.pid ?? '—';
        if (cap.capChunks) cap.capChunks.textContent = s.tcpdump?.chunks?.count ?? '—';
        if (cap.capWatcher) {
            const w = s.chunk_watcher || {};
            cap.capWatcher.textContent = w.running ? `on (${w.chunks_processed || 0} done)` : 'off';
        }
        if (cap.btnStart) cap.btnStart.disabled = s.running || !liveConfig.enabled || actionBusy.capture;
        if (cap.btnStop) cap.btnStop.disabled = !captureStoppable || actionBusy.capture;
        const evePath = s.suricata?.eve?.path;
        if (evePath && els.evePath && !els.evePath.value.trim()) {
            els.evePath.value = evePath;
        }
        if (s.running && s.suricata?.eve?.exists && els.evePath) {
            els.evePath.value = s.suricata.eve.path || els.evePath.value;
        }
    } catch {
        cap.badge.textContent = 'unavailable';
        cap.badge.className = 'badge bg-danger';
    }
}

async function startCapture() {
    if (actionBusy.capture) return;
    const iface = selectedInterface();
    if (!iface) {
        capFeedback('Pick a network interface before starting capture.', 'warning');
        await showNotice('Interface required', 'Pick a network interface before starting capture.', 'warning');
        cap.iface?.focus();
        return;
    }
    if (cap.iface && cap.iface.value !== iface) cap.iface.value = iface;
    if (sur.iface && !sur.iface.value) sur.iface.value = iface;
    if (els.iface && !els.iface.value.trim()) els.iface.value = iface;

    capFeedback('Starting capture…', 'info');
    const result = await apiAction({
        url: '/api/capture/start',
        body: { mode: cap.mode?.value, interface: iface },
        busyKey: 'capture',
        btn: cap.btnStart,
        busyLabel: '<span class="spinner-border spinner-border-sm"></span> Starting…',
        errorTitle: 'Capture start failed',
    });
    if (result?.ok) {
        const data = result.data;
        capFeedback(`Capture running (${data.mode}, pid ${data.pid}).`
            + (data.note ? ` ${data.note}` : ''), 'success');
        if (data.eve_hint && els.evePath) els.evePath.value = data.eve_hint;
        await showNotice('Capture started', `Traffic capture is running (${data.mode}, pid ${data.pid}).`, 'success');
    }
    refreshCapture();
}

async function stopCapture() {
    if (actionBusy.capture) return;
    if (!captureStoppable) {
        await showNotice(
            'Nothing to stop',
            'No packetEye-managed capture is running. If Suricata runs externally, stop it from the host.',
            'warning',
        );
        refreshCapture();
        return;
    }
    capFeedback('Stopping capture…', 'info');
    const result = await apiAction({
        url: '/api/capture/stop',
        busyKey: 'capture',
        btn: cap.btnStop,
        busyLabel: '<span class="spinner-border spinner-border-sm"></span> Stopping…',
        confirmTitle: 'Stop traffic capture?',
        confirmMessage: 'This stops the capture process started from packetEye.',
        showError: false,
    });
    if (result?.ok) {
        capFeedback('Capture stopped.', 'muted');
        await showNotice('Capture stopped', 'Traffic capture has been stopped.', 'success');
    } else if (result?.data?.cleared_stale_state) {
        capFeedback('Cleared stale capture state.', 'warning');
        await showNotice(
            'Capture state reset',
            result.data.error || 'Stale capture state was cleared. You can start capture again.',
            'warning',
        );
    } else if (result) {
        capFeedback(result.data?.error || 'Failed to stop capture.', 'danger');
        await showNotice('Capture stop failed', result.data?.error || 'Failed to stop capture.', 'danger');
    }
    refreshCapture();
}

function populateCaptureInterfaces() {
    /* handled by loadInterfaces() */
}

function initSectionNav() {
    const nav = document.getElementById('liveSectionNav');
    if (!nav) return;
    const links = [...nav.querySelectorAll('.nav-link')];
    const sections = links
        .map((a) => document.querySelector(a.getAttribute('href')))
        .filter(Boolean);

    links.forEach((link) => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const target = document.querySelector(link.getAttribute('href'));
            target?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            links.forEach((l) => l.classList.remove('active'));
            link.classList.add('active');
        });
    });

    if (!sections.length || !('IntersectionObserver' in window)) return;
    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) return;
                const id = `#${entry.target.id}`;
                links.forEach((l) => l.classList.toggle('active', l.getAttribute('href') === id));
            });
        },
        { rootMargin: '-30% 0px -55% 0px', threshold: 0.01 },
    );
    sections.forEach((s) => observer.observe(s));
}

// Keep capture + suricata interface selects in sync
if (cap.iface) {
    cap.iface.addEventListener('change', () => {
        if (sur.iface && cap.iface.value) sur.iface.value = cap.iface.value;
        if (els.iface && cap.iface.value) els.iface.value = cap.iface.value;
    });
}
if (sur.iface) {
    sur.iface.addEventListener('change', () => {
        if (cap.iface && sur.iface.value) cap.iface.value = sur.iface.value;
        if (els.iface && sur.iface.value) els.iface.value = sur.iface.value;
    });
}

if (cap.btnStart) cap.btnStart.addEventListener('click', startCapture);
if (cap.btnStop) cap.btnStop.addEventListener('click', stopCapture);
if (cap.btnRefresh) cap.btnRefresh.addEventListener('click', refreshCapture);

// ---------------------------------------------------------------------------
// OSINT investigation offcanvas
// ---------------------------------------------------------------------------
const investigateBody = document.getElementById('investigateBody');
const investigatePanelEl = document.getElementById('investigatePanel');
const investigatePanel = investigatePanelEl ? new bootstrap.Offcanvas(investigatePanelEl) : null;

function renderVerdict(entry) {
    if (entry.results?.skipped) return `<span class="text-muted">${esc(entry.results.skipped)}</span>`;
    const mal = entry.is_malicious;
    const badge = mal
        ? `<span class="badge bg-danger">malicious</span>`
        : `<span class="badge bg-success">clean</span>`;
    const conf = entry.confidence != null ? ` <span class="text-muted">conf ${entry.confidence}</span>` : '';
    const vt = entry.results?.virustotal;
    const abuse = entry.results?.abuseipdb;
    const parts = [];
    if (vt && vt.malicious != null) parts.push(`VT: ${vt.malicious} malicious`);
    if (abuse && abuse.abuseConfidenceScore != null) parts.push(`AbuseIPDB: ${abuse.abuseConfidenceScore}%`);
    if (entry.results?.geo?.country) parts.push(`Geo: ${esc(entry.results.geo.country)}`);
    return `${badge}${conf}${parts.length ? `<div class="small text-muted mt-1">${esc(parts.join(' · '))}</div>` : ''}`;
}

function renderInvestigation(inv) {
    if (!investigateBody) return;
    if (!inv || inv.status === 'none') {
        investigateBody.innerHTML = '<div class="empty-state"><i class="bi bi-hourglass"></i> Not investigated yet.</div>';
        return;
    }
    if (inv.status === 'running') {
        investigateBody.innerHTML = '<div class="text-info"><span class="spinner-border spinner-border-sm"></span> Running OSINT lookups…</div>';
        return;
    }
    if (inv.status === 'failed') {
        investigateBody.innerHTML = `<div class="text-danger">Investigation failed: ${esc(inv.error || 'unknown error')}</div>`;
        return;
    }
    const targets = inv.targets || {};
    const keys = Object.keys(targets);
    if (!keys.length) {
        investigateBody.innerHTML = `<div class="text-muted">${esc(inv.note || 'No public IPs or domains to investigate.')}</div>`;
        return;
    }
    investigateBody.innerHTML = keys.map((k) => `
        <div class="card mb-2">
            <div class="card-body py-2">
                <div class="d-flex justify-content-between align-items-center">
                    <code class="text-info">${esc(k)}</code>
                    <span class="badge text-bg-light border">${esc(targets[k].type)}</span>
                </div>
                <div class="mt-2">${renderVerdict(targets[k])}</div>
            </div>
        </div>
    `).join('');
}

async function investigateFinding(findingId) {
    if (!findingId || !investigatePanel) return;
    investigatePanel.show();
    renderInvestigation({ status: 'running' });
    try {
        await fetch(`/api/investigate/finding/${findingId}`, { method: 'POST' });
    } catch {
        renderInvestigation({ status: 'failed', error: 'could not start investigation' });
        return;
    }
    // Poll for results.
    let tries = 0;
    const poll = setInterval(async () => {
        tries += 1;
        try {
            const res = await fetch(`/api/investigate/finding/${findingId}`);
            if (res.ok) {
                const data = await res.json();
                renderInvestigation(data.investigation);
                if (['complete', 'failed'].includes(data.investigation?.status) || tries > 20) {
                    clearInterval(poll);
                }
            }
        } catch {
            /* retry */
        }
        if (tries > 20) clearInterval(poll);
    }, 1500);
}

// Webhook test
const btnWebhookTest = document.getElementById('btnWebhookTest');
if (btnWebhookTest) {
    btnWebhookTest.addEventListener('click', async () => {
        btnWebhookTest.disabled = true;
        const original = btnWebhookTest.innerHTML;
        btnWebhookTest.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Sending…';
        try {
            const res = await fetch('/api/webhook/test', { method: 'POST' });
            const data = await res.json();
            showPathFeedback(res.ok ? (data.message || 'Test alert sent.') : (data.error || 'Webhook test failed.'),
                res.ok ? 'success' : 'danger');
        } catch {
            showPathFeedback('Network error — webhook test failed.', 'danger');
        } finally {
            btnWebhookTest.disabled = false;
            btnWebhookTest.innerHTML = original;
        }
    });
}

setStatus('idle', 'bg-secondary', false);
document.addEventListener('DOMContentLoaded', async () => {
    initActionModal();
    await loadConfig();
    await loadInterfaces();
    initSectionNav();
    refreshSuricata();
    loadRules();
    refreshCapture();
    suricataTimer = setInterval(refreshSuricata, 10000);
    captureTimer = setInterval(refreshCapture, 5000);
});
