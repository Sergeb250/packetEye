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

function formatApiError(data) {
    if (!data) return 'Request failed.';
    return [data.error, data.hint].filter(Boolean).join('\n\n');
}

function renderDiagnosticsTable(rows) {
    if (!rows?.length) return '';
    const head = `<thead><tr><th>#</th><th>Severity</th><th>Category</th><th>Message</th></tr></thead>`;
    const body = rows.map((r) => {
        const sev = (r.severity || 'info').toLowerCase();
        const badge = sev === 'critical' || sev === 'error' ? 'bg-danger'
            : sev === 'warning' ? 'bg-warning text-dark' : 'bg-secondary';
        return `<tr>
            <td class="text-muted">${r.line ?? '—'}</td>
            <td><span class="badge ${badge}">${esc((sev).toUpperCase())}</span></td>
            <td><span class="badge text-bg-light border">${esc(r.category || 'general')}</span></td>
            <td class="small font-monospace text-break">${esc(r.message)}</td>
        </tr>`;
    }).join('');
    return `<div class="table-responsive mt-3" style="max-height:240px;overflow:auto">
        <table class="table table-sm table-hover suricata-diag-table mb-0">${head}<tbody>${body}</tbody></table>
    </div>`;
}

function showErrorDetails(title, data) {
    return new Promise((resolve) => {
        if (useInlineLiveOps()) {
            const box = document.getElementById('liveOpsFeedback');
            const body = document.getElementById('liveOpsFeedbackBody');
            const extra = document.getElementById('liveOpsFeedbackExtra');
            if (box && body) {
                box.className = 'alert alert-danger mb-3';
                body.textContent = `${title}\n\n${formatApiError(data)}`;
                let html = '';
                if (data?.command) {
                    html += `<div class="mt-2"><span class="text-muted">Command:</span><br><code class="small user-select-all">${esc(data.command)}</code></div>`;
                }
                if (data?.config_path) {
                    html += `<div class="mt-1"><span class="text-muted">Config:</span> <code class="small">${esc(data.config_path)}</code></div>`;
                }
                html += renderDiagnosticsTable(data?.diagnostics);
                if (extra) extra.innerHTML = html;
                box.classList.remove('d-none');
                box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                if (window.suricataPage?.renderDiagnosticsRows && data?.diagnostics?.length) {
                    window.suricataPage.renderDiagnosticsRows(data.diagnostics);
                }
                resolve();
                return;
            }
        }
        const titleEl = document.getElementById('actionModalTitle');
        const bodyEl = document.getElementById('actionModalBody');
        const cancelBtn = document.getElementById('actionModalCancel');
        const confirmBtn = document.getElementById('actionModalConfirm');
        if (!titleEl || !bodyEl || !confirmBtn || !actionModalInst) {
            window.alert(`${title}\n\n${formatApiError(data)}`);
            resolve();
            return;
        }
        titleEl.innerHTML = `${MODAL_ICONS.danger} ${esc(title)}`;
        let html = esc(formatApiError(data)).replace(/\n/g, '<br>');
        if (data?.command) {
            html += `<div class="mt-2"><span class="text-muted small">Command:</span><br><code class="small user-select-all">${esc(data.command)}</code></div>`;
        }
        if (data?.config_path) {
            html += `<div class="mt-1"><span class="text-muted small">Config:</span> <code class="small">${esc(data.config_path)}</code></div>`;
        }
        html += renderDiagnosticsTable(data?.diagnostics);
        bodyEl.innerHTML = html;
        cancelBtn?.classList.add('d-none');
        confirmBtn.textContent = 'OK';
        confirmBtn.className = 'btn btn-danger';
        const onConfirm = () => {
            confirmBtn.removeEventListener('click', onConfirm);
            bodyEl.textContent = '';
            actionModalInst.hide();
            resolve();
        };
        confirmBtn.addEventListener('click', onConfirm);
        actionModalInst.show();
        if (window.suricataPage?.renderDiagnosticsRows && data?.diagnostics?.length) {
            window.suricataPage.renderDiagnosticsRows(data.diagnostics);
        }
    });
}

function initActionModal() {
    const el = document.getElementById('actionModal');
    if (el) actionModalInst = new bootstrap.Modal(el);
}

function useInlineLiveOps() {
    return Boolean(document.getElementById('liveOpsFeedback'));
}

function showInlineFeedback(message, variant = 'info', title = null) {
    const box = document.getElementById('liveOpsFeedback');
    const body = document.getElementById('liveOpsFeedbackBody');
    const extra = document.getElementById('liveOpsFeedbackExtra');
    if (!box || !body) return false;
    const variants = { success: 'alert-success', danger: 'alert-danger', warning: 'alert-warning', info: 'alert-info' };
    box.className = `alert ${variants[variant] || variants.info} mb-3`;
    body.textContent = title ? `${title}\n\n${message}` : message;
    if (extra) extra.innerHTML = '';
    box.classList.remove('d-none');
    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    return true;
}

function hideInlineFeedback() {
    document.getElementById('liveOpsFeedback')?.classList.add('d-none');
    const extra = document.getElementById('liveOpsFeedbackExtra');
    if (extra) extra.innerHTML = '';
}

window.showInlineFeedback = showInlineFeedback;

function showNotice(title, message, variant = 'danger') {
    return new Promise((resolve) => {
        if (showInlineFeedback(message, variant, title)) {
            resolve();
            return;
        }
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
        const confirmBox = document.getElementById('liveOpsConfirm');
        if (confirmBox) {
            const titleEl = document.getElementById('liveOpsConfirmTitle');
            const bodyEl = document.getElementById('liveOpsConfirmBody');
            const yesBtn = document.getElementById('liveOpsConfirmYes');
            const noBtn = document.getElementById('liveOpsConfirmNo');
            if (titleEl && bodyEl && yesBtn && noBtn) {
                titleEl.textContent = title;
                bodyEl.textContent = message;
                confirmBox.classList.remove('d-none');
                confirmBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                const cleanup = (result) => {
                    confirmBox.classList.add('d-none');
                    yesBtn.removeEventListener('click', onYes);
                    noBtn.removeEventListener('click', onNo);
                    resolve(result);
                };
                const onYes = () => cleanup(true);
                const onNo = () => cleanup(false);
                yesBtn.addEventListener('click', onYes);
                noBtn.addEventListener('click', onNo);
                return;
            }
        }
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
                if (data?.diagnostics?.length) {
                    await showErrorDetails(errorTitle || 'Action failed', data);
                } else {
                    await showNotice(errorTitle || 'Action failed', formatApiError(data) || `Request failed (${res.status})`, 'danger');
                }
            }
            return { ok: false, data, status: res.status };
        }
        if (successMessage && !useInlineLiveOps()) {
            await showNotice(successTitle || 'Success', successMessage, 'success');
        } else if (successMessage) {
            showInlineFeedback(successMessage, 'success', successTitle || 'Success');
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

async function syncEveFromCapture() {
    try {
        const [capRes, surRes] = await Promise.all([
            fetch('/api/capture/status'),
            fetch('/api/suricata/status'),
        ]);
        const s = capRes.ok ? await capRes.json() : {};
        const sur = surRes.ok ? await surRes.json() : {};
        const path = sur.eve?.path || s.suricata?.eve?.path || liveConfig.capture?.eve_path || liveConfig.default_eve_path || '';
        const eveInput = document.getElementById('evePathInput');
        if (path && els.evePath) {
            els.evePath.value = path;
        }
        if (path && eveInput && !eveInput.value.trim()) {
            eveInput.value = path;
        }
        const disp = document.getElementById('evePathDisplay');
        if (disp && path) disp.textContent = path + (sur.eve?.source ? ` (${sur.eve.source})` : '');

        const mlBadge = document.getElementById('mlCaptureBadge');
        if (mlBadge) {
            if (s.running) {
                mlBadge.textContent = `capture: ${s.mode} · ${s.interface || '?'}`;
                mlBadge.className = 'badge bg-success';
            } else if (sur.running && !sur.managed) {
                mlBadge.textContent = 'external suricata · connected';
                mlBadge.className = 'badge bg-info text-dark';
            } else if (sur.running) {
                mlBadge.textContent = 'suricata · live';
                mlBadge.className = 'badge bg-success';
            } else {
                mlBadge.textContent = 'capture: stopped';
                mlBadge.className = 'badge bg-secondary';
            }
        }

        if (sur.eve?.path && liveConfig.auto_sync_eve !== false && sessionId && path !== els.evePath?.dataset.lastRebind) {
            fetch('/api/live/rebind-eve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: sessionId, eve_path: path }),
            }).then(() => {
                if (els.evePath) els.evePath.dataset.lastRebind = path;
            }).catch(() => {});
        }

        if (s.interface && els.iface && !els.iface.value.trim()) {
            els.iface.value = s.interface;
        }
        if (s.interface && cap.iface && !cap.iface.value) {
            cap.iface.value = s.interface;
        }
    } catch {
        /* optional sync */
    }
}

window.alertSeverityFilter = '';

async function importEveFile() {
    const fileInput = document.getElementById('eveFileUpload');
    const pathInput = document.getElementById('evePathInput');
    const form = new FormData();
    if (fileInput?.files?.[0]) {
        form.append('file', fileInput.files[0]);
    } else if (pathInput?.value.trim()) {
        const res = await fetch('/api/live/import-eve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ eve_path: pathInput.value.trim() }),
        });
        const data = await res.json();
        if (!res.ok) {
            await showNotice('Import failed', data.error || 'Failed', 'danger');
            return null;
        }
        return data.eve_path;
    } else {
        await showNotice('Import EVE', 'Choose a file or paste a path.', 'warning');
        return null;
    }
    const res = await fetch('/api/live/import-eve', { method: 'POST', body: form });
    const data = await res.json();
    if (!res.ok) {
        await showNotice('Import failed', data.error || 'Failed', 'danger');
        return null;
    }
    return data.eve_path;
}

async function plugEveIntoMl(evePath) {
    const path = evePath || document.getElementById('evePathInput')?.value?.trim() || els.evePath?.value?.trim();
    if (!path) {
        await showNotice('EVE path required', 'Set or import an eve.json path first.', 'warning');
        return;
    }
    if (els.evePath) els.evePath.value = path;
    if (sessionId) {
        const res = await fetch('/api/live/rebind-eve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, eve_path: path }),
        });
        const data = await res.json();
        if (res.ok) {
            await showNotice('EVE plugged in', `ML session now tailing ${path}`, 'success');
        } else {
            await showNotice('Rebind failed', data.error || 'Failed', 'danger');
        }
        return;
    }
    showPathFeedback('Starting ML on imported EVE…', 'info');
    if (els.evePath) els.evePath.value = path;
    await startMonitor();
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
    window.liveConfig = liveConfig;

    try {
        const res = await fetch('/api/live/config');
        if (res.ok) {
            liveConfig = { ...liveConfig, ...(await res.json()) };
            window.liveConfig = liveConfig;
        }
    } catch {
        /* use template defaults */
    }

    if (liveConfig.default_eve_path && els.evePath && !els.evePath.value.trim()) {
        els.evePath.value = liveConfig.capture?.eve_path || liveConfig.default_eve_path;
    }
    const disp = document.getElementById('evePathDisplay');
    if (disp && els.evePath?.value) disp.textContent = els.evePath.value;

    await syncEveFromCapture();

    if (liveConfig.privilege_hint && document.getElementById('mlCaptureBadge')) {
        showPathFeedback(liveConfig.privilege_hint, 'danger');
    }

    if (liveConfig.active_session) {
        resumeSession(liveConfig.active_session);
    }
}

let sessionResumed = false;

function resumeSession(status) {
    if (sessionResumed && sessionId === status.session_id) return;
    sessionResumed = true;
    sessionId = status.session_id;
    window.sessionId = sessionId;
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
    if (typeof window.socLoadAlerts === 'function') window.socLoadAlerts();
}

async function startMonitor() {
    await syncEveFromCapture();
    const evePath = (els.evePath?.value || liveConfig.capture?.eve_path || liveConfig.default_eve_path || '').trim();
    const captureIface = (
        cap.iface?.value || sur.iface?.value || els.iface?.value
        || liveConfig.capture?.interface || liveConfig.capture_interface || ''
    ).trim();
    const captureMode = (cap.mode?.value || liveConfig.capture_mode || 'suricata').trim();

    if (!captureIface && captureMode !== 'tcpdump') {
        showPathFeedback('Pick a network interface on the Capture page (or set CAPTURE_INTERFACE in .env).', 'warning');
        const capLink = document.querySelector('a[href*="live/capture"]');
        capLink?.focus();
        return;
    }

    showPathFeedback('Starting ML live monitor…', 'info');
    if (els.btnStart) {
        els.btnStart.disabled = true;
        els.btnStart.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Starting…';
    }

    const body = {
        interface: captureIface || undefined,
        mode: captureMode,
        auto_start_capture: captureMode === 'suricata',
    };
    if (evePath) body.eve_path = evePath;

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
            showPathFeedback(data.note || 'tcpdump capture + ML started.', 'success');
            refreshCapture();
            if (data.session_id) {
                resumeSession({
                    session_id: data.session_id,
                    total_flows: 0,
                    total_findings: 0,
                });
                alertSince = 0;
                totalAlertsShown = 0;
            } else if (data.ml_status === 'model_missing') {
                showPathFeedback('Capture started but ML model missing — train model first.', 'warning');
            }
            if (els.btnStart) {
                els.btnStart.innerHTML = '<i class="bi bi-play-fill"></i> Start ML Live Monitor';
            }
            return;
        }

        sessionId = data.session_id;
        window.sessionId = sessionId;
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
        if (typeof window.socLoadAlerts === 'function') window.socLoadAlerts();
        document.getElementById('alertFeedSection')?.scrollIntoView({ behavior: 'smooth' });
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
        pollTimer = null;
        sessionId = null;
        window.sessionId = null;
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
    const sev = window.socAlertSeverity || window.alertSeverityFilter || '';
    const src = window.socAlertSource || '';
    let alertUrl = `/api/live/alerts?session_id=${sessionId}&since=${alertSince}`;
    if (sev) alertUrl += `&severity=${encodeURIComponent(sev)}`;
    if (src) alertUrl += `&source=${encodeURIComponent(src)}`;
    const [statusRes, alertsRes] = await Promise.all([
        fetch(`/api/live/status?session_id=${sessionId}`),
        fetch(alertUrl),
    ]);
    let status = null;
    if (statusRes.ok) {
        status = await statusRes.json();
        if (els.flowCount) els.flowCount.textContent = (status.total_flows || 0).toLocaleString();
        if (els.alertCount) els.alertCount.textContent = (status.total_findings || 0).toLocaleString();
        const socFlows = document.getElementById('socKpiFlows');
        const socAlerts = document.getElementById('socKpiAlerts');
        if (socFlows) socFlows.textContent = (status.total_flows || 0).toLocaleString();
        if (socAlerts) socAlerts.textContent = (status.total_findings || 0).toLocaleString();
        if (status.running) setStatus('running', 'bg-success', true);
        else if (sessionId) setStatus('stopped', 'bg-secondary', false);
        if (typeof window.socUpdateStatus === 'function') window.socUpdateStatus(status);
        window.socServerTotal = status.total_findings || 0;
    }
    if (alertsRes.ok) {
        const { alerts } = await alertsRes.json();
        if (alerts.length) {
            renderAlerts(alerts);
            alertSince = Math.max(...alerts.map((a) => a.timestamp));
        }
        if (typeof window.socOnAlerts === 'function' && alerts.length) window.socOnAlerts(alerts);
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
        const isCorr = a.type === 'correlation';
        const sourceBadge = isCorr
            ? '<span class="badge bg-danger"><i class="bi bi-link-45deg"></i> CORR</span>'
            : isSuricata
            ? '<span class="badge bg-warning text-dark"><i class="bi bi-shield-exclamation"></i> SURICATA</span>'
            : '<span class="badge bg-info text-dark"><i class="bi bi-cpu"></i> ML</span>';
        const detailBadge = isSuricata
            ? `<span class="badge text-bg-light border">${esc(a.category || 'signature')}</span>`
            : `<span class="badge text-bg-light border">score ${a.anomaly_score}</span>`;
        const detailText = isSuricata ? (a.signature || a.explanation) : a.explanation;
        const insight = typeof window.socBuildInsight === 'function' ? window.socBuildInsight(a) : null;
        const item = document.createElement('div');
        item.className = `list-group-item alert-feed-item severity-${a.severity || 'info'} soc-clickable-alert`;
        item.style.cursor = 'pointer';
        item.title = 'Click for details';
        item.innerHTML = `
            <div class="d-flex justify-content-between align-items-start gap-2 mb-1">
                <span class="badge bg-${meta.badge}">${meta.label}</span>
                ${sourceBadge}
                ${detailBadge}
                <small class="text-muted ms-auto">${new Date(a.timestamp * 1000).toLocaleTimeString()}</small>
            </div>
            ${insight ? `<div class="small fw-semibold text-dark mb-1">${esc(insight.headline)}</div>` : ''}
            <div class="font-monospace small">
                ${esc(a.src_ip)}:${a.src_port || '*'} → ${esc(a.dst_ip)}:${a.dst_port || '*'}
                <span class="text-muted">(${esc(a.protocol) || '?'})</span>
            </div>
            ${detailText ? `<small class="text-muted d-block mt-1">${esc(detailText)}</small>` : ''}
            <div class="d-flex flex-wrap gap-1 mt-2 soc-alert-actions">
            ${a.finding_id ? `<button class="btn btn-outline-info btn-sm btn-investigate" data-finding-id="${esc(a.finding_id)}">
                <i class="bi bi-search"></i> Investigate</button>` : ''}
            ${a.dst_ip && sessionId ? `<button class="btn btn-outline-primary btn-sm btn-alert-osint" data-ip="${esc(a.dst_ip)}">OSINT</button>` : ''}
            ${a.dst_ip && sessionId ? `<button class="btn btn-outline-secondary btn-sm btn-alert-map" data-ip="${esc(a.dst_ip)}">Map</button>` : ''}
            ${sessionId ? `<button class="btn btn-info btn-sm btn-alert-ai"><i class="bi bi-robot"></i> AI</button>` : ''}
            </div>`;
        item.addEventListener('click', (e) => {
            if (e.target.closest('.soc-alert-actions')) return;
            if (typeof window.socSelectAlert === 'function') {
                window.socSelectAlert(a);
                if (window.livePage !== 'overview') window.location.href = '/live/overview';
            }
        });
        item.querySelector('.btn-alert-ai')?.addEventListener('click', (e) => {
            e.stopPropagation();
            if (window.openChatWithContext) {
                window.openChatWithContext(
                    'Analyze this live alert with full JSON. Use tables for IOCs and mermaid for traffic flow.',
                    sessionId,
                    a.finding_id || null,
                    { type: 'live_alert', raw: a },
                    null,
                );
            }
        });
        const invBtn = item.querySelector('.btn-investigate');
        if (invBtn) invBtn.addEventListener('click', () => investigateFinding(invBtn.dataset.findingId));
        item.querySelector('.btn-alert-osint')?.addEventListener('click', (e) => {
            e.stopPropagation();
            if (window.openOsintForTarget && sessionId) {
                window.openOsintForTarget(sessionId, e.target.dataset.ip);
            }
        });
        item.querySelector('.btn-alert-map')?.addEventListener('click', async (e) => {
            const ip = e.target.dataset.ip;
            const mapPanel = document.getElementById('liveThreatMapPanel');
            const canvas = document.getElementById('liveThreatMapCanvas');
            if (!mapPanel || !canvas || !sessionId) return;
            mapPanel.classList.remove('d-none');
            canvas.innerHTML = '';
            try {
                const res = await fetch(`/api/analysis/${sessionId}/geo`);
                const data = res.ok ? await res.json() : { markers: [] };
                let markers = data.markers || [];
                if (ip) markers = markers.filter((m) => m.ip === ip);
                if (!markers.length) {
                    showInlineFeedback(`No geo for ${ip} yet — run Investigate/OSINT first.`, 'warning', 'Map');
                    return;
                }
                window.renderThreatMap('liveThreatMapCanvas', markers);
                mapPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            } catch {
                showInlineFeedback('Threat map unavailable.', 'danger', 'Map');
            }
        });
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
    configPath: document.getElementById('surConfig'),
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
        if (sur.configPath) {
            const src = s.config_source ? `${s.config_source}: ` : '';
            sur.configPath.textContent = s.config_path ? `${src}${s.config_path.split(/[\\/]/).pop()}` : '—';
            sur.configPath.title = s.config_path || '';
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
            const isLo = i.loopback || i.name === 'lo';
            const loBlocked = isLo && !liveConfig.suricata_allow_loopback;
            opt.textContent = `${i.name}${addr}${i.up === false ? ' (down)' : ''}${loBlocked ? ' (loopback — blocked)' : ''}`;
            if (loBlocked) opt.disabled = true;
            selectEl.appendChild(opt);
        });
        if (!defaultName) {
            const preferred = interfaces.find(
                (i) => !i.loopback && i.name !== 'lo' && i.up !== false
                    && /^(eth|enp|ens|wlan|wlp|wifi)/i.test(i.name),
            );
            const nonLoop = interfaces.find((i) => !i.loopback && i.name !== 'lo' && i.up !== false);
            defaultName = preferred?.name || nonLoop?.name || '';
            if (!defaultName) {
                const firstAllowed = interfaces.find((i) => !i.loopback && i.name !== 'lo');
                defaultName = firstAllowed?.name || '';
            }
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
    if (iface === 'lo' && !liveConfig.suricata_allow_loopback) {
        surFeedback('Interface lo (loopback) is blocked. Select eth0, wlan0, or your active NIC.', 'danger');
        await showNotice(
            'Loopback blocked',
            'Suricata cannot use lo by default. Pick eth0, wlan0, or enp*.\n\nSet SURICATA_ALLOW_LOOPBACK=true in .env only for local testing.',
            'warning',
        );
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
        surFeedback(`Suricata started (pid ${data.pid}). EVE: ${data.eve_hint}`, 'success');
        if (data.eve_hint) suricataEvePath = data.eve_hint;
        if (data.eve_hint && els.evePath) els.evePath.value = data.eve_hint;
        await showNotice('Suricata started', `Running (pid ${data.pid}). Config: ${data.config_source || 'default'}`, 'success');
    } else if (result) {
        surFeedback(formatApiError(result.data), 'danger');
        if (result.data?.diagnostics?.length && window.suricataPage?.renderDiagnosticsRows) {
            window.suricataPage.renderDiagnosticsRows(result.data.diagnostics);
        }
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
    sur.btnUseEve.addEventListener('click', async () => {
        const path = suricataEvePath || (els.evePath?.value || '').trim();
        if (!path) {
            await showNotice('EVE path unavailable', 'Start Suricata first or set SURICATA_EVE_PATH in .env.', 'warning');
            return;
        }
        if (els.evePath) els.evePath.value = path;
        try {
            await navigator.clipboard.writeText(path);
        } catch {
            /* clipboard optional */
        }
        await showNotice('EVE log path', `${path}\n\nUse this on the ML Live Monitor page.`, 'info');
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
    if (iface === 'lo' && !liveConfig.suricata_allow_loopback) {
        capFeedback('Interface lo (loopback) is blocked. Select eth0, wlan0, or your active NIC.', 'danger');
        await showNotice('Loopback blocked', 'Do not use lo for live capture. Pick eth0, wlan0, or enp*.', 'warning');
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
        capFeedback(`Capture running (${data.mode}, pid ${data.pid}).`, 'success');
        if (data.eve_hint && els.evePath) els.evePath.value = data.eve_hint;
        if (data.session_id) {
            resumeSession({
                session_id: data.session_id,
                total_flows: 0,
                total_findings: 0,
            });
            alertSince = 0;
            totalAlertsShown = 0;
            capFeedback(`Capture + ML live (${data.mode}, session ${data.session_id.slice(0, 8)}…).`, 'success');
        } else if (data.ml_status === 'model_missing') {
            capFeedback('Capture started — ML model not loaded.', 'warning');
        }
        await showNotice('Capture started', `Traffic capture running (${data.mode}, pid ${data.pid}).`, 'success');
    } else if (result) {
        capFeedback(formatApiError(result.data), 'danger');
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
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
        sessionId = null;
        window.sessionId = null;
        if (els.btnStop) els.btnStop.disabled = true;
        if (els.btnStart) els.btnStart.disabled = false;
        setStatus('idle', 'bg-secondary', false);
        await showNotice('Capture stopped', 'Traffic capture and ML session stopped.', 'success');
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

if (cap.btnStart) cap.btnStart.addEventListener('click', startCapture);
if (cap.btnStop) cap.btnStop.addEventListener('click', stopCapture);
if (cap.btnRefresh) cap.btnRefresh.addEventListener('click', refreshCapture);

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

function initSectionNav() {
    const tabMap = {
        overview: '#tab-overview',
        capture: '#tab-capture',
        suricata: '#tab-suricata',
        ml: '#tab-ml',
        lab: '#tab-lab',
    };
    const page = window.livePage || 'overview';
    const target = tabMap[page] || tabMap.overview;
    const pane = document.querySelector(target);
    if (pane && !pane.classList.contains('active')) {
        document.querySelectorAll('#liveOpsTabContent .tab-pane').forEach((el) => {
            el.classList.remove('show', 'active');
        });
        pane.classList.add('show', 'active');
    }
}

async function refreshOverviewPanels() {
    const capEl = document.getElementById('overviewCaptureStatus');
    const surEl = document.getElementById('overviewSuricataStatus');
    if (!capEl && !surEl) return;
    try {
        const [capRes, surRes] = await Promise.all([
            fetch('/api/capture/status'),
            fetch('/api/suricata/status'),
        ]);
        const cap = capRes.ok ? await capRes.json() : {};
        const sur = surRes.ok ? await surRes.json() : {};
        if (capEl) {
            capEl.innerHTML = `
                <div><strong>Status:</strong> ${cap.running ? `${esc(cap.mode)} (pid ${cap.pid || '—'})` : 'stopped'}</div>
                <div><strong>Interface:</strong> ${esc(cap.interface || '—')}</div>
                <div><strong>Chunks:</strong> ${cap.tcpdump?.chunks?.count ?? '—'}</div>
                <div><strong>Watcher:</strong> ${cap.chunk_watcher?.running ? 'running' : 'off'}</div>`;
        }
        if (surEl) {
            surEl.innerHTML = `
                <div><strong>Installed:</strong> ${sur.installed ? 'yes' : 'no'}</div>
                <div><strong>Running:</strong> ${sur.running ? 'yes' : 'no'}</div>
                <div><strong>EVE:</strong> <code class="small">${esc(sur.eve?.path || '—')}</code></div>
                <div><strong>Rate:</strong> ${sur.eve?.events_per_second != null ? sur.eve.events_per_second.toFixed(1) + '/s' : '—'}</div>`;
        }
    } catch {
        /* ignore */
    }
}

async function toggleLabTraffic() {
    const btn = document.getElementById('opsBtnLabToggle');
    const running = btn?.dataset.running === 'true';
    if (running) {
        await stopLabTraffic();
    } else {
        await runLabTraffic();
    }
}

async function runLabTraffic() {
    const patterns = [];
    document.querySelectorAll('.lab-pat:checked').forEach((el) => {
        if (el?.value) patterns.push(el.value);
    });
    const iface = (document.getElementById('labIface')?.value || cap.iface?.value || sur.iface?.value || '').trim();
    const logEl = document.getElementById('labLog');
    const btn = document.getElementById('opsBtnLabToggle');
    if (!patterns.length) {
        await showNotice('Lab traffic', 'Select at least one attack pattern.', 'warning');
        showInlineFeedback('Select at least one attack pattern.', 'warning', 'Lab traffic');
        return;
    }
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Starting…';
    }
    if (logEl) logEl.textContent = 'Starting lab generator…';
    try {
        const res = await fetch('/api/lab/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ patterns, interface: iface }),
        });
        const data = await res.json();
        if (!res.ok) {
            const msg = data.hint ? `${data.error} — ${data.hint}` : (data.error || 'Failed to start');
            if (logEl) logEl.textContent = msg;
            await showNotice('Lab start failed', msg, 'danger');
            showInlineFeedback(msg, 'danger', 'Lab traffic');
            setLabToggleState(false);
            return;
        }
        setLabToggleState(true);
        await showNotice('Lab traffic started', `Generating ${patterns.length} attack pattern(s) on ${data.interface || iface}.`, 'success');
        showInlineFeedback('Lab traffic running — watch ML alerts on Overview.', 'success', 'Lab traffic');
        startLabPoll();
        refreshLabStatus();
    } catch (err) {
        await showNotice('Lab start failed', String(err), 'danger');
        setLabToggleState(false);
    }
}

async function stopLabTraffic() {
    const logEl = document.getElementById('labLog');
    const btn = document.getElementById('opsBtnLabToggle');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Stopping…';
    }
    try {
        const res = await fetch('/api/lab/stop', { method: 'POST' });
        const data = await res.json();
        stopLabPoll();
        if (!res.ok || data.ok === false) {
            const msg = data.error || 'Failed to stop lab generator';
            await showNotice('Lab stop failed', msg, 'danger');
            showInlineFeedback(msg, 'danger', 'Lab traffic');
        } else {
            await showNotice('Lab traffic stopped', data.message || 'Generator stopped.', 'success');
            showInlineFeedback('Lab traffic stopped.', 'info', 'Lab traffic');
        }
        setLabToggleState(false);
        refreshLabStatus();
        if (logEl && data.message) logEl.textContent += `\n[ui] ${data.message}`;
    } catch (err) {
        await showNotice('Lab stop failed', String(err), 'danger');
        setLabToggleState(false);
    }
}

function setLabToggleState(running) {
    const btn = document.getElementById('opsBtnLabToggle');
    if (!btn) return;
    btn.dataset.running = running ? 'true' : 'false';
    btn.disabled = false;
    if (running) {
        btn.className = 'btn btn-danger btn-sm mt-3';
        btn.innerHTML = '<i class="bi bi-stop-fill"></i> Stop lab traffic';
    } else {
        btn.className = 'btn btn-primary btn-sm mt-3';
        btn.innerHTML = '<i class="bi bi-play-fill"></i> Start lab traffic';
    }
}

function renderLabAttackTable(rows) {
    const body = document.getElementById('labAttackBody');
    if (!body) return;
    if (!rows?.length) {
        body.innerHTML = '<tr><td colspan="4" class="text-muted small">Start lab traffic to see active attacks.</td></tr>';
        return;
    }
    const statusBadge = (s) => {
        const map = { active: 'success', queued: 'secondary', done: 'light text-dark', pending: 'secondary' };
        return `<span class="badge bg-${map[s] || 'secondary'}">${esc(s)}</span>`;
    };
    body.innerHTML = rows.map((r) => `
        <tr class="${r.status === 'active' ? 'table-warning' : ''}">
            <td><code>${esc(r.pattern)}</code></td>
            <td>${esc(r.cic_label)}</td>
            <td>${statusBadge(r.status)}</td>
            <td>${r.status === 'active' ? `${Number(r.elapsed_sec || 0).toFixed(1)}s` : '—'}</td>
        </tr>`).join('');
}

let labPollTimer = null;

function startLabPoll() {
    stopLabPoll();
    labPollTimer = setInterval(refreshLabStatus, 1500);
}

function stopLabPoll() {
    if (labPollTimer) {
        clearInterval(labPollTimer);
        labPollTimer = null;
    }
}

async function refreshLabStatus() {
    const logEl = document.getElementById('labLog');
    const badge = document.getElementById('labStatusBadge');
    try {
        const res = await fetch('/api/lab/status');
        if (!res.ok) return;
        const data = await res.json();
        if (logEl && Array.isArray(data.log)) {
            logEl.textContent = data.log.join('\n') || '—';
            logEl.scrollTop = logEl.scrollHeight;
        }
        renderLabAttackTable(data.patterns_queue);
        if (badge) {
            badge.textContent = data.running ? 'running' : (data.last_error ? 'error' : 'idle');
            badge.className = `badge ${data.running ? 'bg-success' : (data.last_error ? 'bg-danger' : 'bg-secondary')}`;
        }
        setLabToggleState(!!data.running);
        if (data.last_error && !data.running) {
            showInlineFeedback(data.last_error, 'danger', 'Lab traffic');
        }
        if (!data.running) stopLabPoll();
    } catch {
        /* ignore transient poll errors */
    }
}

let nidsTestPollTimer = null;

function setNidsTestToggleState(running) {
    const btn = document.getElementById('opsBtnNidsTestToggle');
    if (!btn) return;
    btn.dataset.running = running ? 'true' : 'false';
    btn.disabled = false;
    if (running) {
        btn.className = 'btn btn-danger btn-sm w-100';
        btn.innerHTML = '<i class="bi bi-stop-fill"></i> Stop soak test';
    } else {
        btn.className = 'btn btn-success btn-sm w-100';
        btn.innerHTML = '<i class="bi bi-play-fill"></i> Start soak test';
    }
}

function startNidsTestPoll() {
    stopNidsTestPoll();
    nidsTestPollTimer = setInterval(refreshNidsTestStatus, 2000);
}

function stopNidsTestPoll() {
    if (nidsTestPollTimer) {
        clearInterval(nidsTestPollTimer);
        nidsTestPollTimer = null;
    }
}

function renderNidsTestCoverage(rows, activePattern) {
    const body = document.getElementById('nidsTestCoverageBody');
    if (!body) return;
    if (!rows?.length) {
        body.innerHTML = '<tr><td colspan="5" class="text-muted small">Start soak test to track all 13 attack patterns.</td></tr>';
        return;
    }
    const yesNo = (v) => (v ? '<span class="badge bg-success">yes</span>' : '<span class="badge bg-secondary">no</span>');
    body.innerHTML = rows.map((r) => `
        <tr class="${r.pattern === activePattern ? 'table-warning' : ''}">
            <td><code>${esc(r.pattern)}</code></td>
            <td>${esc(r.cic_label)}</td>
            <td>${yesNo(r.alerted_ml)}</td>
            <td>${yesNo(r.alerted_suricata)}</td>
            <td>${yesNo(r.completed)}</td>
        </tr>`).join('');
}

async function refreshNidsTestStatus() {
    const logEl = document.getElementById('nidsTestLog');
    const badge = document.getElementById('nidsTestBadge');
    try {
        const res = await fetch('/api/nids-test/status');
        if (!res.ok) return;
        const data = await res.json();
        const st = data.stats || {};
        const al = st.alerts || {};
        const set = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };
        set('nidsTestFlows', st.total_flows ?? '—');
        set('nidsTestFindings', st.total_findings ?? '—');
        set('nidsTestMl', al.ml ?? '—');
        set('nidsTestSuri', al.suricata ?? '—');
        set('nidsTestElapsed', data.elapsed_sec != null ? `${Number(data.elapsed_sec).toFixed(0)}s` : '—');
        renderNidsTestCoverage(data.pattern_coverage, st.current_pattern);
        if (logEl && Array.isArray(data.log)) {
            logEl.textContent = data.log.slice(-40).join('\n') || '—';
            logEl.scrollTop = logEl.scrollHeight;
        }
        if (badge) {
            badge.textContent = data.running ? 'running' : (data.last_error ? 'error' : 'idle');
            badge.className = `badge ${data.running ? 'bg-success' : (data.last_error ? 'bg-danger' : 'bg-secondary')}`;
        }
        setNidsTestToggleState(!!data.running);
        if (data.session_id) {
            sessionId = data.session_id;
            window.sessionId = sessionId;
        }
        if (!data.running) stopNidsTestPoll();
    } catch {
        /* ignore */
    }
}

async function startNidsSoakTest() {
    const btn = document.getElementById('opsBtnNidsTestToggle');
    const logEl = document.getElementById('nidsTestLog');
    const mode = document.getElementById('nidsTestMode')?.value || 'suricata';
    const iface = (document.getElementById('nidsTestIface')?.value || cap.iface?.value || sur.iface?.value || '').trim();
    const withLab = document.getElementById('nidsTestWithLab')?.checked !== false;
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Starting…';
    }
    if (logEl) logEl.textContent = 'Starting NIDS soak test…';
    try {
        const res = await fetch('/api/nids-test/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode, interface: iface, with_lab: withLab, poll_sec: 5, rotate_sec: 12 }),
        });
        const data = await res.json();
        if (!res.ok) {
            const msg = data.hint ? `${data.error} — ${data.hint}` : (data.error || 'Failed to start');
            if (logEl) logEl.textContent = msg;
            await showNotice('Soak test failed', msg, 'danger');
            setNidsTestToggleState(false);
            return;
        }
        if (data.session_id) {
            sessionId = data.session_id;
            window.sessionId = sessionId;
            resumeSession({ session_id: data.session_id, running: true });
        }
        setNidsTestToggleState(true);
        await showNotice('Soak test started', data.message || 'Monitoring until stopped.', 'success');
        startNidsTestPoll();
        refreshNidsTestStatus();
    } catch (err) {
        await showNotice('Soak test failed', String(err), 'danger');
        setNidsTestToggleState(false);
    }
}

async function stopNidsSoakTest() {
    const btn = document.getElementById('opsBtnNidsTestToggle');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Stopping…';
    }
    try {
        const res = await fetch('/api/nids-test/stop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ stop_live: false }),
        });
        const data = await res.json();
        stopNidsTestPoll();
        setNidsTestToggleState(false);
        await showNotice('Soak test stopped', data.message || 'Stopped.', 'info');
        refreshNidsTestStatus();
    } catch (err) {
        await showNotice('Stop failed', String(err), 'danger');
        setNidsTestToggleState(false);
    }
}

async function toggleNidsSoakTest() {
    const btn = document.getElementById('opsBtnNidsTestToggle');
    if (btn?.dataset.running === 'true') await stopNidsSoakTest();
    else await startNidsSoakTest();
}

document.addEventListener('DOMContentLoaded', async () => {
    initActionModal();
    initSectionNav();
    await loadConfig();
    await loadInterfaces();

    if (sur.badge) {
        refreshSuricata();
        loadRules();
        suricataTimer = setInterval(refreshSuricata, 10000);
    }
    if (cap.badge) {
        refreshCapture();
        captureTimer = setInterval(refreshCapture, 5000);
    }
    if (document.getElementById('socSensorHealth')) {
        /* polled by live_soc.js */
    }
    if (document.getElementById('mlCaptureBadge')) {
        syncEveFromCapture();
        setInterval(syncEveFromCapture, 5000);
    }
    if (els.btnStart || els.alertFeed || document.getElementById('liveStatus')) {
        if (document.getElementById('liveStatus')) setStatus('idle', 'bg-secondary', false);
        if (liveConfig.active_session) {
            resumeSession(liveConfig.active_session);
        }
    }
    document.getElementById('opsBtnLabToggle')?.addEventListener('click', toggleLabTraffic);
    document.getElementById('opsBtnNidsTestToggle')?.addEventListener('click', toggleNidsSoakTest);
    refreshNidsTestStatus();
    document.getElementById('evePathInput')?.addEventListener('change', (e) => {
        if (els.evePath) els.evePath.value = e.target.value;
        const disp = document.getElementById('evePathDisplay');
        if (disp) disp.textContent = e.target.value;
    });
    document.getElementById('btnImportEve')?.addEventListener('click', async () => {
        const path = await importEveFile();
        if (path) {
            const inp = document.getElementById('evePathInput');
            if (inp) inp.value = path;
            if (els.evePath) els.evePath.value = path;
            await showNotice('EVE imported', path, 'success');
            await plugEveIntoMl(path);
        }
    });
    document.getElementById('btnPlugEve')?.addEventListener('click', () => plugEveIntoMl());
    document.querySelectorAll('#mlAlertFilters button').forEach((btn) => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('#mlAlertFilters button').forEach((b) => b.classList.remove('active'));
            btn.classList.add('active');
            window.alertSeverityFilter = btn.dataset.severity || '';
            alertSince = 0;
            if (typeof window.socLoadAlerts === 'function') window.socLoadAlerts();
        });
    });
    refreshLabStatus();
    document.getElementById('liveOpsFeedbackDismiss')?.addEventListener('click', hideInlineFeedback);
    document.getElementById('liveInvestigatePanelHide')?.addEventListener('click', () => {
        document.getElementById('liveInvestigatePanel')?.classList.add('d-none');
    });
    document.getElementById('liveOsintPanelHide')?.addEventListener('click', () => {
        document.getElementById('liveOsintPanel')?.classList.add('d-none');
    });
    document.getElementById('liveThreatMapPanelHide')?.addEventListener('click', () => {
        document.getElementById('liveThreatMapPanel')?.classList.add('d-none');
    });
});

// ---------------------------------------------------------------------------
// OSINT investigation (inline panel on Live Operations, offcanvas elsewhere)
// ---------------------------------------------------------------------------
const investigateBody = document.getElementById('investigateBody');
const investigatePanelEl = document.getElementById('liveInvestigatePanel');
const investigateOffcanvasEl = document.getElementById('investigatePanel');
const investigatePanel = investigateOffcanvasEl ? new bootstrap.Offcanvas(investigateOffcanvasEl) : null;

function showInvestigatePanel() {
    if (investigatePanelEl) {
        investigatePanelEl.classList.remove('d-none');
        investigatePanelEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        return;
    }
    investigatePanel?.show();
}

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
    if (vt?.error) parts.push(`VT: error`);
    else if (vt && vt.malicious != null) parts.push(`VT: ${vt.malicious} malicious`);
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
    if (!findingId || !investigateBody) return;
    showInvestigatePanel();
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

// Webhook test
