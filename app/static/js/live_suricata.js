/**
 * Suricata page: tabular diagnostics + EVE event monitor (/live/suricata)
 */
(function () {
    const diagBody = document.getElementById('surDiagBody');
    const monitorBody = document.getElementById('surMonitorBody');
    if (!diagBody && !monitorBody) return;

    const els = {
        diagBody,
        diagCount: document.getElementById('surDiagCount'),
        diagWrap: document.getElementById('surDiagWrap'),
        btnDiagRefresh: document.getElementById('btnSurDiagRefresh'),
        monitorBody,
        monitorWrap: document.getElementById('surMonitorWrap'),
        monitorBadge: document.getElementById('surMonitorBadge'),
        monitorCount: document.getElementById('surMonitorCount'),
        monitorFilter: document.getElementById('surMonitorFilter'),
        btnMonitorPause: document.getElementById('btnSurMonitorPause'),
        btnMonitorClear: document.getElementById('btnSurMonitorClear'),
        btnExport: document.getElementById('btnSurExport'),
        autoscroll: document.getElementById('chkSurMonitorAutoscroll'),
        btnPreflight: document.getElementById('btnSuricataPreflight'),
    };

    let monitorSince = 0;
    let monitorPaused = false;
    let monitorRowCount = 0;
    let pollBusy = false;
    const MAX_MONITOR_ROWS = 250;
    const rowCache = new Map();

    function esc(v) {
        const d = document.createElement('div');
        d.textContent = v == null ? '' : String(v);
        return d.innerHTML;
    }

    function diagSeverityClass(sev) {
        const map = {
            critical: 'diag-sev-critical',
            error: 'diag-sev-error',
            warning: 'diag-sev-warning',
            info: 'diag-sev-info',
        };
        return map[sev] || 'diag-sev-info';
    }

    function diagSeverityBadge(sev) {
        const cls = {
            critical: 'bg-danger',
            error: 'bg-danger',
            warning: 'bg-warning text-dark',
            info: 'bg-secondary',
        }[sev] || 'bg-secondary';
        return `<span class="badge ${cls}">${esc((sev || 'info').toUpperCase())}</span>`;
    }

    function renderDiagnosticsRows(rows) {
        if (!els.diagBody) return;
        if (!rows?.length) {
            els.diagBody.innerHTML = '<tr><td colspan="4" class="empty-state py-4 text-center text-muted"><i class="bi bi-info-circle"></i> No diagnostic lines yet.</td></tr>';
            if (els.diagCount) els.diagCount.textContent = '0 rows';
            return;
        }
        els.diagBody.innerHTML = rows.map((r) => `
            <tr class="${diagSeverityClass(r.severity)}">
                <td class="text-muted">${r.line ?? '—'}</td>
                <td>${diagSeverityBadge(r.severity)}</td>
                <td><span class="badge text-bg-light border">${esc(r.category || 'general')}</span></td>
                <td class="small font-monospace text-break">${esc(r.message)}</td>
            </tr>
        `).join('');
        if (els.diagCount) els.diagCount.textContent = `${rows.length} row${rows.length === 1 ? '' : 's'}`;
        if (els.diagWrap) els.diagWrap.scrollTop = els.diagWrap.scrollHeight;
    }

    async function refreshDiagnostics() {
        try {
            const res = await fetch('/api/suricata/diagnostics');
            if (!res.ok) return;
            const data = await res.json();
            renderDiagnosticsRows(data.rows || []);
        } catch {
            /* ignore poll errors */
        }
    }

    function fmtTime(ts) {
        const d = new Date(ts * 1000);
        return d.toLocaleTimeString(undefined, { hour12: false, fractionalSecondDigits: 3 });
    }

    function fmtEndpoint(ip, port) {
        if (!ip) return '—';
        return port ? `${ip}:${port}` : ip;
    }

    function severityClass(sev) {
        const map = {
            critical: 'pkt-risk-critical',
            high: 'pkt-risk-high',
            medium: 'pkt-risk-medium',
            low: 'pkt-risk-low',
            info: 'pkt-risk-info',
        };
        return map[sev] || 'pkt-risk-info';
    }

    function severityBadge(sev) {
        const cls = {
            critical: 'bg-danger',
            high: 'bg-danger',
            medium: 'bg-warning text-dark',
            low: 'bg-info text-dark',
            info: 'bg-secondary',
        }[sev] || 'bg-secondary';
        return `<span class="badge ${cls}">${esc((sev || 'info').toUpperCase())}</span>`;
    }

    function matchesFilter(row, q) {
        if (!q) return true;
        const hay = [
            row.src_ip, row.dst_ip, row.protocol, row.info,
            row.event_type, row.source, String(row.src_port), String(row.dst_port),
        ].join(' ').toLowerCase();
        return hay.includes(q);
    }

    function buildMonitorRowHtml(row) {
        return `
            <td class="text-muted">${row.id}</td>
            <td class="font-monospace small">${fmtTime(row.timestamp)}</td>
            <td class="font-monospace small">${esc(fmtEndpoint(row.src_ip, row.src_port))}</td>
            <td class="font-monospace small">${esc(fmtEndpoint(row.dst_ip, row.dst_port))}</td>
            <td><span class="badge text-bg-light border">${esc(row.protocol)}</span></td>
            <td class="text-end">${row.length ? row.length.toLocaleString() : '—'}</td>
            <td class="small text-truncate" style="max-width:220px" title="${esc(row.info)}">${esc(row.info)}</td>
            <td>${severityBadge(row.severity)}</td>
            <td class="text-nowrap">
                <button type="button" class="btn btn-outline-secondary btn-sm py-0 sur-act-inspect" title="Inspect"><i class="bi bi-eye"></i></button>
                ${row.dst_ip ? `<button type="button" class="btn btn-outline-primary btn-sm py-0 sur-act-osint" data-ip="${esc(row.dst_ip)}" title="OSINT"><i class="bi bi-globe2"></i></button>` : ''}
                <button type="button" class="btn btn-outline-secondary btn-sm py-0 sur-act-copy" title="Copy"><i class="bi bi-clipboard"></i></button>
            </td>`;
    }

    function trimMonitorRows() {
        if (!els.monitorBody) return;
        while (els.monitorBody.rows.length > MAX_MONITOR_ROWS) {
            const first = els.monitorBody.rows[0];
            const id = first?.dataset?.id;
            if (id) rowCache.delete(id);
            els.monitorBody.deleteRow(0);
        }
    }

    function appendMonitorRows(rows) {
        if (!els.monitorBody || !rows.length) return;
        const q = (els.monitorFilter?.value || '').trim().toLowerCase();
        const filtered = rows.filter((row) => matchesFilter(row, q));
        if (!filtered.length) return;

        const empty = els.monitorBody.querySelector('.empty-state');
        if (empty) els.monitorBody.innerHTML = '';

        const fragment = document.createDocumentFragment();
        filtered.forEach((row) => {
            rowCache.set(String(row.id), row);
            const tr = document.createElement('tr');
            tr.className = severityClass(row.severity);
            tr.dataset.id = row.id;
            tr.style.cursor = 'pointer';
            tr.title = 'Click for details';
            tr.innerHTML = buildMonitorRowHtml(row);
            fragment.appendChild(tr);
            monitorRowCount += 1;
        });
        els.monitorBody.appendChild(fragment);
        trimMonitorRows();

        if (els.autoscroll?.checked !== false && els.monitorWrap) {
            els.monitorWrap.scrollTop = els.monitorWrap.scrollHeight;
        }
    }

    function handleMonitorClick(e) {
        const tr = e.target.closest('tr[data-id]');
        if (!tr || !els.monitorBody?.contains(tr)) return;
        const row = rowCache.get(tr.dataset.id);
        if (!row) return;

        if (e.target.closest('.sur-act-inspect') || (!e.target.closest('.sur-act-osint') && !e.target.closest('.sur-act-copy'))) {
            if (typeof window.socShowEventDetail === 'function') window.socShowEventDetail(row);
            return;
        }
        if (e.target.closest('.sur-act-osint')) {
            e.stopPropagation();
            const ip = e.target.closest('.sur-act-osint')?.dataset.ip;
            const sid = window.sessionId || window.liveConfig?.active_session?.session_id;
            if (ip && sid && window.openOsintForTarget) {
                window.openOsintForTarget(sid, ip, { live: true });
            }
            return;
        }
        if (e.target.closest('.sur-act-copy')) {
            e.stopPropagation();
            navigator.clipboard?.writeText(JSON.stringify(row));
        }
    }

    async function pollMonitor() {
        if (monitorPaused || pollBusy || !els.monitorBody) return;
        pollBusy = true;
        try {
            const res = await fetch(`/api/suricata/monitor?since=${monitorSince}`);
            if (!res.ok) return;
            const data = await res.json();
            const events = data.events || [];
            const st = data.status || {};

            if (els.monitorBadge) {
                if (st.running) {
                    els.monitorBadge.textContent = st.managed ? 'managed · live' : 'external · live';
                    els.monitorBadge.className = 'badge bg-success';
                } else if (st.installed) {
                    els.monitorBadge.textContent = 'stopped';
                    els.monitorBadge.className = 'badge bg-secondary';
                } else {
                    els.monitorBadge.textContent = 'not installed';
                    els.monitorBadge.className = 'badge bg-danger';
                }
            }

            if (events.length) {
                appendMonitorRows(events);
                monitorSince = Math.max(monitorSince, ...events.map((ev) => ev.id || 0));
            }

            if (els.monitorCount) {
                els.monitorCount.textContent = `${Math.min(monitorRowCount, MAX_MONITOR_ROWS)} row${monitorRowCount === 1 ? '' : 's'}`;
            }
        } catch {
            /* ignore */
        } finally {
            pollBusy = false;
        }
    }

    function clearMonitor() {
        monitorSince = 0;
        monitorRowCount = 0;
        rowCache.clear();
        if (els.monitorBody) {
            els.monitorBody.innerHTML = '<tr><td colspan="9" class="empty-state py-4 text-center text-muted"><i class="bi bi-trash"></i> Monitor cleared.</td></tr>';
        }
        if (els.monitorCount) els.monitorCount.textContent = '0 rows';
    }

    async function runPreflight() {
        const ifaceEl = document.getElementById('surIface');
        const iface = (ifaceEl?.value || '').trim();
        if (!iface) {
            if (typeof showNotice === 'function') {
                await showNotice('Interface required', 'Pick a network interface before testing Suricata config.', 'warning');
            }
            ifaceEl?.focus();
            return;
        }
        if (iface === 'lo' && !window.liveConfig?.suricata_allow_loopback) {
            if (typeof showNotice === 'function') {
                await showNotice('Loopback blocked', 'Interface lo is not allowed. Select eth0, wlan0, or your active NIC.', 'warning');
            }
            return;
        }

        const btn = els.btnPreflight;
        const original = btn?.innerHTML;
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Testing…';
        }
        try {
            const res = await fetch('/api/suricata/preflight', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: iface }),
            });
            const data = await res.json();
            if (data.diagnostics?.length) renderDiagnosticsRows(data.diagnostics);
            else await refreshDiagnostics();

            if (res.ok) {
                if (typeof showNotice === 'function') {
                    await showNotice('Preflight passed', `Config OK for ${iface}.\n\n${data.command || ''}`, 'success');
                }
            } else if (typeof showErrorDetails === 'function') {
                await showErrorDetails('Preflight failed', data);
            } else if (typeof showNotice === 'function') {
                await showNotice('Preflight failed', data.error || 'Config test failed.', 'danger');
            }
        } catch {
            if (typeof showNotice === 'function') {
                await showNotice('Network error', 'Could not reach the server.', 'danger');
            }
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = original;
            }
        }
    }

    if (els.btnDiagRefresh) els.btnDiagRefresh.addEventListener('click', refreshDiagnostics);
    if (els.btnPreflight) els.btnPreflight.addEventListener('click', runPreflight);
    if (els.btnMonitorPause) {
        els.btnMonitorPause.addEventListener('click', () => {
            monitorPaused = !monitorPaused;
            els.btnMonitorPause.innerHTML = monitorPaused
                ? '<i class="bi bi-play-fill"></i> Resume'
                : '<i class="bi bi-pause-fill"></i> Pause';
            if (!monitorPaused) pollMonitor();
        });
    }
    if (els.btnMonitorClear) els.btnMonitorClear.addEventListener('click', clearMonitor);
    if (els.btnExport) {
        els.btnExport.addEventListener('click', () => {
            window.open('/api/suricata/export?since=0&format=csv', '_blank');
        });
    }
    if (els.monitorBody) {
        els.monitorBody.addEventListener('click', handleMonitorClick);
    }

    document.addEventListener('DOMContentLoaded', () => {
        refreshDiagnostics();
        LivePollHub.register('suricata-monitor', pollMonitor, {
            interval: 5000,
            tabs: ['suricata'],
        });
        LivePollHub.register('suricata-diagnostics', refreshDiagnostics, {
            interval: 30000,
            tabs: ['suricata'],
            immediate: false,
        });
    });

    window.suricataPage = {
        refreshDiagnostics,
        renderDiagnosticsRows,
        pollMonitor,
        clearMonitor,
    };
})();
