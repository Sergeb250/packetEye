/**
 * Wireshark-style live packet view on /live/capture
 */
(function () {
    const body = document.getElementById('livePacketBody');
    if (!body) return;

    const els = {
        body,
        wrap: document.getElementById('livePacketWrap'),
        count: document.getElementById('livePktCount'),
        rate: document.getElementById('livePktRate'),
        feedBadge: document.getElementById('liveFeedBadge'),
        filter: document.getElementById('livePktFilter'),
        pause: document.getElementById('btnPktPause'),
        clear: document.getElementById('btnPktClear'),
        autoscroll: document.getElementById('chkPktAutoscroll'),
    };

    let sinceId = 0;
    let paused = false;
    let pollTimer = null;
    let rowCount = 0;
    let lastRateTs = Date.now();
    let lastRateCount = 0;
    const MAX_ROWS = 400;

    function esc(v) {
        const d = document.createElement('div');
        d.textContent = v == null ? '' : String(v);
        return d.innerHTML;
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
        return `<span class="badge ${cls}">${esc(sev.toUpperCase())}</span>`;
    }

    function matchesFilter(row, q) {
        if (!q) return true;
        const hay = [
            row.src_ip, row.dst_ip, row.protocol, row.info,
            row.event_type, row.source, String(row.src_port), String(row.dst_port),
        ].join(' ').toLowerCase();
        return hay.includes(q);
    }

    function appendRow(row) {
        const q = (els.filter?.value || '').trim().toLowerCase();
        if (!matchesFilter(row, q)) return;

        const empty = body.querySelector('.empty-state');
        if (empty) empty.remove();

        const tr = document.createElement('tr');
        tr.className = severityClass(row.severity);
        tr.dataset.id = row.id;
        tr.style.cursor = 'pointer';
        tr.title = 'Click for details';
        tr.innerHTML = `
            <td class="text-muted">${row.id}</td>
            <td class="font-monospace small">${fmtTime(row.timestamp)}</td>
            <td class="font-monospace small">${esc(fmtEndpoint(row.src_ip, row.src_port))}</td>
            <td class="font-monospace small">${esc(fmtEndpoint(row.dst_ip, row.dst_port))}</td>
            <td><span class="badge text-bg-light border">${esc(row.protocol)}</span></td>
            <td class="text-end">${row.length ? row.length.toLocaleString() : '—'}</td>
            <td class="small text-truncate" style="max-width:280px" title="${esc(row.info)}">${esc(row.info)}</td>
            <td>${severityBadge(row.severity)}</td>
        `;
        body.appendChild(tr);
        tr.addEventListener('click', () => {
            if (typeof window.socShowEventDetail === 'function') {
                window.socShowEventDetail(row);
                if (window.livePage !== 'overview') window.location.href = '/live/overview';
            }
        });
        rowCount += 1;

        while (body.rows.length > MAX_ROWS) {
            body.deleteRow(0);
        }

        if (els.autoscroll?.checked !== false && els.wrap) {
            els.wrap.scrollTop = els.wrap.scrollHeight;
        }
    }

    async function pollPackets() {
        if (paused) return;
        try {
            const res = await fetch(`/api/capture/packets?since=${sinceId}`);
            if (!res.ok) return;
            const data = await res.json();
            const packets = data.packets || [];
            const st = data.status || {};

            if (els.feedBadge) {
                if (st.running) {
                    els.feedBadge.textContent = `live · ${st.mode || '?'}`;
                    els.feedBadge.className = 'badge bg-success';
                } else {
                    els.feedBadge.textContent = 'waiting for capture';
                    els.feedBadge.className = 'badge bg-secondary';
                }
            }

            packets.forEach((p) => {
                if (p.id > sinceId) {
                    appendRow(p);
                    sinceId = p.id;
                }
            });

            if (els.count) els.count.textContent = `${rowCount.toLocaleString()} rows`;
            const now = Date.now();
            const dt = (now - lastRateTs) / 1000;
            if (dt >= 1) {
                const rate = Math.round((rowCount - lastRateCount) / dt);
                if (els.rate) els.rate.textContent = `${rate}/s`;
                lastRateTs = now;
                lastRateCount = rowCount;
            }
        } catch {
            /* retry next tick */
        }
    }

    async function ensureFeedRunning() {
        try {
            const res = await fetch('/api/capture/status');
            if (!res.ok) return;
            const s = await res.json();
            if (s.running && !(s.live_feed || {}).running) {
                /* feed starts with capture; if page opened mid-session, poll still works once feed catches up */
            }
        } catch {
            /* ignore */
        }
    }

    if (els.pause) {
        els.pause.addEventListener('click', () => {
            paused = !paused;
            els.pause.innerHTML = paused
                ? '<i class="bi bi-play-fill"></i> Resume'
                : '<i class="bi bi-pause-fill"></i> Pause';
            els.pause.classList.toggle('btn-warning', paused);
            els.pause.classList.toggle('btn-outline-secondary', !paused);
        });
    }

    if (els.clear) {
        els.clear.addEventListener('click', async () => {
            await fetch('/api/capture/packets/clear', { method: 'POST' });
            body.innerHTML = '<tr><td colspan="8" class="empty-state text-center py-4 text-muted"><i class="bi bi-eye"></i> Live view cleared. New packets will appear when capture is running.</td></tr>';
            sinceId = 0;
            rowCount = 0;
            if (els.count) els.count.textContent = '0 rows';
        });
    }

    if (els.filter) {
        els.filter.addEventListener('input', () => {
            /* filter applies to new rows only — clearing refilters on next poll cycle */
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        ensureFeedRunning();
        pollPackets();
        pollTimer = setInterval(pollPackets, 800);
    });

    window.addEventListener('beforeunload', () => {
        if (pollTimer) clearInterval(pollTimer);
    });
})();
