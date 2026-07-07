/**
 * AI Triage page — batch AI status badges, deep investigate (OSINT + briefing), escalate.
 */
(function () {
    if (!document.getElementById('aiTriageTable')) return;

    const store = { allRows: [], expanded: new Set() };
    let pollBusy = false;
    let pollQueued = false;

    const COLSPAN = 7;

    function activeFilters() {
        return {
            source: document.getElementById('aiFilterSource')?.value || '',
            disposition: document.getElementById('aiFilterDisposition')?.value || '',
            search: (document.getElementById('aiFilterSearch')?.value || '').trim().toLowerCase(),
        };
    }

    function filteredRows() {
        const { source, disposition, search } = activeFilters();
        return store.allRows.filter((row) => {
            const status = row.ai_status || row.disposition;
            if (disposition && status !== disposition && row.disposition !== disposition) return false;
            if (source && !(row.sources || []).includes(source)) return false;
            if (search) {
                const hay = [
                    row.src_ip, row.dst_ip, row.attack_type, row.llm_merged_summary,
                    row.protocol, row.disposition, row.ai_status,
                ].join(' ').toLowerCase();
                if (!hay.includes(search)) return false;
            }
            return true;
        });
    }

    function esc(v) {
        const d = document.createElement('div');
        d.textContent = v == null ? '' : String(v);
        return d.innerHTML;
    }

    function fmtTime(ts) {
        return new Date(ts * 1000).toLocaleTimeString(undefined, { hour12: false });
    }

    function fmtEp(row) {
        const s = row.src_ip || '—';
        const d = row.dst_ip || '—';
        const sp = row.src_port ? `:${row.src_port}` : '';
        const dp = row.dst_port ? `:${row.dst_port}` : '';
        return `${s}${sp} → ${d}${dp}`;
    }

    function sid() {
        return window.sessionId || liveConfig?.active_session?.session_id;
    }

    async function resolveSessionId() {
        let sid = window.sessionId || liveConfig?.active_session?.session_id;
        if (sid) return sid;
        try {
            const st = await fetch('/api/live/triage/status').then((r) => r.json());
            sid = st.session_id || st.llm_packet_triage?.session_id;
            if (sid) {
                window.sessionId = sid;
                return sid;
            }
            const cfg = await fetch('/api/live/config').then((r) => r.json());
            sid = cfg.active_session?.session_id;
            if (sid) window.sessionId = sid;
            return sid || null;
        } catch {
            return null;
        }
    }

    function showNoSessionHint() {
        const tbody = document.getElementById('aiTriageBody');
        if (!tbody) return;
        tbody.innerHTML = `<tr><td colspan="${COLSPAN}" class="empty-state py-4 text-center text-muted">
            Start <strong>ML Live Monitor</strong> on the ML tab, then enable <strong>Live triage</strong> above.
            AI alerts also appear on the <a href="/live/overview">SOC Console</a> with an <span class="badge bg-info text-dark">AI</span> badge.
        </td></tr>`;
        const cnt = document.getElementById('aiTriageRowCount');
        if (cnt) cnt.textContent = '0 rows';
    }

    function sourceBadges(sources, fromAi) {
        const map = {
            suricata: 'bg-warning text-dark',
            ml: 'bg-primary',
            llm: 'bg-info text-dark',
            correlation: 'bg-danger',
            heuristic: 'bg-secondary',
        };
        let html = (sources || []).map((s) => {
            const cls = map[s] || 'bg-secondary';
            const label = s === 'llm' ? 'AI' : s.toUpperCase();
            return `<span class="badge ${cls} me-1">${esc(label)}</span>`;
        }).join('');
        if (fromAi && !(sources || []).includes('llm')) {
            html += '<span class="badge bg-info text-dark me-1">AI</span>';
        }
        return html || '<span class="text-muted">—</span>';
    }

    function statusBadge(row) {
        const status = (row.ai_status || row.disposition || 'open').toLowerCase();
        const labels = {
            true_positive: { cls: 'bg-danger', text: 'TP' },
            true_negative: { cls: 'bg-success', text: 'TN' },
            false_positive: { cls: 'bg-warning text-dark', text: 'FP' },
            benign: { cls: 'bg-success', text: 'Benign' },
            open: { cls: 'bg-secondary', text: 'Open' },
            error: { cls: 'bg-dark border', text: 'Error' },
        };
        const cfg = labels[status] || labels.open;
        const title = row.verdict_line || row.llm_merged_summary || status.replace(/_/g, ' ');
        return `<span class="badge ${cfg.cls}" title="${esc(title)}">${esc(cfg.text)}</span>`;
    }

    function sevBadge(s) {
        const sev = (s || 'info').toLowerCase();
        const cls = { critical: 'bg-danger', high: 'bg-warning text-dark', medium: 'bg-info text-dark', info: 'bg-secondary' }[sev] || 'bg-secondary';
        return `<span class="badge ${cls}">${esc(sev)}</span>`;
    }

    function isPublicIp(ip) {
        if (!ip || typeof ip !== 'string') return false;
        if (ip.includes(':')) return !ip.startsWith('fe80') && ip !== '::1';
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
        if (parts[0] === 10) return false;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
        if (parts[0] === 192 && parts[1] === 168) return false;
        if (parts[0] === 127) return false;
        if (parts[0] >= 224) return false;
        return true;
    }

    function updateKpis(stats, llm) {
        const by = stats?.by_disposition || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        set('aiKpiOpen', by.open || 0);
        set('aiKpiTp', by.true_positive || 0);
        set('aiKpiFp', by.false_positive || 0);
        set('aiKpiTn', (by.true_negative || 0) + (by.benign || 0));
        set('aiKpiErrors', by.error || 0);
        const st = llm?.stats || {};
        const elapsed = llm?.elapsed_sec || 0;
        const rate = elapsed > 0 ? ((st.llm_calls || 0) / elapsed * 60).toFixed(1) : '—';
        set('aiKpiLlmRate', rate);
        const badge = document.getElementById('aiTriageRunnerBadge');
        if (badge) {
            badge.textContent = llm?.running ? 'running' : 'idle';
            badge.className = `badge ${llm?.running ? 'bg-success' : 'bg-secondary'}`;
        }
        const toggle = document.getElementById('aiTriageToggle');
        if (toggle && llm) toggle.checked = !!llm.running;
        const stackEl = document.getElementById('aiTriageModelStack');
        if (stackEl && llm?.model_stack?.length) {
            const batch = llm.batch_size ? ` · batch ${llm.batch_size}` : '';
            stackEl.textContent = llm.model_stack.join(' · ') + batch;
            stackEl.className = 'badge bg-info text-dark';
        }
        renderContextFeed(llm?.context_log || []);
    }

    function renderContextFeed(entries) {
        const feed = document.getElementById('aiLiveContextFeed');
        const cnt = document.getElementById('aiContextCount');
        if (!feed) return;
        if (cnt) cnt.textContent = `${entries.length} events`;
        if (!entries.length) {
            feed.innerHTML = '<div class="text-muted small p-3">Enable live triage to stream batch packet classification here.</div>';
            return;
        }
        feed.innerHTML = entries.map((e) => `
            <div class="ai-context-row border-bottom border-secondary px-3 py-2 small">
                <div class="d-flex justify-content-between text-muted font-monospace mb-1">
                    <span>${fmtTime(e.timestamp)}</span>
                    <span>${esc(e.connection || '')}</span>
                </div>
                <div><span class="badge bg-info text-dark me-1">AI</span>${esc(e.merged || e.disposition || '—')}</div>
                ${(e.errors || []).length ? `<div class="text-warning mt-1">${esc(e.errors.join(' · '))}</div>` : ''}
            </div>`).join('');
    }

    function renderActions(row) {
        return `<div class="d-flex flex-wrap gap-1">
            <button type="button" class="btn btn-outline-info btn-sm py-0 ai-btn-deep" data-id="${esc(row.id)}" data-dst="${esc(row.dst_ip || '')}" title="OSINT + AI briefing">Deep Investigate</button>
            <button type="button" class="btn btn-outline-danger btn-sm py-0 ai-btn-escalate" data-id="${esc(row.id)}" title="Email escalation">Escalate</button>
        </div>`;
    }

    function renderTable() {
        const tbody = document.getElementById('aiTriageBody');
        const cnt = document.getElementById('aiTriageRowCount');
        if (!tbody) return;
        const rows = filteredRows();
        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="${COLSPAN}" class="empty-state py-4 text-center text-muted">No incidents match filters.</td></tr>`;
            if (cnt) cnt.textContent = '0 rows';
            return;
        }
        if (cnt) cnt.textContent = `${rows.length} rows`;
        tbody.innerHTML = rows.map((row) => {
            const exp = store.expanded.has(row.id);
            const actions = renderActions(row);
            const detail = exp ? renderExpand(row) : '';
            return `<tr class="ai-triage-row" data-id="${esc(row.id)}">
                <td><button type="button" class="btn btn-link btn-sm p-0 ai-btn-expand" data-id="${esc(row.id)}"><i class="bi bi-chevron-${exp ? 'down' : 'right'}"></i></button></td>
                <td class="small font-monospace">${fmtTime(row.timestamp)}</td>
                <td class="small font-monospace">${esc(fmtEp(row))}</td>
                <td>${sourceBadges(row.sources, row.from_ai)}</td>
                <td>${statusBadge(row)}</td>
                <td>${sevBadge(row.severity)}</td>
                <td class="small">${actions}</td>
            </tr>${detail}`;
        }).join('');

        tbody.querySelectorAll('.ai-btn-expand').forEach((btn) => {
            btn.addEventListener('click', () => {
                const id = btn.dataset.id;
                if (store.expanded.has(id)) store.expanded.delete(id);
                else store.expanded.add(id);
                renderTable();
            });
        });
        tbody.querySelectorAll('.ai-btn-deep').forEach((btn) => {
            btn.addEventListener('click', () => deepInvestigate(btn.dataset.id, btn.dataset.dst));
        });
        tbody.querySelectorAll('.ai-btn-escalate').forEach((btn) => {
            btn.addEventListener('click', () => {
                const session = sid();
                if (window.openEscalationCompose && session) {
                    window.openEscalationCompose({
                        context_type: 'incident',
                        session_id: session,
                        incident_id: btn.dataset.id,
                    });
                }
            });
        });
    }

    function renderExpand(row) {
        const summary = row.llm_merged_summary || row.verdict_line || '—';
        return `<tr class="table-secondary"><td colspan="${COLSPAN}" class="small p-3">
            <div class="row g-3">
                <div class="col-md-12"><strong>Summary</strong><p class="mb-0 mt-1">${esc(summary)}</p></div>
                <div class="col-md-4"><strong>Primary LLM</strong><pre class="small bg-black border border-secondary p-2 mt-1 mb-0">${esc(JSON.stringify(row.llm_primary || {}, null, 2))}</pre></div>
                <div class="col-md-4"><strong>Secondary</strong><pre class="small bg-black border border-secondary p-2 mt-1 mb-0">${esc(JSON.stringify(row.llm_secondary || {}, null, 2))}</pre></div>
                <div class="col-md-4"><strong>3rd model</strong><pre class="small bg-black border border-secondary p-2 mt-1 mb-0">${esc(JSON.stringify(row.llm_tertiary || {}, null, 2))}</pre></div>
                <div class="col-md-6"><strong>Packet</strong><pre class="small bg-black border border-secondary p-2 mt-1 mb-0">${esc(JSON.stringify(row.packet || {}, null, 2))}</pre></div>
                <div class="col-md-6"><strong>Errors / indicators</strong>
                    <div class="mt-1">${(row.errors || []).map((e) => `<div class="text-warning">${esc(e)}</div>`).join('') || '<span class="text-muted">None</span>'}</div>
                    <div class="mt-1">${(row.indicators || []).map((i) => `<span class="badge bg-dark border me-1">${esc(i)}</span>`).join('')}</div>
                </div>
            </div>
        </td></tr>`;
    }

    async function pollIncidents() {
        if (pollBusy) {
            pollQueued = true;
            return;
        }
        pollBusy = true;
        try {
            const sessionId = await resolveSessionId();
            if (!sessionId) {
                showNoSessionHint();
                return;
            }
            const params = new URLSearchParams({ session_id: sessionId, limit: '200' });
            const incRes = await fetch(`/api/live/triage/incidents?${params}`);
            if (incRes.ok) {
                const data = await incRes.json();
                store.allRows = data.incidents || [];
                renderTable();
            }
            const stRes = await fetch(`/api/live/triage/status?session_id=${sessionId}`);
            if (stRes.ok) {
                const st = await stRes.json();
                if (st.session_id && !window.sessionId) window.sessionId = st.session_id;
                updateKpis(st.registry, st.llm_packet_triage);
            }
        } catch { /* ignore */ }
        finally {
            pollBusy = false;
            if (pollQueued) {
                pollQueued = false;
                pollIncidents();
            }
        }
    }

    async function toggleTriage(enabled) {
        const sessionId = await resolveSessionId();
        try {
            const res = await fetch('/api/live/llm-packets', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled, session_id: sessionId }),
            });
            const data = await res.json();
            if (typeof showInlineFeedback === 'function') {
                showInlineFeedback(data.message || data.error || (enabled ? 'Started' : 'Stopped'), res.ok ? 'info' : 'danger', 'AI Triage');
            }
            pollIncidents();
        } catch {
            if (typeof showInlineFeedback === 'function') showInlineFeedback('Toggle failed', 'danger', 'AI Triage');
        }
    }

    async function testModels() {
        const btn = document.getElementById('aiTriageTestModels');
        if (btn) btn.disabled = true;
        if (typeof showInlineFeedback === 'function') {
            showInlineFeedback('Probing models one at a time (≈12s each)…', 'info', 'LLM test');
        }
        try {
            const res = await fetch('/api/llm/test', { method: 'POST' });
            const data = await res.json();
            let msg = data.error || (data.ok ? 'At least one model OK' : 'All probes failed');
            if (data.results) {
                msg = Object.entries(data.results).map(([k, v]) => {
                    if (v.skipped) return `${k}: skipped (${v.error || 'backoff'})`;
                    return `${k}: ${v.ok ? 'OK' : (v.error || 'fail')} (${v.latency_ms || '?'}ms)`;
                }).join(' · ');
            }
            if (typeof showInlineFeedback === 'function') {
                showInlineFeedback(msg, data.ok ? 'success' : 'warning', 'LLM test');
            }
        } catch (e) {
            if (typeof showInlineFeedback === 'function') {
                showInlineFeedback(`Probe request failed: ${e}`, 'danger', 'LLM test');
            }
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function deepInvestigate(incidentId, dstIp) {
        const sessionId = sid();
        const body = document.getElementById('aiDeepInspectBody');
        const drawer = document.getElementById('aiDeepInspectDrawer');
        if (!sessionId || !body) return;

        const row = store.allRows.find((r) => r.id === incidentId) || {};
        body.innerHTML = '<div class="text-muted"><span class="spinner-border spinner-border-sm"></span> Running OSINT + AI briefing…</div>';
        bootstrap.Offcanvas.getOrCreateInstance(drawer).show();

        const parse = window.fetchJsonOrThrow || ((r) => r.json());
        const inspectPromise = fetch('/api/live/triage/inspect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, incident_id: incidentId }),
        }).then(parse);

        const osintPromise = (dstIp && isPublicIp(dstIp))
            ? fetch(`/api/live/osint/${encodeURIComponent(sessionId)}/${encodeURIComponent(dstIp)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ summarize: true, detail_level: 'brief' }),
            }).then(parse).catch(() => null)
            : Promise.resolve(null);

        try {
            const [inspectData, osintData] = await Promise.all([inspectPromise, osintPromise]);
            const parts = [];

            parts.push(`<div class="mb-3">${statusBadge(row)} ${sevBadge(row.severity || 'info')}</div>`);

            if (osintData?.ok) {
                const verdict = osintData.verdict || osintData.overall_verdict || 'unknown';
                const brief = osintData.ai_summary || osintData.summary || '';
                parts.push(`<div class="border border-secondary rounded p-2 mb-3">
                    <h6 class="mb-2"><i class="bi bi-globe2"></i> OSINT — ${esc(dstIp)}</h6>
                    <p class="mb-1"><strong>Verdict:</strong> ${esc(verdict)}</p>
                    ${brief ? `<p class="small text-muted mb-0">${esc(brief)}</p>` : ''}
                </div>`);
            } else if (dstIp && !isPublicIp(dstIp)) {
                parts.push(`<div class="text-muted small mb-3">OSINT skipped — ${esc(dstIp)} is private/local.</div>`);
            }

            if (inspectData?.ok && inspectData.analysis) {
                parts.push(`<div class="ai-deep-markdown small">${esc(inspectData.analysis).replace(/\n/g, '<br>')}</div>`);
            } else {
                parts.push(`<div class="text-danger">${esc(inspectData?.error || 'Inspect failed')}</div>`);
            }

            body.innerHTML = parts.join('');
        } catch (e) {
            body.innerHTML = `<div class="text-danger">${esc(String(e))}</div>`;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('aiTriageToggle')?.addEventListener('change', (e) => toggleTriage(e.target.checked));
        document.getElementById('aiTriageTestModels')?.addEventListener('click', testModels);
        ['aiFilterSource', 'aiFilterDisposition', 'aiFilterSearch'].forEach((id) => {
            document.getElementById(id)?.addEventListener('input', renderTable);
            document.getElementById(id)?.addEventListener('change', renderTable);
        });
        LivePollHub.register('ai-incidents', pollIncidents, { interval: 5000, tabs: ['ai_triage'] });
        if (LivePollHub.activeTab() === 'ai_triage') {
            fetch('/api/live/llm-packets').then((r) => r.json()).then((d) => {
                const toggle = document.getElementById('aiTriageToggle');
                if (toggle) toggle.checked = !!d.running;
                updateKpis({}, d);
            }).catch(() => {});
        }
    });
})();
