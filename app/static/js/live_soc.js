/**
 * SOC Console — alert queue, inspector, insights, clickable event stream.
 */
(function () {
    if (!document.getElementById('socAlertQueue')) return;

    const store = { alerts: [], events: [], selectedId: null, filterSeverity: '', filterSource: '', triageByConn: {} };
    let streamSince = 0;

    function esc(v) {
        const d = document.createElement('div');
        d.textContent = v == null ? '' : String(v);
        return d.innerHTML;
    }

    function fmtTime(ts) {
        return new Date(ts * 1000).toLocaleTimeString(undefined, { hour12: false, fractionalSecondDigits: 3 });
    }

    function fmtEp(ip, port) {
        if (!ip) return '—';
        return port ? `${ip}:${port}` : ip;
    }

    function alertKey(a) {
        return a.id || `${a.timestamp}-${a.src_ip}-${a.dst_ip}-${a.type}`;
    }

    function buildAlertInsight(a) {
        const enh = a.enhanced || {};
        if (enh.summary) {
            return {
                headline: enh.probable_attack_type
                    ? `${enh.probable_attack_type}${enh.confidence != null ? ` (${Math.round(enh.confidence * 100)}% conf.)` : ''}`
                    : (a.signature || `ML anomaly — score ${(a.anomaly_score || 0).toFixed(1)}`),
                body: enh.summary,
                action: enh.recommended_action || 'Review network context and OSINT verdict below.',
            };
        }
        const src = fmtEp(a.src_ip, a.src_port);
        const dst = fmtEp(a.dst_ip, a.dst_port);
        const proto = a.protocol || 'TCP';

        if (a.type === 'llm') {
            return {
                headline: `AI alert — ${a.attack_type || 'suspicious traffic'}`,
                body: `${a.explanation || '3-model AI triage flagged this connection.'} Confidence: ${a.confidence != null ? Math.round(a.confidence * 100) + '%' : 'n/a'}. Models: ${a.models || 'Z.ai+NVIDIA'}.`,
                action: 'Review AI Triage tab for per-model JSON and set TP/FP/TN verdict.',
            };
        }
        if (a.type === 'correlation') {
            return {
                headline: 'Correlated threat — signature + ML agree',
                body: `Suricata matched "${a.signature || 'a rule'}" and the ML engine scored the same flow (${(a.anomaly_score || 0).toFixed(1)}). This is high-confidence suspicious activity between ${src} and ${dst}. Priority: isolate source and verify destination.`,
                action: 'Isolate the source host and investigate the destination with OSINT.',
            };
        }
        if (a.type === 'suricata') {
            return {
                headline: `Rule hit: ${a.signature || 'Suricata signature'}`,
                body: `IDS detected "${a.signature || 'signature'}" on ${proto} traffic from ${src} to ${dst}. Category: ${a.category || 'general'}. Confirm whether this service and destination are expected in your environment.`,
                action: 'Validate the signature against known-good traffic; block or tune the rule if false positive.',
            };
        }
        const score = a.anomaly_score || 0;
        return {
            headline: `ML anomaly — score ${score.toFixed(1)}`,
            body: `Traffic from ${src} to ${dst} (${proto}) deviates from the learned baseline. ${a.explanation || 'Review timing, volume, and destination reputation for C2 or data exfil patterns.'}`,
            action: 'Check if destination is external; run OSINT and compare with asset inventory.',
        };
    }

    function buildEventInsight(ev) {
        const src = fmtEp(ev.src_ip, ev.src_port);
        const dst = fmtEp(ev.dst_ip, ev.dst_port);
        const sev = (ev.severity || 'info').toLowerCase();
        if (ev.event_type === 'alert') {
            return {
                headline: 'Suricata alert event',
                body: `${ev.info || 'Signature hit'} between ${src} and ${dst}.`,
                action: 'Correlate with ML alerts if the same hosts appear in the queue.',
            };
        }
        if (sev === 'critical' || sev === 'high') {
            return {
                headline: 'High-risk network activity',
                body: `${ev.event_type || 'event'}: ${ev.info || '—'} (${src} → ${dst}).`,
                action: 'Review payload context in Suricata tab; escalate if destination is unknown external IP.',
            };
        }
        return {
            headline: `${(ev.event_type || 'event').toUpperCase()} — ${ev.protocol || ''}`,
            body: `${ev.info || 'Network event'} from ${src} to ${dst}.`,
            action: sev === 'medium' ? 'Monitor for repetition or beaconing intervals.' : 'Informational — no immediate action required.',
        };
    }

    function severityBadge(sev) {
        const s = (sev || 'info').toLowerCase();
        const cls = { critical: 'bg-danger', high: 'bg-warning text-dark', medium: 'bg-info text-dark', info: 'bg-secondary' }[s] || 'bg-secondary';
        return `<span class="badge ${cls}">${esc(s.toUpperCase())}</span>`;
    }

    function sourceBadge(a) {
        const map = {
            suricata: '<span class="badge bg-warning text-dark">IDS</span>',
            ml: '<span class="badge bg-primary">ML</span>',
            llm: '<span class="badge bg-info text-dark"><i class="bi bi-robot"></i> AI</span>',
            correlation: '<span class="badge bg-danger">CORR</span>',
        };
        return map[a.type] || map.ml;
    }

    function connKey(a) {
        return [a.src_ip, a.dst_ip, a.src_port, a.dst_port].join('|');
    }

    function triageBlock(a) {
        const row = store.triageByConn[connKey(a)];
        if (!row) return '';
        const p = row.llm_primary || {};
        const s = row.llm_secondary || {};
        return `
            <div class="soc-insight-box mb-3 border-info">
                <div class="soc-insight-label"><i class="bi bi-robot"></i> AI triage (linked)</div>
                <p class="mb-1 small"><strong>Primary:</strong> ${esc(p.attack_type || p.summary || '—')} ${p.confidence != null ? `(${Math.round(p.confidence * 100)}%)` : ''}</p>
                <p class="mb-1 small"><strong>Secondary:</strong> ${esc(s.attack_type || s.summary || '—')} ${s.confidence != null ? `(${Math.round(s.confidence * 100)}%)` : ''}</p>
                ${row.llm_merged_summary ? `<p class="mb-0 small text-muted">${esc(row.llm_merged_summary)}</p>` : ''}
                <a href="/live/ai-triage" class="btn btn-outline-info btn-sm mt-2">Open AI Triage →</a>
            </div>`;
    }

    function updateKpis() {
        const counts = { critical: 0, high: 0, medium: 0, info: 0 };
        const srcCounts = { suricata: 0, ml: 0, llm: 0, correlation: 0 };
        store.alerts.forEach((a) => {
            const s = (a.severity || 'medium').toLowerCase();
            if (counts[s] != null) counts[s] += 1;
            else counts.medium += 1;
            const t = (a.type || '').toLowerCase();
            if (srcCounts[t] != null) srcCounts[t] += 1;
        });
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        set('socKpiCritical', counts.critical);
        set('socKpiHigh', counts.high);
        set('socKpiMedium', counts.medium + counts.info);
        const totalEl = document.getElementById('socKpiAlerts');
        if (totalEl) {
            totalEl.textContent = window.socServerTotal != null ? window.socServerTotal : store.alerts.length;
            const breakdown = Object.entries(srcCounts).filter(([, n]) => n).map(([k, n]) => `${k}:${n}`).join(' · ');
            totalEl.title = breakdown ? `By source — ${breakdown}` : 'Total findings (server)';
        }
        set('socQueueCount', `${store.alerts.length} open`);
    }

    function renderInsightsList() {
        const el = document.getElementById('socInsightsList');
        if (!el) return;
        const recent = store.alerts.slice(-5).reverse();
        if (!recent.length) {
            el.innerHTML = '<div class="text-muted">No active threats — sensor operating normally.</div>';
            return;
        }
        el.innerHTML = recent.map((a) => {
            const ins = buildAlertInsight(a);
            return `<div class="soc-insight-item severity-${a.severity || 'medium'}">
                <div class="fw-semibold">${esc(ins.headline)}</div>
                <div class="text-muted">${esc(ins.body.slice(0, 120))}${ins.body.length > 120 ? '…' : ''}</div>
            </div>`;
        }).join('');
    }

    function filteredAlerts() {
        return store.alerts.filter((a) => {
            if (store.filterSeverity && (a.severity || '').toLowerCase() !== store.filterSeverity) return false;
            if (store.filterSource && (a.type || '').toLowerCase() !== store.filterSource) return false;
            return true;
        });
    }

    function renderQueue() {
        const queue = document.getElementById('socAlertQueue');
        const empty = document.getElementById('socQueueEmpty');
        if (!queue) return;

        const visible = filteredAlerts();
        if (!visible.length) {
            if (empty) empty.classList.remove('d-none');
            queue.querySelectorAll('.soc-alert-row').forEach((r) => r.remove());
            updateKpis();
            return;
        }
        if (empty) empty.classList.add('d-none');

        const sorted = visible.slice().sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        queue.innerHTML = sorted.map((a) => {
            const key = alertKey(a);
            const ins = buildAlertInsight(a);
            const selected = store.selectedId === key ? ' selected' : '';
            return `<button type="button" class="soc-alert-row severity-${a.severity || 'medium'}${selected}" data-alert-key="${esc(key)}">
                <div class="soc-alert-row-top">
                    ${severityBadge(a.severity)}
                    ${sourceBadge(a)}
                    <span class="soc-alert-time">${fmtTime(a.timestamp || Date.now() / 1000)}</span>
                </div>
                <div class="soc-alert-headline">${esc(ins.headline)}</div>
                <div class="soc-alert-flow font-monospace">${esc(fmtEp(a.src_ip, a.src_port))} → ${esc(fmtEp(a.dst_ip, a.dst_port))}</div>
            </button>`;
        }).join('');

        queue.querySelectorAll('.soc-alert-row').forEach((btn) => {
            btn.addEventListener('click', () => {
                const a = store.alerts.find((x) => alertKey(x) === btn.dataset.alertKey);
                if (a) selectAlert(a);
            });
        });
        updateKpis();
        renderInsightsList();
    }

    function renderInspectorActions(ctx) {
        const sid = window.sessionId || liveConfig?.active_session?.session_id;
        const parts = [];
        if (ctx.finding_id) {
            parts.push(`<button type="button" class="btn btn-info btn-sm btn-soc-investigate" data-finding-id="${esc(ctx.finding_id)}"><i class="bi bi-search"></i> Investigate</button>`);
        }
        if (ctx.dst_ip && sid) {
            parts.push(`<button type="button" class="btn btn-outline-primary btn-sm btn-soc-osint" data-ip="${esc(ctx.dst_ip)}"><i class="bi bi-globe2"></i> OSINT</button>`);
            parts.push(`<button type="button" class="btn btn-outline-secondary btn-sm btn-soc-map" data-ip="${esc(ctx.dst_ip)}"><i class="bi bi-map"></i> Map</button>`);
        }
        parts.push(`<a href="/live/ml" class="btn btn-outline-secondary btn-sm"><i class="bi bi-cpu"></i> ML</a>`);
        parts.push(`<button type="button" class="btn btn-info btn-sm btn-soc-ai"><i class="bi bi-robot"></i> Ask AI</button>`);
        parts.push(`<button type="button" class="btn btn-outline-danger btn-sm btn-soc-escalate"><i class="bi bi-envelope-exclamation"></i> Escalate</button>`);
        return parts.join(' ');
    }

    function wireInspectorActions(container, ctx) {
        container.querySelector('.btn-soc-investigate')?.addEventListener('click', (e) => {
            if (typeof investigateFinding === 'function') investigateFinding(e.target.dataset.findingId);
        });
        container.querySelector('.btn-soc-osint')?.addEventListener('click', (e) => {
            const ip = e.target.closest('.btn-soc-osint')?.dataset.ip || e.target.dataset.ip;
            const sid = window.sessionId || liveConfig?.active_session?.session_id;
            if (!ip || !sid || !window.openOsintForTarget) return;
            const inspector = document.getElementById('socInspector');
            if (inspector) {
                inspector.innerHTML = `
                    <div class="soc-inspector-content text-center py-4">
                        <div class="spinner-border text-info mb-3" role="status"></div>
                        <div class="fw-semibold">OSINT + AI summary</div>
                        <div class="small text-muted font-monospace">${esc(ip)}</div>
                        <p class="small text-muted mb-0 mt-2">Querying threat intel providers and generating analyst summary…</p>
                    </div>`;
                document.getElementById('socInspectorCard')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
            window.openOsintForTarget(sid, ip, {
                live: true,
                alertContext: ctx,
                onComplete: (data, aiSummary) => {
                    if (!inspector) return;
                    const mal = data.is_malicious;
                    const abuse = data.enrichment_json?.abuseipdb;
                    const geo = data.enrichment_json?.geo;
                    const idb = data.enrichment_json?.internetdb;
                    const summaryHtml = aiSummary?.summary ? `
                        <div class="soc-insight-box mb-3 border-info">
                            <div class="soc-insight-label"><i class="bi bi-robot"></i> AI OSINT summary</div>
                            <span class="badge ${aiSummary.verdict === 'malicious' ? 'bg-danger' : aiSummary.verdict === 'suspicious' ? 'bg-warning text-dark' : 'bg-success'} mb-2">${esc(aiSummary.verdict || 'unknown')}</span>
                            <p class="small mb-0">${esc(aiSummary.summary)}</p>
                        </div>` : '';
                    inspector.innerHTML = `
                        <div class="soc-inspector-content">
                            <div class="d-flex flex-wrap gap-2 align-items-center mb-2">
                                <span class="badge ${mal ? 'bg-danger' : 'bg-success'}">TI: ${mal ? 'Malicious' : 'Clean'}</span>
                                <span class="badge bg-secondary">${Math.round((data.confidence || 0) * 100)}% conf.</span>
                            </div>
                            <h6 class="mb-2 font-monospace">${esc(ip)}</h6>
                            ${summaryHtml}
                            <dl class="row small mb-3">
                                ${geo?.country ? `<dt class="col-4 text-muted">Geo</dt><dd class="col-8">${esc(geo.city || '')} ${esc(geo.country)} (${esc(geo.isp || geo.org || '')})</dd>` : ''}
                                ${abuse?.abuseConfidenceScore != null ? `<dt class="col-4 text-muted">AbuseIPDB</dt><dd class="col-8">${esc(abuse.abuseConfidenceScore)}% · ${esc(abuse.usageType || '')}</dd>` : ''}
                                ${idb?.tags?.length ? `<dt class="col-4 text-muted">Tags</dt><dd class="col-8">${esc(idb.tags.join(', '))}</dd>` : ''}
                            </dl>
                            <div class="d-flex flex-wrap gap-2">
                                <button type="button" class="btn btn-outline-info btn-sm" id="socOsintShowDetail"><i class="bi bi-list-ul"></i> Full OSINT detail</button>
                                <button type="button" class="btn btn-outline-primary btn-sm" id="socOsintMoreDetail"><i class="bi bi-arrows-expand"></i> More detail</button>
                                ${ctx.finding_id ? `<button type="button" class="btn btn-info btn-sm btn-soc-investigate" data-finding-id="${esc(ctx.finding_id)}"><i class="bi bi-search"></i> Investigate</button>` : ''}
                            </div>
                        </div>`;
                    inspector.querySelector('#socOsintShowDetail')?.addEventListener('click', () => {
                        document.getElementById('liveOsintPanel')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    });
                    inspector.querySelector('#socOsintMoreDetail')?.addEventListener('click', () => {
                        window.openOsintForTarget(sid, ip, {
                            live: true,
                            alertContext: ctx,
                            detailLevel: 'detailed',
                            onComplete: (d, ai) => {
                                if (!inspector || !ai?.summary) return;
                                const block = inspector.querySelector('.soc-insight-box');
                                if (block) {
                                    block.innerHTML = `
                                        <div class="soc-insight-label"><i class="bi bi-robot"></i> AI OSINT summary (detailed)</div>
                                        <span class="badge bg-info text-dark mb-2">${esc(ai.verdict || 'unknown')}</span>
                                        <p class="small mb-0">${esc(ai.summary)}</p>
                                        ${ai.recommended_action ? `<p class="small fw-semibold mt-2 mb-0">${esc(ai.recommended_action)}</p>` : ''}`;
                                }
                            },
                        });
                    });
                    wireInspectorActions(inspector, ctx);
                },
            });
        });
        container.querySelector('.btn-soc-map')?.addEventListener('click', async (e) => {
            const ip = e.target.dataset.ip;
            const sid = window.sessionId || liveConfig?.active_session?.session_id;
            const mapPanel = document.getElementById('liveThreatMapPanel');
            const canvas = document.getElementById('liveThreatMapCanvas');
            if (!mapPanel || !canvas || !sid) return;
            mapPanel.classList.remove('d-none');
            canvas.innerHTML = '';
            try {
                const res = await fetch(`/api/analysis/${sid}/geo`);
                const data = res.ok ? await res.json() : { markers: [] };
                let markers = data.markers || [];
                if (ip) markers = markers.filter((m) => m.ip === ip);
                if (markers.length && window.renderThreatMap) {
                    window.renderThreatMap('liveThreatMapCanvas', markers);
                    mapPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                } else if (typeof showInlineFeedback === 'function') {
                    showInlineFeedback('Run Investigate/OSINT first to populate geo data.', 'warning', 'Map');
                }
            } catch { /* ignore */ }
        });
        container.querySelector('.btn-soc-ai')?.addEventListener('click', () => {
            const sid = window.sessionId || liveConfig?.active_session?.session_id;
            if (!window.openChatWithContext) return;
            window.openChatWithContext(
                'Quick take on this live alert.',
                sid,
                ctx.finding_id || null,
                { type: ctx.event_type ? 'live_event' : 'live_alert', raw: ctx, raw_event: ctx.raw_event || null },
                ctx.flow_id || null,
            );
        });
        container.querySelector('.btn-soc-escalate')?.addEventListener('click', () => {
            const sid = window.sessionId || liveConfig?.active_session?.session_id;
            if (!window.openEscalationCompose) return;
            window.openEscalationCompose({
                context_type: 'alert',
                session_id: sid,
                alert_id: ctx.finding_id || ctx.id,
            });
        });
    }

    function renderEnhancedBlock(a) {
        const enh = a.enhanced || {};
        if (!enh.probable_attack_type && !enh.osint) return '';
        let osintHtml = '';
        const vt = enh.osint?.virustotal || enh.osint?.enrichment?.virustotal;
        if (vt && vt.malicious != null) {
            osintHtml = `<div class="small mt-2"><strong>OSINT:</strong> VT ${vt.malicious}/${(vt.malicious || 0) + (vt.harmless || 0) + (vt.undetected || 0)} malicious</div>`;
        }
        return `
            <div class="soc-insight-box mb-3 border-primary">
                <div class="soc-insight-label"><i class="bi bi-shield-check"></i> Enhanced analysis</div>
                ${enh.probable_attack_type ? `<p class="mb-1 small"><strong>Probable attack:</strong> ${esc(enh.probable_attack_type)} ${enh.false_positive_risk ? `<span class="badge bg-light text-dark border">FP risk: ${esc(enh.false_positive_risk)}</span>` : ''}</p>` : ''}
                ${enh.network_summary ? `<p class="mb-1 small">${esc(enh.network_summary)}</p>` : ''}
                ${osintHtml}
            </div>`;
    }

    function selectAlert(a) {
        const key = alertKey(a);
        store.selectedId = key;
        renderQueue();
        const ins = buildAlertInsight(a);
        const el = document.getElementById('socInspector');
        if (!el) return;
        el.innerHTML = `
            <div class="soc-inspector-content">
                <div class="d-flex flex-wrap gap-2 align-items-center mb-2">
                    ${severityBadge(a.severity)}
                    ${sourceBadge(a)}
                    <span class="text-muted small">${fmtTime(a.timestamp || Date.now() / 1000)}</span>
                </div>
                <h6 class="mb-2">${esc(ins.headline)}</h6>
                ${renderEnhancedBlock(a)}
                ${triageBlock(a)}
                <div class="soc-insight-box mb-3">
                    <div class="soc-insight-label"><i class="bi bi-lightbulb"></i> What this means</div>
                    <p class="mb-2 small">${esc(ins.body)}</p>
                    <div class="soc-insight-label"><i class="bi bi-signpost"></i> Recommended action</div>
                    <p class="mb-0 small fw-semibold">${esc(ins.action)}</p>
                </div>
                <dl class="row small mb-3">
                    <dt class="col-4 text-muted">Source</dt><dd class="col-8 font-monospace">${esc(fmtEp(a.src_ip, a.src_port))}</dd>
                    <dt class="col-4 text-muted">Destination</dt><dd class="col-8 font-monospace">${esc(fmtEp(a.dst_ip, a.dst_port))}</dd>
                    <dt class="col-4 text-muted">Protocol</dt><dd class="col-8">${esc(a.protocol || '—')}</dd>
                    ${a.signature ? `<dt class="col-4 text-muted">Signature</dt><dd class="col-8">${esc(a.signature)}</dd>` : ''}
                    ${a.anomaly_score != null ? `<dt class="col-4 text-muted">ML score</dt><dd class="col-8">${esc(a.anomaly_score)}</dd>` : ''}
                    ${a.category ? `<dt class="col-4 text-muted">Category</dt><dd class="col-8">${esc(a.category)}</dd>` : ''}
                    ${a.explanation ? `<dt class="col-4 text-muted">Details</dt><dd class="col-8">${esc(a.explanation)}</dd>` : ''}
                    ${a.total_fwd_packets != null ? `<dt class="col-4 text-muted">Fwd packets</dt><dd class="col-8">${esc(a.total_fwd_packets)} / ${esc(a.total_bwd_packets || 0)} bwd</dd>` : ''}
                    ${a.total_fwd_bytes != null ? `<dt class="col-4 text-muted">Bytes</dt><dd class="col-8">${esc(a.total_fwd_bytes)} fwd / ${esc(a.total_bwd_bytes || 0)} bwd</dd>` : ''}
                    ${a.flow_duration != null ? `<dt class="col-4 text-muted">Duration</dt><dd class="col-8">${esc(a.flow_duration)}s</dd>` : ''}
                </dl>
                <div class="d-flex flex-wrap gap-2">${renderInspectorActions(a)}</div>
                ${a.finding_id ? `<button type="button" class="btn btn-outline-secondary btn-sm mt-2 btn-mark-fp" data-finding-id="${esc(a.finding_id)}"><i class="bi bi-x-circle"></i> Mark false positive</button>` : ''}
            </div>`;
        wireInspectorActions(el, a);
        el.querySelector('.btn-mark-fp')?.addEventListener('click', async (e) => {
            const fid = e.target.closest('.btn-mark-fp')?.dataset.findingId;
            const sid = window.sessionId || liveConfig?.active_session?.session_id;
            if (!fid || !sid) return;
            await fetch(`/api/analysis/${sid}/feedback`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ finding_id: fid, is_false_positive: true }),
            });
            store.alerts = store.alerts.filter((x) => x.finding_id !== fid);
            renderQueue();
            if (typeof showInlineFeedback === 'function') showInlineFeedback('Marked as false positive.', 'info', 'Alert');
        });
        document.getElementById('socInspectorCard')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function showEventDetail(ev) {
        store.selectedId = `ev-${ev.id}`;
        const ins = buildEventInsight(ev);
        const el = document.getElementById('socInspector');
        if (!el) return;
        el.innerHTML = `
            <div class="soc-inspector-content">
                <div class="d-flex flex-wrap gap-2 align-items-center mb-2">
                    ${severityBadge(ev.severity)}
                    <span class="badge text-bg-light border">${esc(ev.event_type || 'event')}</span>
                    <span class="text-muted small">${fmtTime(ev.timestamp || Date.now() / 1000)}</span>
                </div>
                <h6 class="mb-2">${esc(ins.headline)}</h6>
                <div class="soc-insight-box mb-3">
                    <div class="soc-insight-label"><i class="bi bi-lightbulb"></i> What this means</div>
                    <p class="mb-2 small">${esc(ins.body)}</p>
                    <div class="soc-insight-label"><i class="bi bi-signpost"></i> Recommended action</div>
                    <p class="mb-0 small fw-semibold">${esc(ins.action)}</p>
                </div>
                <dl class="row small mb-3">
                    <dt class="col-4 text-muted">Source</dt><dd class="col-8 font-monospace">${esc(fmtEp(ev.src_ip, ev.src_port))}</dd>
                    <dt class="col-4 text-muted">Destination</dt><dd class="col-8 font-monospace">${esc(fmtEp(ev.dst_ip, ev.dst_port))}</dd>
                    <dt class="col-4 text-muted">Protocol</dt><dd class="col-8">${esc(ev.protocol || '—')}</dd>
                    <dt class="col-4 text-muted">Info</dt><dd class="col-8">${esc(ev.info || '—')}</dd>
                </dl>
                <div class="d-flex flex-wrap gap-2">${renderInspectorActions(ev)}</div>
            </div>`;
        wireInspectorActions(el, ev);
    }

    function appendStreamRow(ev) {
        const tbody = document.getElementById('socEventStream');
        if (!tbody) return;
        const empty = tbody.querySelector('.empty-state');
        if (empty) tbody.innerHTML = '';

        const tr = document.createElement('tr');
        tr.className = `soc-stream-row pkt-risk-${ev.severity || 'info'}`;
        tr.innerHTML = `
            <td class="font-monospace small">${fmtTime(ev.timestamp)}</td>
            <td><span class="badge text-bg-light border">${esc(ev.event_type)}</span></td>
            <td class="font-monospace small">${esc(fmtEp(ev.src_ip, ev.src_port))}</td>
            <td class="font-monospace small">${esc(fmtEp(ev.dst_ip, ev.dst_port))}</td>
            <td class="small text-truncate" style="max-width:200px" title="${esc(ev.info)}">${esc(ev.info)}</td>
            <td>${severityBadge(ev.severity)}</td>`;
        tr.addEventListener('click', () => showEventDetail(ev));
        tbody.appendChild(tr);
        while (tbody.rows.length > 150) tbody.deleteRow(0);

        const cnt = document.getElementById('socStreamCount');
        if (cnt) cnt.textContent = `${tbody.rows.length} events`;
    }

    async function pollEventStream() {
        try {
            const res = await fetch(`/api/suricata/monitor?since=${streamSince}`);
            if (!res.ok) return;
            const data = await res.json();
            const st = data.status || {};
            const badge = document.getElementById('socStreamBadge');
            if (badge) {
                badge.textContent = st.running ? 'live' : 'idle';
                badge.className = `badge ${st.running ? 'bg-success' : 'bg-secondary'}`;
            }
            (data.events || []).forEach((ev) => {
                appendStreamRow(ev);
                streamSince = Math.max(streamSince, ev.id || 0);
            });
            const eps = document.getElementById('socKpiEps');
            if (eps && st.eve?.events_per_second != null) {
                eps.textContent = st.eve.events_per_second.toFixed(1);
            } else if (eps && data.events?.length) {
                /* fallback from suricata status poll */
            }
        } catch { /* ignore */ }
    }

    async function refreshSensorHealth() {
        const el = document.getElementById('socSensorHealth');
        if (!el) return;
        try {
            const [cap, sur] = await Promise.all([
                LivePollHub.fetchJSON('/api/capture/status', 2500).then((d) => d || {}),
                LivePollHub.fetchJSON('/api/suricata/status', 2500).then((d) => d || {}),
            ]);
            const capOk = cap.running;
            const surOk = sur.running;
            el.innerHTML = `
                <div class="soc-health-row ${capOk ? 'ok' : 'warn'}">
                    <i class="bi bi-${capOk ? 'check-circle-fill' : 'pause-circle'}"></i>
                    <div><strong>Capture</strong><br>${capOk ? `${esc(cap.mode)} · ${esc(cap.interface || '?')}` : 'Stopped'}</div>
                </div>
                <div class="soc-health-row ${surOk ? 'ok' : 'warn'}">
                    <i class="bi bi-${surOk ? 'shield-fill-check' : 'shield-x'}"></i>
                    <div><strong>Suricata</strong><br>${surOk ? 'Running' : sur.installed ? 'Stopped' : 'Not installed'}</div>
                </div>
                <div class="soc-health-row ${window.sessionId ? 'ok' : 'warn'}">
                    <i class="bi bi-${window.sessionId ? 'cpu-fill' : 'cpu'}"></i>
                    <div><strong>ML session</strong><br>${window.sessionId ? esc(String(window.sessionId).slice(0, 8)) + '…' : 'Not started'}</div>
                </div>
                <div class="soc-health-row neutral">
                    <i class="bi bi-file-earmark-text"></i>
                    <div><strong>EVE</strong><br><code class="small">${esc(sur.eve?.path || '—')}</code></div>
                </div>`;
            const eps = document.getElementById('socKpiEps');
            if (eps && sur.eve?.events_per_second != null) eps.textContent = sur.eve.events_per_second.toFixed(1);
        } catch {
            el.innerHTML = '<div class="text-danger">Sensor status unavailable</div>';
        }
    }

    window.socOnAlerts = function (alerts) {
        alerts.forEach((a) => {
            const key = alertKey(a);
            if (!store.alerts.some((x) => alertKey(x) === key)) store.alerts.push(a);
        });
        if (store.alerts.length > 200) store.alerts = store.alerts.slice(-200);
        renderQueue();
    };

    window.socSelectAlert = selectAlert;
    window.socBuildInsight = buildAlertInsight;
    window.socShowEventDetail = showEventDetail;

    window.socUpdateStatus = function (status) {
        const flows = document.getElementById('socKpiFlows');
        if (flows && status) flows.textContent = (status.total_flows || 0).toLocaleString();
    };

    async function pollTriageLink() {
        const sid = window.sessionId || liveConfig?.active_session?.session_id;
        if (!sid) return;
        try {
            const res = await fetch(`/api/live/triage/incidents?session_id=${sid}&limit=100`);
            if (!res.ok) return;
            const data = await res.json();
            store.triageByConn = {};
            (data.incidents || []).forEach((row) => {
                store.triageByConn[connKey(row)] = row;
            });
        } catch { /* ignore */ }
    }

    async function loadAllAlerts() {
        const sid = window.sessionId || liveConfig?.active_session?.session_id;
        if (!sid) return;
        try {
            const res = await fetch(`/api/live/alerts?session_id=${sid}&since=0`);
            if (res.ok) {
                const data = await res.json();
                window.socOnAlerts(data.alerts || []);
            }
        } catch { /* ignore */ }
    }

    window.socLoadAlerts = loadAllAlerts;

    document.addEventListener('DOMContentLoaded', () => {
        loadAllAlerts();
        // Hub gates these to the SOC Console page — every other /live/* page
        // has this pane hidden, so polling it there was pure waste.
        LivePollHub.register('soc-stream', pollEventStream, { interval: 3000, tabs: ['overview'] });
        LivePollHub.register('soc-health', refreshSensorHealth, { interval: 8000, tabs: ['overview'] });
        LivePollHub.register('soc-triage-link', pollTriageLink, { interval: 5000, tabs: ['overview'] });
        document.querySelectorAll('#socAlertFilters button').forEach((btn) => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('#socAlertFilters button').forEach((b) => b.classList.remove('active'));
                btn.classList.add('active');
                store.filterSeverity = btn.dataset.severity || '';
                store.filterSource = btn.dataset.source || '';
                window.socAlertSeverity = store.filterSeverity;
                window.socAlertSource = store.filterSource;
                renderQueue();
            });
        });
    });

})();
