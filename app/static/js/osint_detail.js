/* Full OSINT detail modal with provider tabs, loading state, and AI summary. */

(function () {
    function esc(value) {
        const div = document.createElement('div');
        div.textContent = value == null ? '' : String(value);
        return div.innerHTML;
    }

    function renderJson(obj) {
        return `<pre class="small bg-light p-2 rounded mb-0" style="max-height:360px;overflow:auto;">${esc(JSON.stringify(obj, null, 2))}</pre>`;
    }

    function renderVtTab(vt) {
        if (!vt || vt.error) {
            return `<div class="text-warning small mb-2">VirusTotal: ${esc(vt?.error || 'unavailable')}</div>${renderJson(vt || {})}`;
        }
        const engines = vt.engines || vt.last_analysis_results || {};
        const rows = Object.entries(engines).map(([name, r]) => {
            const result = typeof r === 'object' ? (r.result || r.category || JSON.stringify(r)) : r;
            return `<tr><td>${esc(name)}</td><td>${esc(result)}</td></tr>`;
        }).join('');
        return `<p>Malicious: <strong>${esc(vt.malicious)}</strong> · Suspicious: <strong>${esc(vt.suspicious || 0)}</strong> · Harmless: <strong>${esc(vt.harmless || 0)}</strong></p>
            ${rows ? `<table class="table table-sm"><thead><tr><th>Engine</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table>` : renderJson(vt)}`;
    }

    function providerHasData(key, enrich) {
        const data = enrich[key];
        if (!data || typeof data !== 'object') return false;
        if (Object.keys(data).length === 0) return false;
        if (data.error && Object.keys(data).length === 1) return true;
        return true;
    }

    const TAB_RENDERERS = {
        overview: (data) => {
            const signals = data.verdict_breakdown || [];
            if (!signals.length) return '<p class="text-muted">No verdict signals.</p>';
            return signals.map((s) => `
                <div class="border rounded p-2 mb-2 ${s.triggered ? 'border-danger' : 'border-secondary'}">
                    <div class="d-flex justify-content-between">
                        <strong>${esc(s.provider)}</strong>
                        ${s.triggered ? '<span class="badge bg-danger">triggered</span>' : '<span class="badge bg-secondary">not triggered</span>'}
                    </div>
                    <div class="small text-muted">${esc(s.reason)}</div>
                </div>`).join('');
        },
        virustotal: (data) => renderVtTab((data.enrichment_json || data.results || {}).virustotal),
        abuseipdb: (data) => renderJson((data.enrichment_json || data.results || {}).abuseipdb),
        otx: (data) => renderJson((data.enrichment_json || data.results || {}).otx),
        anyrun: (data) => {
            const ar = (data.enrichment_json || data.results || {}).anyrun;
            if (ar?.error === 'unauthorized') {
                return '<p class="text-muted small">ANY.RUN lookup skipped — set <code>ANYRUN_API_KEY</code> in .env to enable.</p>';
            }
            return renderJson(ar);
        },
        greynoise: (data) => renderJson((data.enrichment_json || data.results || {}).greynoise),
        internetdb: (data) => renderJson((data.enrichment_json || data.results || {}).internetdb),
        whois: (data) => renderJson((data.enrichment_json || data.results || {}).whois),
        geo: (data) => renderJson((data.enrichment_json || data.results || {}).geo),
        crtsh: (data) => renderJson((data.enrichment_json || data.results || {}).crtsh),
        raw: (data) => renderJson(data.enrichment_json || data.results || data),
    };

    const TAB_LABELS = {
        overview: 'Overview',
        virustotal: 'VirusTotal',
        abuseipdb: 'AbuseIPDB',
        otx: 'OTX',
        anyrun: 'ANY.RUN',
        greynoise: 'GreyNoise',
        internetdb: 'Shodan',
        whois: 'WHOIS',
        geo: 'Geo',
        crtsh: 'crt.sh',
        raw: 'Raw JSON',
    };

    function buildTargetData(targetEntry) {
        const enrichment = targetEntry.results || targetEntry.enrichment_json || {};
        return {
            enrichment_json: enrichment,
            results: enrichment,
            is_malicious: targetEntry.is_malicious,
            confidence: targetEntry.confidence,
            verdict_breakdown: targetEntry.verdict_breakdown || [],
        };
    }

    function renderAiSummaryBlock(aiSummary) {
        const el = document.getElementById('osintAiSummary');
        if (!el) return '';
        if (!aiSummary || !aiSummary.summary) {
            el.classList.add('d-none');
            el.innerHTML = '';
            return '';
        }
        const verdictCls = {
            clean: 'bg-success',
            suspicious: 'bg-warning text-dark',
            malicious: 'bg-danger',
            unknown: 'bg-secondary',
        }[aiSummary.verdict] || 'bg-secondary';
        const highlights = (aiSummary.highlights || []).map((h) => `<li>${esc(h)}</li>`).join('');
        el.classList.remove('d-none');
        el.innerHTML = `
            <div class="soc-insight-box border-info">
                <div class="soc-insight-label"><i class="bi bi-robot"></i> AI OSINT summary</div>
                <div class="d-flex flex-wrap gap-2 align-items-center mb-2">
                    <span class="badge ${verdictCls}">${esc(aiSummary.verdict || 'unknown')}</span>
                </div>
                <p class="small mb-1">${esc(aiSummary.summary)}</p>
                ${highlights ? `<ul class="small text-muted mb-0">${highlights}</ul>` : ''}
            </div>`;
        return el.innerHTML;
    }

    function showOsintLoading(target, message) {
        const inlinePanel = document.getElementById('liveOsintPanel');
        const title = document.getElementById('osintDetailTitle');
        const verdict = document.getElementById('osintDetailVerdict');
        const tabs = document.getElementById('osintDetailTabs');
        const content = document.getElementById('osintDetailTabContent');
        const aiEl = document.getElementById('osintAiSummary');
        if (aiEl) {
            aiEl.classList.remove('d-none');
            aiEl.innerHTML = `<div class="text-info small"><span class="spinner-border spinner-border-sm"></span> ${esc(message || 'Running OSINT lookups…')}</div>`;
        }
        if (title) title.innerHTML = `<i class="bi bi-search text-info"></i> OSINT — ${esc(target)}`;
        if (verdict) verdict.innerHTML = '<span class="badge bg-secondary">Loading…</span>';
        if (tabs) tabs.innerHTML = '';
        if (content) content.innerHTML = '';
        inlinePanel?.classList.remove('d-none');
    }

    window.renderOsintAiSummary = renderAiSummaryBlock;

    window.showOsintDetail = function (payload) {
        const inlinePanel = document.getElementById('liveOsintPanel');
        const modalEl = document.getElementById('osintDetailModal');
        const title = document.getElementById('osintDetailTitle');
        const verdict = document.getElementById('osintDetailVerdict');
        const tabs = document.getElementById('osintDetailTabs');
        const content = document.getElementById('osintDetailTabContent');
        if (!title || !verdict || !tabs || !content) return;

        const label = payload.label || payload.value || 'Target';
        title.innerHTML = `<i class="bi bi-search text-info"></i> OSINT — ${esc(label)}`;

        if (payload.ai_summary) {
            renderAiSummaryBlock(payload.ai_summary);
        }

        const data = payload.targetEntry ? buildTargetData(payload.targetEntry) : payload;
        const mal = data.is_malicious;
        verdict.innerHTML = `
            <div class="d-flex flex-wrap gap-2 align-items-center">
                <span class="badge ${mal ? 'bg-danger' : 'bg-success'}">TI Verdict: ${mal ? 'Malicious' : 'Clean'}</span>
                <span class="badge bg-secondary">Confidence: ${Math.round((data.confidence || 0) * 100)}%</span>
            </div>`;

        const enrich = data.enrichment_json || data.results || {};
        const availableTabs = ['overview'];
        Object.keys(TAB_LABELS).forEach((key) => {
            if (key === 'overview' || key === 'raw') return;
            if (providerHasData(key, enrich)) availableTabs.push(key);
        });
        availableTabs.push('raw');

        tabs.innerHTML = availableTabs.map((key, i) => `
            <li class="nav-item" role="presentation">
                <button class="nav-link ${i === 0 ? 'active' : ''}" data-bs-toggle="pill"
                    data-bs-target="#osintTab_${key}" type="button">${esc(TAB_LABELS[key])}</button>
            </li>`).join('');

        content.innerHTML = availableTabs.map((key, i) => `
            <div class="tab-pane fade ${i === 0 ? 'show active' : ''}" id="osintTab_${key}">
                ${TAB_RENDERERS[key](data)}
            </div>`).join('');

        if (inlinePanel) {
            inlinePanel.classList.remove('d-none');
            inlinePanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            return;
        }
        if (modalEl) {
            bootstrap.Modal.getOrCreateInstance(modalEl).show();
        }
    };

    window.openOsintForTarget = async function (analysisId, target, options) {
        options = options || {};
        const msg = options.summarize !== false
            ? 'Running OSINT + AI summary…'
            : 'Running OSINT lookups…';
        showOsintLoading(target, msg);
        if (options.onLoading && options.inspectorEl) {
            options.onLoading(options.inspectorEl, target);
        }
        try {
            const summarize = options.summarize !== false;
            const detailLevel = options.detailLevel || 'medium';
            const res = await fetch(
                `/api/investigate/target/${analysisId}/${encodeURIComponent(target)}`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        summarize,
                        detail_level: detailLevel,
                        alert_context: options.alertContext || null,
                    }),
                },
            );
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'lookup failed');

            const aiSummary = data.ai_summary?.ok ? data.ai_summary : (data.ai_summary?.error ? null : data.ai_summary);

            window.showOsintDetail({
                label: target,
                value: target,
                ai_summary: aiSummary,
                targetEntry: {
                    results: data.enrichment_json,
                    is_malicious: data.is_malicious,
                    confidence: data.confidence,
                    verdict_breakdown: data.verdict_breakdown,
                },
            });

            if (options.onComplete) {
                options.onComplete(data, aiSummary);
            }
        } catch (err) {
            if (typeof showInlineFeedback === 'function') {
                showInlineFeedback(err.message || 'OSINT lookup failed', 'danger', 'OSINT');
            } else {
                alert(err.message || 'OSINT lookup failed');
            }
            const aiEl = document.getElementById('osintAiSummary');
            if (aiEl) {
                aiEl.classList.remove('d-none');
                aiEl.innerHTML = `<div class="text-danger small">${esc(err.message || 'OSINT lookup failed')}</div>`;
            }
            if (options.onError) options.onError(err);
        }
    };

    window.openOsintFromInvestigation = function (inv, targetKey) {
        const entry = (inv.targets || {})[targetKey];
        if (!entry) return;
        window.showOsintDetail({ label: targetKey, targetEntry: entry });
    };
})();
