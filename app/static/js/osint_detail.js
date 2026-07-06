/* Full OSINT detail modal with provider tabs and verdict breakdown. */

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
        if (!vt || vt.error) return renderJson(vt || {});
        const engines = vt.engines || vt.last_analysis_results || {};
        const rows = Object.entries(engines).map(([name, r]) => {
            const result = typeof r === 'object' ? (r.result || r.category || JSON.stringify(r)) : r;
            return `<tr><td>${esc(name)}</td><td>${esc(result)}</td></tr>`;
        }).join('');
        return `<p>Malicious: <strong>${esc(vt.malicious)}</strong> · Suspicious: <strong>${esc(vt.suspicious || 0)}</strong> · Harmless: <strong>${esc(vt.harmless || 0)}</strong></p>
            ${rows ? `<table class="table table-sm"><thead><tr><th>Engine</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table>` : renderJson(vt)}`;
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
        anyrun: (data) => renderJson((data.enrichment_json || data.results || {}).anyrun),
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
            if (enrich[key] && Object.keys(enrich[key]).length) availableTabs.push(key);
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

    window.openOsintForTarget = async function (analysisId, target, type) {
        try {
            const res = await fetch(`/api/investigate/target/${analysisId}/${encodeURIComponent(target)}`);
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'lookup failed');
            window.showOsintDetail({
                label: target,
                value: target,
                targetEntry: {
                    results: data.enrichment_json,
                    is_malicious: data.is_malicious,
                    confidence: data.confidence,
                    verdict_breakdown: data.verdict_breakdown,
                },
            });
        } catch (err) {
            if (typeof showInlineFeedback === 'function') {
                showInlineFeedback(err.message || 'OSINT lookup failed', 'danger', 'OSINT');
            } else {
                alert(err.message || 'OSINT lookup failed');
            }
        }
    };

    window.openOsintFromInvestigation = function (inv, targetKey) {
        const entry = (inv.targets || {})[targetKey];
        if (!entry) return;
        window.showOsintDetail({ label: targetKey, targetEntry: entry });
    };
})();
