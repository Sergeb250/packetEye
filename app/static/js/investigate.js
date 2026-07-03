/* Report page: on-demand OSINT investigation per finding. */

function escInv(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
}

function renderInvestigationInline(container, inv) {
    if (!inv || inv.status === 'none') {
        container.innerHTML = '';
        return;
    }
    if (inv.status === 'running') {
        container.innerHTML = '<span class="text-info"><span class="spinner-border spinner-border-sm"></span> Running OSINT lookups…</span>';
        return;
    }
    if (inv.status === 'failed') {
        container.innerHTML = `<span class="text-danger">Investigation failed: ${escInv(inv.error)}</span>`;
        return;
    }
    const targets = inv.targets || {};
    const keys = Object.keys(targets);
    if (!keys.length) {
        container.innerHTML = `<span class="text-muted">${escInv(inv.note || 'No public IPs or domains to investigate.')}</span>`;
        return;
    }
    container.innerHTML = '<div class="fw-semibold mb-1">OSINT results</div>' + keys.map((k) => {
        const t = targets[k];
        if (t.results?.skipped) {
            return `<div><code>${escInv(k)}</code> — <span class="text-muted">${escInv(t.results.skipped)}</span></div>`;
        }
        const badge = t.is_malicious
            ? '<span class="badge bg-danger">malicious</span>'
            : '<span class="badge bg-success">clean</span>';
        return `<div class="mb-2"><code>${escInv(k)}</code> ${badge}
            <div class="text-muted">${window.osintSummaryLines(t.results || {}).map(escInv).join('<br>')}</div></div>`;
    }).join('');
}

/* One line per OSINT provider that returned data. Shared with the live page. */
window.osintSummaryLines = function (r) {
    const lines = [];
    const vt = r.virustotal;
    if (vt && vt.malicious != null) lines.push(`VirusTotal: ${vt.malicious} malicious / ${vt.suspicious || 0} suspicious engines`);
    const abuse = r.abuseipdb;
    if (abuse && abuse.abuseConfidenceScore != null) lines.push(`AbuseIPDB: ${abuse.abuseConfidenceScore}% abuse confidence`);
    const gn = r.greynoise;
    if (gn && gn.classification) {
        lines.push(`GreyNoise: ${gn.classification}${gn.riot ? ' (known-good service)' : ''}${gn.name ? ` — ${gn.name}` : ''}`);
    }
    const otx = r.otx;
    if (otx && otx.pulse_count != null) {
        lines.push(`OTX: in ${otx.pulse_count} threat pulses${otx.pulses?.length ? ` (e.g. ${otx.pulses[0]})` : ''}`);
    }
    const idb = r.internetdb;
    if (idb && (idb.ports?.length || idb.vulns?.length)) {
        lines.push(`Shodan: ports ${idb.ports?.slice(0, 8).join(', ') || '—'}${idb.vulns?.length ? ` · ${idb.vulns.length} known vulns` : ''}`);
    }
    const crt = r.crtsh;
    if (crt && crt.cert_count != null) lines.push(`crt.sh: ${crt.cert_count} certificates seen`);
    const whois = r.whois;
    if (whois && whois.hostname) lines.push(`rDNS: ${whois.hostname}`);
    if (whois && whois.registrar) lines.push(`WHOIS: ${whois.registrar}${whois.creation_date ? ` (created ${whois.creation_date})` : ''}`);
    const geo = r.geo;
    if (geo && (geo.country || geo.isp)) lines.push(`Geo: ${[geo.city, geo.country].filter(Boolean).join(', ')}${geo.isp ? ` · ${geo.isp}` : ''}`);
    return lines.length ? lines : ['No provider returned data.'];
};

document.querySelectorAll('.btn-investigate').forEach((btn) => {
    btn.addEventListener('click', async () => {
        const findingId = btn.dataset.findingId;
        const container = document.querySelector(`.investigation-result[data-finding-id="${findingId}"]`);
        if (!container) return;
        btn.disabled = true;
        renderInvestigationInline(container, { status: 'running' });
        try {
            await fetch(`/api/investigate/finding/${findingId}`, { method: 'POST' });
        } catch {
            renderInvestigationInline(container, { status: 'failed', error: 'could not start' });
            btn.disabled = false;
            return;
        }
        let tries = 0;
        const poll = setInterval(async () => {
            tries += 1;
            try {
                const res = await fetch(`/api/investigate/finding/${findingId}`);
                if (res.ok) {
                    const data = await res.json();
                    renderInvestigationInline(container, data.investigation);
                    if (['complete', 'failed'].includes(data.investigation?.status) || tries > 20) {
                        clearInterval(poll);
                        btn.disabled = false;
                    }
                }
            } catch { /* retry */ }
            if (tries > 20) { clearInterval(poll); btn.disabled = false; }
        }, 1500);
    });
});
