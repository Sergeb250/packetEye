async function markFP(findingId) {
    await fetch(`/api/analysis/${analysisId}/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: findingId, is_false_positive: true }),
    });
    alert('Marked as false positive');
}

window.refreshReportMetrics = async function () {
    if (typeof analysisId === 'undefined') return;
    try {
        const res = await fetch(`/api/analysis/${analysisId}/metrics`);
        if (!res.ok) return;
        const m = await res.json();
        const riskEl = document.getElementById('liveRiskScore');
        if (riskEl) riskEl.textContent = Number(m.detection_risk || m.risk_score || 0).toFixed(1);
        const set = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
        set('metricMaliciousIocs', `${m.confirmed_malicious_iocs ?? m.malicious_observables ?? 0} confirmed IOCs`);
        set('metricInvestigated', `${m.investigated_count ?? 0} investigated`);
        set('metricFlows', `${m.total_flows ?? 0} flows`);
        set('metricExternalIps', `${m.unique_external_ips ?? 0} external IPs`);
    } catch { /* ignore */ }
};

(async () => {
    if (typeof analysisId !== 'undefined') await window.refreshReportMetrics();
})();

// Threat map: merge markers baked into the report with live observable geo
// (investigations run after the report was built still show up).
(async () => {
    const el = document.getElementById('threatMap');
    if (!el || typeof L === 'undefined') return;

    const baked = (typeof reportData !== 'undefined' && reportData.geo_markers) || [];
    let live = [];
    try {
        const res = await fetch(`/api/analysis/${analysisId}/geo`);
        if (res.ok) live = (await res.json()).markers || [];
    } catch { /* fall back to baked markers */ }

    const byIp = new Map();
    baked.concat(live).forEach((m) => byIp.set(m.ip, m));
    const markers = Array.from(byIp.values());

    if (!markers.length) {
        el.innerHTML = '<div class="empty-state"><i class="bi bi-globe"></i>'
            + 'No geolocated IPs yet — click "Investigate (OSINT)" on a finding to populate the map.</div>';
        el.style.height = 'auto';
        return;
    }
    window.renderThreatMap('threatMap', markers);
})();
