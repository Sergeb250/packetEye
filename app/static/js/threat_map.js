/* Shared Leaflet threat map (light theme). Used by dashboard and report pages. */

(function () {
    function escHtml(value) {
        const div = document.createElement('div');
        div.textContent = value == null ? '' : String(value);
        return div.innerHTML;
    }

    window.renderThreatMap = function (elementId, markers) {
        const el = document.getElementById(elementId);
        if (!el || typeof L === 'undefined') return null;

        const map = L.map(elementId, { scrollWheelZoom: false }).setView([25, 10], 2);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; OpenStreetMap &copy; CARTO',
            maxZoom: 18,
        }).addTo(map);

        (markers || []).forEach((m) => {
            if (m.lat == null || m.lon == null) return;
            const color = m.is_malicious ? '#dc3545' : '#2563eb';
            const label = [
                `<strong>${escHtml(m.ip)}</strong>`,
                m.is_malicious
                    ? '<span style="color:#dc3545;font-weight:600">MALICIOUS</span>'
                    : '<span style="color:#15803d">clean</span>',
                escHtml([m.city, m.country].filter(Boolean).join(', ')),
                m.analysis ? `<span style="color:#6b7280">${escHtml(m.analysis)}</span>` : '',
            ].filter(Boolean).join('<br>');
            L.circleMarker([m.lat, m.lon], {
                radius: m.is_malicious ? 9 : 6,
                color,
                fillColor: color,
                fillOpacity: 0.65,
                weight: 1.5,
            }).bindPopup(label).addTo(map);
        });

        return map;
    };

    window.loadThreatMap = async function (elementId, url, emptyMessage) {
        const el = document.getElementById(elementId);
        if (!el) return;
        try {
            const res = await fetch(url);
            if (!res.ok) throw new Error();
            const { markers } = await res.json();
            if (!markers || !markers.length) {
                el.innerHTML = `<div class="empty-state"><i class="bi bi-globe"></i>${escHtml(
                    emptyMessage || 'No geolocated IPs yet — run an OSINT investigation on a finding to populate the map.'
                )}</div>`;
                el.style.height = 'auto';
                return;
            }
            window.renderThreatMap(elementId, markers);
        } catch {
            el.innerHTML = '<div class="empty-state"><i class="bi bi-globe"></i>Threat map unavailable.</div>';
            el.style.height = 'auto';
        }
    };
})();
