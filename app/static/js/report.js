async function markFP(findingId) {
    await fetch(`/api/analysis/${analysisId}/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: findingId, is_false_positive: true }),
    });
    alert('Marked as false positive');
}

if (typeof reportData !== 'undefined' && reportData.geo_markers) {
    const map = L.map('threatMap').setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; OpenStreetMap',
    }).addTo(map);

    reportData.geo_markers.forEach(m => {
        const color = m.is_malicious ? 'red' : 'cyan';
        L.circleMarker([m.lat, m.lon], { radius: 8, color, fillColor: color, fillOpacity: 0.7 })
            .bindPopup(`<strong>${m.ip}</strong><br>${m.country || ''}`)
            .addTo(map);
    });
}
