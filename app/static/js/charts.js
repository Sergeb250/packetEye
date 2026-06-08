if (typeof reportData === 'undefined') return;

const charts = reportData.charts || {};
const riskScore = reportData.risk_score || 0;

// Risk gauge
const gaugeCtx = document.getElementById('riskGauge');
if (gaugeCtx) {
    new Chart(gaugeCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [riskScore, 10 - riskScore],
                backgroundColor: [
                    riskScore >= 8 ? '#dc3545' : riskScore >= 5 ? '#ffc107' : '#198754',
                    '#212529',
                ],
                borderWidth: 0,
            }],
        },
        options: {
            cutout: '75%',
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
        },
    });
}

function barChart(id, labels, data, label) {
    const el = document.getElementById(id);
    if (!el || !labels.length) return;
    new Chart(el, {
        type: 'bar',
        data: {
            labels,
            datasets: [{ label, data, backgroundColor: '#0dcaf0' }],
        },
        options: {
            indexAxis: id === 'talkersChart' ? 'y' : 'x',
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#adb5bd' }, grid: { color: '#343a40' } },
                y: { ticks: { color: '#adb5bd' }, grid: { color: '#343a40' } },
            },
        },
    });
}

const proto = charts.protocol_distribution || {};
barChart('protocolChart', Object.keys(proto), Object.values(proto), 'Flows');

const talkers = charts.top_talkers || {};
barChart('talkersChart', Object.keys(talkers), Object.values(talkers), 'Bytes');

const timeline = charts.traffic_timeline || {};
const tlEl = document.getElementById('timelineChart');
if (tlEl && Object.keys(timeline).length) {
    new Chart(tlEl, {
        type: 'line',
        data: {
            labels: Object.keys(timeline),
            datasets: [{ label: 'Bytes', data: Object.values(timeline), borderColor: '#0dcaf0', tension: 0.3, fill: false }],
        },
        options: {
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#adb5bd', maxTicksLimit: 8 }, grid: { color: '#343a40' } },
                y: { ticks: { color: '#adb5bd' }, grid: { color: '#343a40' } },
            },
        },
    });
}
