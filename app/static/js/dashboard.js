/* global Chart */

function pct(value) {
    if (value == null || Number.isNaN(value)) return '—';
    return `${(value * 100).toFixed(1)}%`;
}

function num(value) {
    if (value == null) return '—';
    return Number(value).toLocaleString();
}

function initMlMetricsChart(verification) {
    const canvas = document.getElementById('mlMetricsChart');
    if (!canvas || !verification) return;

    const labels = ['Accuracy', 'Precision', 'Recall', 'F1'];
    const values = [
        (verification.accuracy || 0) * 100,
        (verification.precision || 0) * 100,
        (verification.recall || 0) * 100,
        (verification.f1 || 0) * 100,
    ];
    const colors = ['#2563eb', '#15803d', '#d97706', '#2563eb'];

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Score (%)',
                data: values,
                backgroundColor: colors,
                borderRadius: 6,
            }],
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.parsed.y.toFixed(1)}%`,
                    },
                },
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: { color: '#6b7280' },
                    grid: { color: '#e5e7eb' },
                },
                x: {
                    ticks: { color: '#6b7280' },
                    grid: { display: false },
                },
            },
        },
    });
}

function initDetectionMixChart(verification) {
    const canvas = document.getElementById('detectionMixChart');
    if (!canvas || !verification) return;

    const attacks = verification.attacks || 0;
    const benign = verification.benign || 0;
    const predicted = verification.predicted_anomalies || 0;
    const caught = Math.round(attacks * (verification.recall || 0));
    const missed = Math.max(0, attacks - caught);
    const falseAlarms = Math.max(0, predicted - caught);

    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['Attacks caught', 'Attacks missed', 'False alarms (benign flagged)'],
            datasets: [{
                data: [caught, missed, falseAlarms],
                backgroundColor: ['#15803d', '#dc3545', '#d97706'],
                borderWidth: 0,
            }],
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#374151', boxWidth: 12 },
                },
            },
        },
    });
}

function initFindingsChart(findingsBySource) {
    const canvas = document.getElementById('findingsSourceChart');
    if (!canvas || !findingsBySource) return;

    const labels = Object.keys(findingsBySource);
    const values = Object.values(findingsBySource);
    if (!labels.length) return;

    new Chart(canvas, {
        type: 'pie',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: ['#2563eb', '#7c3aed', '#ea580c', '#15803d', '#6b7280'],
                borderWidth: 0,
            }],
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#374151', boxWidth: 12 },
                },
            },
        },
    });
}

function initThresholdChart(sweep) {
    const canvas = document.getElementById('thresholdSweepChart');
    if (!canvas || !sweep || !sweep.length) return;

    new Chart(canvas, {
        type: 'line',
        data: {
            labels: sweep.map((s) => s.threshold),
            datasets: [
                {
                    label: 'Attack recall',
                    data: sweep.map((s) => (s.attack_recall || s.tuesday_recall || 0) * 100),
                    borderColor: '#15803d',
                    tension: 0.2,
                },
                {
                    label: 'Benign false-positive rate',
                    data: sweep.map((s) => (s.benign_fp_rate || s.monday_fp_rate || 0) * 100),
                    borderColor: '#d97706',
                    tension: 0.2,
                },
                ...(sweep.some((s) => s.f1 != null) ? [{
                    label: 'F1 score',
                    data: sweep.map((s) => (s.f1 || 0) * 100),
                    borderColor: '#2563eb',
                    borderDash: [6, 4],
                    tension: 0.2,
                }] : []),
            ],
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#374151' } },
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#6b7280' },
                    grid: { color: '#e5e7eb' },
                },
                x: {
                    title: { display: true, text: 'Threshold', color: '#6b7280' },
                    ticks: { color: '#6b7280' },
                    grid: { color: '#e5e7eb' },
                },
            },
        },
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const root = document.getElementById('dashboard-data');
    if (!root) return;

    const payload = JSON.parse(root.textContent || '{}');
    const ml = payload.ml_performance || {};
    const overview = payload.analysis_overview || {};

    initMlMetricsChart(ml.verification);
    initDetectionMixChart(ml.verification);
    initFindingsChart(overview.findings_by_source);
    initThresholdChart(ml.threshold && ml.threshold.sweep);
});
