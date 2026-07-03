const STEP_ORDER = ['queued', 'parsing', 'enriching', 'analyzing', 'complete'];

const STATUS_LABELS = {
    queued: 'Queued',
    parsing: 'Parsing PCAP',
    enriching: 'Enriching observables',
    analyzing: 'Detecting threats',
    complete: 'Complete',
    failed: 'Failed',
};

const STATUS_BADGE = {
    queued: 'bg-secondary',
    parsing: 'bg-info',
    enriching: 'bg-primary',
    analyzing: 'bg-warning text-dark',
    complete: 'bg-success',
    failed: 'bg-danger',
};

function updatePipelineSteps(status) {
    const steps = document.querySelectorAll('.pipeline-step');
    const idx = STEP_ORDER.indexOf(status);

    steps.forEach((el) => {
        const step = el.dataset.step;
        const stepIdx = STEP_ORDER.indexOf(step);
        el.classList.remove('active', 'done');

        if (status === 'complete') {
            el.classList.add('done');
            return;
        }

        if (status === 'failed') {
            if (stepIdx < idx && idx >= 0) el.classList.add('done');
            else if (stepIdx === idx || idx === -1) el.classList.add('active');
            return;
        }

        if (stepIdx < idx) el.classList.add('done');
        else if (stepIdx === idx) el.classList.add('active');
    });
}

function initAnalysisProgress(analysisId, initialStatus) {
    const pollInterval = 1500;

    async function pollStatus() {
        try {
            const resp = await fetch(`/api/analysis/${analysisId}/status`);
            const data = await resp.json();

            const label = STATUS_LABELS[data.status] || data.status;
            document.getElementById('statusLabel').textContent = label;
            document.getElementById('progressPct').textContent = `${data.progress_pct}%`;
            document.getElementById('progressBar').style.width = `${data.progress_pct}%`;

            const msgEl = document.getElementById('progressMessage');
            if (msgEl && data.progress_message) {
                msgEl.textContent = data.progress_message;
            }

            document.getElementById('statFlows').textContent = (data.total_flows || 0).toLocaleString();
            document.getElementById('statFindings').textContent = (data.total_findings || 0).toLocaleString();
            document.getElementById('statRisk').textContent = (data.risk_score || 0).toFixed(1);

            const badge = document.getElementById('statusBadge');
            if (badge) {
                badge.textContent = (data.status || '').toUpperCase();
                badge.className = `badge fs-6 ${STATUS_BADGE[data.status] || 'bg-secondary'}`;
            }

            updatePipelineSteps(data.status);

            if (data.status === 'complete') {
                document.getElementById('completeActions')?.classList.remove('d-none');
                document.getElementById('waitingNote')?.classList.add('d-none');
                document.getElementById('progressBar')?.classList.remove('progress-bar-animated');
                return;
            }

            if (data.status === 'failed') {
                document.getElementById('errorText').textContent = data.error_message || 'Analysis failed';
                document.getElementById('errorBox')?.classList.remove('d-none');
                document.getElementById('waitingNote')?.classList.add('d-none');
                document.getElementById('progressBar')?.classList.remove('progress-bar-animated');
                document.getElementById('progressBar')?.classList.add('bg-danger');
                return;
            }

            setTimeout(pollStatus, pollInterval);
        } catch {
            setTimeout(pollStatus, pollInterval * 2);
        }
    }

    updatePipelineSteps(initialStatus);
    if (initialStatus !== 'complete' && initialStatus !== 'failed') {
        setTimeout(pollStatus, pollInterval);
    }
}
