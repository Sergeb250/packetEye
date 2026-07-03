/* Analyses list page: delete modal + live status refresh for running analyses. */

let pendingDeleteId = null;

const deleteModalEl = document.getElementById('deleteModal');
const deleteModal = deleteModalEl ? new bootstrap.Modal(deleteModalEl) : null;
const deleteName = document.getElementById('deleteModalName');
const deleteError = document.getElementById('deleteModalError');
const deleteConfirm = document.getElementById('deleteModalConfirm');

document.querySelectorAll('.btn-delete').forEach((btn) => {
    btn.addEventListener('click', () => {
        pendingDeleteId = btn.dataset.analysisId;
        if (deleteName) deleteName.textContent = btn.dataset.analysisName || 'this analysis';
        if (deleteError) deleteError.classList.add('d-none');
        deleteModal?.show();
    });
});

deleteConfirm?.addEventListener('click', async () => {
    if (!pendingDeleteId) return;
    deleteConfirm.disabled = true;
    deleteConfirm.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Deleting…';
    try {
        const res = await fetch(`/api/analysis/${pendingDeleteId}`, { method: 'DELETE' });
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            throw new Error(data.error || `Delete failed (${res.status})`);
        }
        document.querySelector(`tr[data-analysis-id="${pendingDeleteId}"]`)?.remove();
        deleteModal?.hide();
    } catch (err) {
        if (deleteError) {
            deleteError.textContent = err.message || 'Delete failed.';
            deleteError.classList.remove('d-none');
        }
    } finally {
        deleteConfirm.disabled = false;
        deleteConfirm.innerHTML = '<i class="bi bi-trash"></i> Delete';
        pendingDeleteId = null;
    }
});

// Poll status for analyses still processing so the page updates without reloads.
const activeRows = Array.from(
    document.querySelectorAll('tr[data-analysis-id]'),
).filter((row) => !['complete', 'failed'].includes(row.dataset.status));

async function refreshActiveRows() {
    await Promise.all(activeRows.map(async (row) => {
        if (['complete', 'failed'].includes(row.dataset.status)) return;
        try {
            const res = await fetch(`/api/analysis/${row.dataset.analysisId}/status`);
            if (!res.ok) return;
            const a = await res.json();
            if (a.status && a.status !== row.dataset.status) {
                row.dataset.status = a.status;
                const badge = row.querySelector('.status-badge');
                if (badge) {
                    badge.textContent = a.status;
                    badge.className = `badge status-badge ${
                        a.status === 'complete' ? 'bg-success' : a.status === 'failed' ? 'bg-danger' : 'bg-secondary'
                    }`;
                }
                if (['complete', 'failed'].includes(a.status)) {
                    row.querySelector('.status-spinner')?.remove();
                    // Reload once so action buttons (Report/exports) appear for this row.
                    window.location.reload();
                }
            }
            const flows = row.querySelector('.flows-cell');
            if (flows && a.total_flows != null) flows.textContent = Number(a.total_flows).toLocaleString();
            const findings = row.querySelector('.findings-cell');
            if (findings && a.total_findings != null) findings.textContent = a.total_findings;
        } catch {
            /* transient network error — retry next tick */
        }
    }));
}

if (activeRows.length) {
    setInterval(refreshActiveRows, 5000);
}
