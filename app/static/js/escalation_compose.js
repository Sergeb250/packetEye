/* Gmail-inspired escalation compose — AI draft + Google SMTP send. */

(function () {
    const modalEl = document.getElementById('escalationComposeModal');
    if (!modalEl || typeof bootstrap === 'undefined') return;

    const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    const toEl = document.getElementById('escalationTo');
    const ccEl = document.getElementById('escalationCc');
    const subjectEl = document.getElementById('escalationSubject');
    const bodyEl = document.getElementById('escalationBody');
    const draftBtn = document.getElementById('escalationDraftBtn');
    const draftDetailedBtn = document.getElementById('escalationDraftDetailedBtn');
    const sendBtn = document.getElementById('escalationSendBtn');
    const statusEl = document.getElementById('escalationDraftStatus');

    let context = {};

    async function loadDefaults() {
        try {
            const res = await fetch('/api/escalation/config');
            const data = await res.json();
            if (data.default_to && toEl && !toEl.value) {
                toEl.value = data.default_to;
            }
        } catch { /* optional */ }
    }

    function setStatus(msg, isError) {
        if (!statusEl) return;
        statusEl.textContent = msg || '';
        statusEl.className = 'small ms-auto ' + (isError ? 'text-danger' : 'text-muted');
    }

    async function runDraft(detailTier) {
        setStatus('Drafting…');
        if (draftBtn) draftBtn.disabled = true;
        if (draftDetailedBtn) draftDetailedBtn.disabled = true;
        try {
            const res = await fetch('/api/escalation/draft', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ...context,
                    detail_tier: detailTier,
                }),
            });
            const parse = window.fetchJsonOrThrow || ((r) => r.json());
            const data = await parse(res);
            if (!res.ok) throw new Error(data.error || 'Draft failed');
            if (subjectEl) subjectEl.value = data.subject || '';
            if (bodyEl) bodyEl.value = data.body || '';
            setStatus('Draft ready');
        } catch (err) {
            setStatus(err.message || 'Draft failed', true);
        } finally {
            if (draftBtn) draftBtn.disabled = false;
            if (draftDetailedBtn) draftDetailedBtn.disabled = false;
        }
    }

    async function sendEmail() {
        const to = toEl?.value?.trim();
        const subject = subjectEl?.value?.trim();
        const body = bodyEl?.value?.trim();
        if (!to || !body) {
            setStatus('To and body are required', true);
            return;
        }
        sendBtn.disabled = true;
        setStatus('Sending…');
        try {
            const res = await fetch('/api/escalation/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    to,
                    cc: ccEl?.value?.trim() || undefined,
                    subject,
                    body,
                }),
            });
            const parse = window.fetchJsonOrThrow || ((r) => r.json());
            const data = await parse(res);
            if (!res.ok) throw new Error(data.error || 'Send failed');
            setStatus('Sent');
            if (typeof showInlineFeedback === 'function') {
                showInlineFeedback(`Escalation sent to ${to}`, 'success', 'Escalation');
            }
            modal.hide();
        } catch (err) {
            setStatus(err.message || 'Send failed', true);
        } finally {
            sendBtn.disabled = false;
        }
    }

    draftBtn?.addEventListener('click', () => runDraft('brief'));
    draftDetailedBtn?.addEventListener('click', () => runDraft('detailed'));
    sendBtn?.addEventListener('click', sendEmail);

    window.openEscalationCompose = function (ctx) {
        context = {
            context_type: ctx.context_type || (ctx.incident_id ? 'incident' : 'alert'),
            session_id: ctx.session_id || window.sessionId || null,
            alert_id: ctx.alert_id || ctx.finding_id || null,
            incident_id: ctx.incident_id || null,
        };
        if (subjectEl) subjectEl.value = '';
        if (bodyEl) bodyEl.value = '';
        setStatus('');
        loadDefaults();
        modal.show();
    };

    loadDefaults();
})();
