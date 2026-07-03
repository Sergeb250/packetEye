/* SOC AI assistant chat — global widget, loaded on every page via base.html. */

(function () {
    const fab = document.getElementById('chatFab');
    const panelEl = document.getElementById('chatPanel');
    if (!fab || !panelEl || typeof bootstrap === 'undefined') return;

    const panel = new bootstrap.Offcanvas(panelEl);
    const messages = document.getElementById('chatMessages');
    const form = document.getElementById('chatForm');
    const input = document.getElementById('chatInput');
    const sendBtn = document.getElementById('chatSend');
    const history = [];
    let focusFindingId = null;
    // Analysis context comes from the widget's data attribute (set by the
    // page template); falls back to a page-level `analysisId` global.
    const pageAnalysisId = panelEl.dataset.analysisId
        || (typeof analysisId !== 'undefined' ? analysisId : null)
        || null;

    fab.addEventListener('click', () => panel.show());

    function esc(value) {
        const div = document.createElement('div');
        div.textContent = value == null ? '' : String(value);
        return div.innerHTML;
    }

    function addMessage(role, text, isHtml = false) {
        const wrap = document.createElement('div');
        wrap.className = `chat-msg ${role === 'user' ? 'chat-user' : 'chat-ai'}`;
        const bubble = document.createElement('div');
        bubble.className = 'chat-bubble';
        if (isHtml) bubble.innerHTML = text;
        else bubble.textContent = text;
        wrap.appendChild(bubble);
        messages.appendChild(wrap);
        messages.scrollTop = messages.scrollHeight;
        return bubble;
    }

    async function send(message) {
        if (!message.trim()) return;
        addMessage('user', message);
        history.push({ role: 'user', content: message });
        input.value = '';
        sendBtn.disabled = true;
        const thinking = addMessage('ai', '', true);
        thinking.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Thinking…';

        try {
            const res = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message,
                    history: history.slice(-10),
                    analysis_id: pageAnalysisId,
                    finding_id: focusFindingId,
                }),
            });
            const data = await res.json();
            if (!res.ok) {
                thinking.innerHTML = `<span class="text-danger">${esc(data.error || 'Chat failed.')}</span>`;
            } else {
                thinking.textContent = data.reply;
                history.push({ role: 'assistant', content: data.reply });
            }
        } catch {
            thinking.innerHTML = '<span class="text-danger">Network error — could not reach the assistant.</span>';
        } finally {
            sendBtn.disabled = false;
            focusFindingId = null;
            messages.scrollTop = messages.scrollHeight;
        }
    }

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        send(input.value);
    });

    document.querySelectorAll('.chat-suggest').forEach((btn) => {
        btn.addEventListener('click', () => { panel.show(); send(btn.textContent.trim()); });
    });

    // "Ask AI about this" buttons on individual findings.
    document.querySelectorAll('.btn-ask-ai').forEach((btn) => {
        btn.addEventListener('click', () => {
            focusFindingId = btn.dataset.findingId;
            panel.show();
            send(`Explain this finding and what I should do: "${btn.dataset.findingTitle || 'selected finding'}"`);
        });
    });
})();
