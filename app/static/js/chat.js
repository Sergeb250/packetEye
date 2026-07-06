/* SOC AI assistant chat — global widget with Markdown + Mermaid rendering. */

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
    let focusFlowId = null;
    let focusContextPayload = null;
    const pageAnalysisId = panelEl.dataset.analysisId
        || (typeof analysisId !== 'undefined' ? analysisId : null)
        || null;

    fab.addEventListener('click', () => panel.show());

    function esc(value) {
        const div = document.createElement('div');
        div.textContent = value == null ? '' : String(value);
        return div.innerHTML;
    }

    function renderMarkdown(text) {
        const raw = String(text || '');
        if (typeof marked === 'undefined') {
            return esc(raw).replace(/\n/g, '<br>');
        }
        marked.setOptions({ gfm: true, breaks: true });
        let html = marked.parse(raw);
        if (typeof DOMPurify !== 'undefined') {
            html = DOMPurify.sanitize(html, {
                ADD_TAGS: ['iframe'],
                ADD_ATTR: ['target', 'rel'],
            });
        }
        return html;
    }

    async function renderMermaid(container) {
        if (typeof mermaid === 'undefined' || !container) return;
        const blocks = container.querySelectorAll('pre code.language-mermaid, code.language-mermaid');
        for (let i = 0; i < blocks.length; i += 1) {
            const code = blocks[i];
            const parent = code.closest('pre') || code.parentElement;
            if (!parent || parent.dataset.mermaidDone) continue;
            parent.dataset.mermaidDone = '1';
            const src = code.textContent || '';
            const mount = document.createElement('div');
            mount.className = 'chat-mermaid mermaid';
            mount.textContent = src;
            parent.replaceWith(mount);
        }
        try {
            await mermaid.run({ querySelector: '.chat-mermaid' });
        } catch {
            /* mermaid optional */
        }
    }

    function addMessage(role, text, options = {}) {
        const { isHtml = false, isMarkdown = false } = options;
        const wrap = document.createElement('div');
        wrap.className = `chat-msg ${role === 'user' ? 'chat-user' : 'chat-ai'}`;
        const bubble = document.createElement('div');
        bubble.className = 'chat-bubble' + (isMarkdown ? ' chat-markdown' : '');
        if (isMarkdown) {
            bubble.innerHTML = renderMarkdown(text);
            renderMermaid(bubble);
        } else if (isHtml) {
            bubble.innerHTML = text;
        } else {
            bubble.textContent = text;
        }
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
        const thinking = addMessage('ai', '', { isHtml: true });
        thinking.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Analyzing traffic data…';

        const body = {
            message,
            history: history.slice(-10),
            analysis_id: panelEl.dataset.analysisId || pageAnalysisId,
            finding_id: focusFindingId,
            flow_id: focusFlowId,
            context_payload: focusContextPayload,
        };

        try {
            const res = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const data = await res.json();
            if (!res.ok) {
                thinking.innerHTML = `<span class="text-danger">${esc(data.error || 'Chat failed.')}</span>`;
            } else {
                const bubble = thinking.closest('.chat-bubble');
                if (bubble) {
                    bubble.classList.add('chat-markdown');
                    bubble.innerHTML = renderMarkdown(data.reply);
                    await renderMermaid(bubble);
                } else {
                    thinking.textContent = data.reply;
                }
                history.push({ role: 'assistant', content: data.reply });
            }
        } catch {
            thinking.innerHTML = '<span class="text-danger">Network error — could not reach the assistant.</span>';
        } finally {
            sendBtn.disabled = false;
            focusFindingId = null;
            focusFlowId = null;
            focusContextPayload = null;
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

    document.querySelectorAll('.btn-ask-ai').forEach((btn) => {
        btn.addEventListener('click', () => {
            focusFindingId = btn.dataset.findingId || null;
            focusFlowId = btn.dataset.flowId || null;
            try {
                focusContextPayload = btn.dataset.contextJson
                    ? JSON.parse(btn.dataset.contextJson)
                    : null;
            } catch {
                focusContextPayload = null;
            }
            panel.show();
            send(`Analyze this finding with full context. Use markdown tables and a mermaid diagram if helpful: "${btn.dataset.findingTitle || 'selected finding'}"`);
        });
    });

    window.openChatWithContext = function (message, analysisIdOverride, findingId, contextPayload, flowId) {
        if (analysisIdOverride) panelEl.dataset.analysisId = analysisIdOverride;
        focusFindingId = findingId || null;
        focusFlowId = flowId || null;
        focusContextPayload = contextPayload || null;
        panel.show();
        send(message);
    };
})();
