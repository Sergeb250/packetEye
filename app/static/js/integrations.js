/**
 * Integrations page — Discord webhook config with alert filters.
 */
(function () {
    if (!document.getElementById('discordEnabled')) return;

    const state = { urlConfigured: false, urlMasked: '' };

    function feedback(msg, kind) {
        const el = document.getElementById('integrationsFeedback');
        if (!el) return;
        el.textContent = msg;
        el.className = `alert alert-${kind || 'info'}`;
        el.classList.remove('d-none');
    }

    function setBadge(id, ok, yes, no) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = ok ? yes : no;
        el.className = `badge ${ok ? 'bg-success' : 'bg-secondary'}`;
    }

    function groupContainer(group) {
        if (group === 'severities') return document.getElementById('discordSeverities');
        if (group === 'sources') return document.getElementById('discordSources');
        return document.getElementById('discordAiStatuses');
    }

    function readGroup(group) {
        const root = groupContainer(group);
        if (!root) return [];
        const all = root.querySelector('.filter-all');
        if (all?.checked) return ['all'];
        return [...root.querySelectorAll('.filter-item:checked')].map((el) => el.value);
    }

    function applyGroup(group, values) {
        const root = groupContainer(group);
        if (!root) return;
        const set = new Set((values || []).map(String));
        const isAll = set.has('all') || !set.size;
        root.querySelector('.filter-all').checked = isAll;
        root.querySelectorAll('.filter-item').forEach((el) => {
            el.checked = isAll ? false : set.has(el.value);
        });
    }

    function wireFilterGroups() {
        document.querySelectorAll('.filter-all').forEach((allCb) => {
            allCb.addEventListener('change', () => {
                const group = allCb.dataset.group;
                const root = groupContainer(group);
                if (!root) return;
                if (allCb.checked) {
                    root.querySelectorAll('.filter-item').forEach((el) => { el.checked = false; });
                }
            });
        });
        document.querySelectorAll('.filter-item').forEach((itemCb) => {
            itemCb.addEventListener('change', () => {
                const group = itemCb.dataset.group;
                const root = groupContainer(group);
                if (!root) return;
                if (itemCb.checked) {
                    root.querySelector('.filter-all').checked = false;
                } else if (!root.querySelector('.filter-item:checked')) {
                    root.querySelector('.filter-all').checked = true;
                }
            });
        });
    }

    async function loadConfig() {
        try {
            const res = await fetch('/api/integrations/config');
            const data = await res.json();
            const dc = data.discord || {};
            state.urlConfigured = !!dc.url_configured;
            state.urlMasked = dc.url_masked || '';

            document.getElementById('discordEnabled').checked = !!dc.enabled;
            const urlInput = document.getElementById('discordUrl');
            if (urlInput) {
                urlInput.value = '';
                urlInput.placeholder = dc.url_configured
                    ? `Configured (${dc.url_masked}) — paste to replace`
                    : 'https://discord.com/api/webhooks/…';
            }
            applyGroup('severities', dc.severities);
            applyGroup('sources', dc.sources);
            applyGroup('ai_statuses', dc.ai_statuses);
            const rate = document.getElementById('discordRateLimit');
            if (rate) rate.value = dc.rate_limit_per_minute || 10;

            setBadge('statusLlm', data.llm_configured, 'configured', 'not set');
            setBadge('statusOsint', data.osint_configured, 'configured', 'not set');
            setBadge('statusSmtp', data.smtp_enabled, 'enabled', 'disabled');
        } catch (e) {
            feedback(`Failed to load config: ${e}`, 'danger');
        }
    }

    async function saveDiscord() {
        const urlVal = (document.getElementById('discordUrl')?.value || '').trim();
        const payload = {
            enabled: document.getElementById('discordEnabled')?.checked || false,
            severities: readGroup('severities'),
            sources: readGroup('sources'),
            ai_statuses: readGroup('ai_statuses'),
            rate_limit_per_minute: parseInt(document.getElementById('discordRateLimit')?.value || '10', 10),
        };
        if (urlVal) payload.url = urlVal;
        else if (!state.urlConfigured) {
            feedback('Enter a Discord webhook URL before enabling.', 'warning');
            return;
        }

        const btn = document.getElementById('btnSaveDiscord');
        if (btn) btn.disabled = true;
        try {
            const res = await fetch('/api/integrations/discord', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            if (!res.ok) {
                feedback(data.error || 'Save failed', 'danger');
                return;
            }
            feedback('Discord integration saved.', 'success');
            await loadConfig();
        } catch (e) {
            feedback(`Save failed: ${e}`, 'danger');
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function testDiscord() {
        const btn = document.getElementById('btnTestDiscord');
        if (btn) btn.disabled = true;
        try {
            const res = await fetch('/api/integrations/discord/test', { method: 'POST' });
            const data = await res.json();
            feedback(res.ok ? (data.message || 'Test sent.') : (data.error || 'Test failed'), res.ok ? 'success' : 'danger');
        } catch (e) {
            feedback(`Test failed: ${e}`, 'danger');
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        wireFilterGroups();
        loadConfig();
        document.getElementById('btnSaveDiscord')?.addEventListener('click', saveDiscord);
        document.getElementById('btnTestDiscord')?.addEventListener('click', testDiscord);
    });
})();
