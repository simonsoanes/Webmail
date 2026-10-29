// UI helpers for the Blazor circuit: theme, keyboard shortcuts, live mailbox events,
// and sizing of the sandboxed message frame. No third-party code.
window.nullifyApp = (() => {
    let dotnet = null;

    // ---- resizable panes ----------------------------------------------------
    // Widths live in CSS variables on <html> and in localStorage, so they survive
    // re-renders and reloads. Dragging the sidebar narrow snaps it to an icon rail.
    const panes = {
        sidebar: { cssVar: '--sidebar-w', key: 'nullify.sidebarW', min: 180, max: 440, def: 248, collapseBelow: 140 },
        list: { cssVar: '--list-w', key: 'nullify.listW', min: 280, max: 760, def: 400 },
    };
    const root = document.documentElement;
    const store = {
        get(k) { try { return localStorage.getItem(k); } catch { return null; } },
        set(k, v) { try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch { } },
    };

    function applyWidth(name, px, persist) {
        const p = panes[name];
        if (name === 'sidebar' && p.collapseBelow && px < p.collapseBelow) {
            root.dataset.sidebar = 'collapsed';
            if (persist) store.set('nullify.sidebarCollapsed', '1');
            return;
        }
        if (name === 'sidebar') {
            delete root.dataset.sidebar;
            if (persist) store.set('nullify.sidebarCollapsed', null);
        }
        // Never take space the other panes need (reading pane ≥ 320px, list ≥ 280px),
        // so the stored width is the width the user actually sees.
        const sidebarPx = root.dataset.sidebar === 'collapsed' ? 64 : (parseInt(getComputedStyle(root).getPropertyValue('--sidebar-w'), 10) || 248);
        const room = name === 'list' ? window.innerWidth - sidebarPx - 322 : window.innerWidth - panes.list.min - 322;
        const w = Math.round(Math.min(p.max, Math.max(p.min, Math.min(px, room))));
        root.style.setProperty(p.cssVar, w + 'px');
        if (persist) store.set(p.key, String(w));
    }

    function currentWidth(name) {
        if (name === 'sidebar' && root.dataset.sidebar === 'collapsed') return 64;
        const v = parseInt(getComputedStyle(root).getPropertyValue(panes[name].cssVar), 10);
        return isNaN(v) ? panes[name].def : v;
    }

    function resetWidth(name) {
        const p = panes[name];
        root.style.removeProperty(p.cssVar);
        store.set(p.key, null);
        if (name === 'sidebar') { delete root.dataset.sidebar; store.set('nullify.sidebarCollapsed', null); }
    }

    function restoreWidths() {
        for (const name of Object.keys(panes)) {
            const saved = parseInt(store.get(panes[name].key), 10);
            if (!isNaN(saved)) applyWidth(name, saved, false);
        }
        if (store.get('nullify.sidebarCollapsed') === '1') root.dataset.sidebar = 'collapsed';
    }

    function wireSplitters() {
        if (wireSplitters.done) return;
        wireSplitters.done = true;

        document.addEventListener('pointerdown', (e) => {
            const handle = e.target.closest('.splitter[data-resize]');
            if (!handle || e.button !== 0) return;
            e.preventDefault();
            const name = handle.dataset.resize;
            const startX = e.clientX;
            const startW = currentWidth(name);
            handle.setPointerCapture(e.pointerId);
            root.classList.add('resizing');
            const move = (ev) => applyWidth(name, startW + ev.clientX - startX, false);
            const up = (ev) => {
                handle.removeEventListener('pointermove', move);
                handle.removeEventListener('pointerup', up);
                handle.removeEventListener('pointercancel', up);
                root.classList.remove('resizing');
                applyWidth(name, startW + ev.clientX - startX, true);
            };
            handle.addEventListener('pointermove', move);
            handle.addEventListener('pointerup', up);
            handle.addEventListener('pointercancel', up);
        });

        document.addEventListener('dblclick', (e) => {
            const handle = e.target.closest('.splitter[data-resize]');
            if (handle) resetWidth(handle.dataset.resize);
        });

        document.addEventListener('keydown', (e) => {
            const handle = e.target.closest && e.target.closest('.splitter[data-resize]');
            if (!handle) return;
            const name = handle.dataset.resize;
            const step = e.shiftKey ? 64 : 16;
            if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
                e.preventDefault();
                e.stopPropagation();
                const from = name === 'sidebar' && root.dataset.sidebar === 'collapsed' && e.key === 'ArrowRight'
                    ? panes.sidebar.min - step : currentWidth(name);
                applyWidth(name, from + (e.key === 'ArrowRight' ? step : -step), true);
            } else if (e.key === 'Home') {
                e.preventDefault();
                resetWidth(name);
            }
        }, true);
    }

    restoreWidths();

    // Firefox only starts a drag when the drag carries some data; Blazor's handlers don't set any.
    document.addEventListener('dragstart', (e) => {
        const el = e.target;
        if (!el || !el.closest || !el.closest('.msg-row, .nav-item[draggable="true"]') || !e.dataTransfer) return;
        if (e.dataTransfer.types.length === 0) e.dataTransfer.setData('text/plain', '');
        e.dataTransfer.effectAllowed = 'move';
    });
    // Recipient suggestions: while a field's list is open, the navigation keys drive the list
    // (handled in Blazor) instead of moving the caret, leaving the field or submitting.
    // This listener runs on the input itself, before the document-level shortcut handler.
    document.addEventListener('keydown', (e) => {
        const el = e.target;
        if (!el || el.dataset == null || el.dataset.suggestOpen !== 'true') return;
        if (e.ctrlKey || e.metaKey || e.altKey) return;
        if (['ArrowDown', 'ArrowUp', 'Enter', 'Tab', 'Escape'].includes(e.key)) e.preventDefault();
    }, true);
    let events = null;
    let keyHandler = null;

    const isTyping = (el) =>
        el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));

    function connectEvents() {
        if (!window.EventSource || events) return;
        events = new EventSource('api/events', { withCredentials: true });
        events.addEventListener('update', () => dotnet && dotnet.invokeMethodAsync('OnMailboxUpdate'));
        // EventSource reconnects on its own; nothing to do on error.
    }

    return {
        /** Wire shortcuts + live updates; returns the browser's IANA time zone. */
        init(ref) {
            dotnet = ref;
            if (keyHandler) document.removeEventListener('keydown', keyHandler);
            keyHandler = (e) => {
                // An open suggestion list (see below) has already claimed this key.
                if (e.defaultPrevented) return;
                if (e.ctrlKey || e.metaKey || e.altKey) {
                    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && document.querySelector('.compose-form')) {
                        e.preventDefault();
                        dotnet.invokeMethodAsync('OnShortcut', 'send');
                    }
                    return;
                }
                if (e.key === 'Escape') {
                    if (document.activeElement && isTyping(document.activeElement)) document.activeElement.blur();
                    dotnet.invokeMethodAsync('OnShortcut', 'escape');
                    return;
                }
                if (isTyping(e.target)) return;
                if (e.key === '/') {
                    const search = document.querySelector('.list-search input');
                    if (search) { e.preventDefault(); search.focus(); search.select(); }
                    return;
                }
                const keys = ['j', 'k', 'r', 'a', 'f', 'c', 'e', 's', 'u', '#', 'Delete', '?', 'ArrowDown', 'ArrowUp'];
                if (keys.includes(e.key)) {
                    e.preventDefault();
                    dotnet.invokeMethodAsync('OnShortcut', e.key);
                }
            };
            document.addEventListener('keydown', keyHandler);
            wireSplitters();
            connectEvents();
            try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch { return ''; }
        },

        dispose() {
            if (keyHandler) document.removeEventListener('keydown', keyHandler);
            if (events) events.close();
            keyHandler = null; events = null; dotnet = null;
        },

        getTheme() {
            try { return localStorage.getItem('nullify.theme') || 'system'; } catch { return 'system'; }
        },

        setTheme(theme) {
            try { localStorage.setItem('nullify.theme', theme); } catch { }
            if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
            else delete document.documentElement.dataset.theme;
        },

        /** Size the message iframe to its content (same-origin sandbox, scripts still disabled). */
        fitFrame(frame) {
            if (!frame) return;
            const fit = () => {
                try {
                    const doc = frame.contentDocument;
                    if (!doc || !doc.body) return;
                    // body, not <html>: the root element is never shorter than the frame itself.
                    // Fixed-width newsletters scroll sideways; leave room for that scrollbar.
                    const root = doc.documentElement;
                    const hbar = root.scrollWidth > root.clientWidth ? 18 : 0;
                    frame.style.height = Math.max(Math.ceil(doc.body.scrollHeight) + 4 + hbar, 120) + 'px';
                } catch { /* cross-origin: keep default height */ }
            };
            if (!frame._nullifyFit) {
                // Blazor reuses the element when srcdoc changes, so wire it once.
                frame._nullifyFit = true;
                frame.addEventListener('load', () => {
                    fit();
                    try {
                        const doc = frame.contentDocument;
                        doc.querySelectorAll('img').forEach(img => img.addEventListener('load', fit));
                        if (window.ResizeObserver) new ResizeObserver(fit).observe(doc.body);
                    } catch { }
                });
            }
            fit();
        },

        /** Toggle the icon-rail sidebar (used by the collapse button). */
        toggleSidebar() {
            if (root.dataset.sidebar === 'collapsed') {
                delete root.dataset.sidebar;
                store.set('nullify.sidebarCollapsed', null);
            } else {
                root.dataset.sidebar = 'collapsed';
                store.set('nullify.sidebarCollapsed', '1');
            }
        },

        scrollIntoView(selector) {
            const el = document.querySelector(selector);
            if (el) el.scrollIntoView({ block: 'nearest' });
        },

        focus(selector) {
            const el = document.querySelector(selector);
            if (el) el.focus();
        },

        /** Focus a textarea with the caret at the very top (replies are written above the quote). */
        focusStart(el) {
            if (!el) return;
            el.focus();
            el.setSelectionRange(0, 0);
            el.scrollTop = 0;
        },

        /** Focus an input with the caret after its last character. */
        focusEnd(el) {
            if (!el) return;
            el.focus();
            const end = el.value.length;
            el.setSelectionRange(end, end);
            el.scrollLeft = el.scrollWidth;
        },

        confirm(message) { return window.confirm(message); },

        /**
         * Drag across days ([data-day]) or times ([data-slot]) on the calendar to highlight them.
         * The drag is painted here, without round trips; the calendar hears of the range when the
         * button goes up: OnCalendarRange(kind, from, to) with the first and last cells' keys.
         * A click on a time slot is reported the same way (from == to); clicks on days are left to
         * the calendar. Touch only taps, so the page still scrolls.
         */
        calendarSelect(root, ref) {
            if (!root) return;
            if (root._calSel) { root._calSel.ref = ref; return; }
            const s = root._calSel = { ref, kind: null, anchor: null, current: null, moved: false, swallow: false, touch: false };
            const key = (el) => s.kind === 'slot' ? el.dataset.slot : el.dataset.day;
            const selector = () => s.kind === 'slot' ? '[data-slot]' : '[data-day]';
            const paint = () => {
                const a = key(s.anchor), b = key(s.current);
                const [lo, hi] = a <= b ? [a, b] : [b, a];
                root.querySelectorAll(selector()).forEach(el => {
                    const k = key(el);
                    el.classList.toggle('sel-drag', s.moved && k >= lo && k <= hi);
                });
            };
            const clear = () => root.querySelectorAll('.sel-drag').forEach(el => el.classList.remove('sel-drag'));
            root.addEventListener('pointerdown', (e) => {
                if (e.button !== 0 || e.target.closest('button, a, input, select, .tg-event, .sel-toolbar')) return;
                const cell = e.target.closest('[data-day], [data-slot]');
                if (!cell || !root.contains(cell)) return;
                s.kind = cell.dataset.slot ? 'slot' : 'day';
                s.anchor = s.current = cell;
                s.moved = false;
                s.touch = e.pointerType === 'touch';
            });
            window.addEventListener('pointermove', (e) => {
                if (!s.anchor || s.touch) return;
                const hit = document.elementFromPoint(e.clientX, e.clientY);
                const cell = hit && hit.closest(selector());
                if (!cell || !root.contains(cell) || cell === s.current) return;
                s.current = cell;
                s.moved = true;
                paint();
            });
            window.addEventListener('pointerup', () => {
                if (!s.anchor) return;
                const from = key(s.anchor), to = key(s.current), kind = s.kind, moved = s.moved;
                s.anchor = s.current = null;
                if (moved) {
                    // The click that follows a drag isn't a click on a day (it comes straight after, if at all).
                    s.swallow = true;
                    setTimeout(() => { s.swallow = false; }, 0);
                }
                if ((moved || kind === 'slot') && s.ref) s.ref.invokeMethodAsync('OnCalendarRange', kind, from, to).finally(clear);
                else clear();
            });
            window.addEventListener('pointercancel', () => { s.anchor = s.current = null; clear(); });
            root.addEventListener('click', (e) => {
                if (!s.swallow) return;
                s.swallow = false;
                e.stopPropagation();
            }, true);
        },

        /** Scroll the time grid so that a time of day (minutes after midnight) is near the top. */
        scrollCalendarTo(el, minutes) {
            if (!el) return;
            el.scrollTop = Math.max(0, el.scrollHeight * minutes / 1440 - 8);
        },

        /** Tell the mail page, if it is up, that files were opened with the app. */
        notifyLaunchedFiles() { if (dotnet) dotnet.invokeMethodAsync('OnFilesLaunched'); },

        /** Keep a context menu opened at (x, y) inside the window; focus it when it first opens. */
        fitMenu(el, x, y, first) {
            if (!el) return;
            const pad = 8;
            const w = el.offsetWidth, h = el.offsetHeight;
            el.style.left = Math.max(pad, Math.min(x, window.innerWidth - w - pad)) + 'px';
            el.style.top = Math.max(pad, Math.min(y, window.innerHeight - h - pad)) + 'px';
            if (first) {
                const item = el.querySelector('input, .menu-item');
                if (item) item.focus({ preventScroll: true });
            }
        },
    };
})();

// Calendar files opened with the installed app (the manifest's file_handlers). They wait in
// sessionStorage, so they survive signing in first, until the mail page takes them.
(() => {
    const key = 'nullify.launchedFiles';
    const maxBytes = 1024 * 1024;
    const read = () => { try { return JSON.parse(sessionStorage.getItem(key) || '[]'); } catch { return []; } };
    const write = (files) => { try { if (files.length) sessionStorage.setItem(key, JSON.stringify(files)); else sessionStorage.removeItem(key); } catch { } };

    Object.assign(window.nullifyApp, {
        /** Names of the files waiting to be imported. */
        launchedFiles() { return read().map(f => f.name); },
        /** One waiting file's contents, as bytes so they stream past the circuit's message size limit. */
        launchedFile(i) { const f = read()[i]; return new TextEncoder().encode(f ? f.text : ''); },
        clearLaunchedFiles() { write([]); },
    });

    if (!('launchQueue' in window)) return;
    window.launchQueue.setConsumer(async (params) => {
        if (!params.files || !params.files.length) return;
        const files = read();
        for (const handle of params.files) {
            try {
                const file = await handle.getFile();
                if (file.size > maxBytes) continue;
                files.push({ name: file.name, text: await file.text() });
            } catch { /* unreadable: skip it */ }
        }
        write(files);
        window.nullifyApp.notifyLaunchedFiles();
    });
})();

// Installable as an app. The worker only shows an offline page; it caches no mail.
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => { });
