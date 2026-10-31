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

    // ---- notifications (installed app only; the choices are kept in this browser) ----
    const NOTIFY_PREFS = 'nullify.notify', NOTIFIED = 'nullify.notified';
    const installed = () =>
        ['standalone', 'window-controls-overlay', 'minimal-ui', 'fullscreen'].some(m => matchMedia(`(display-mode: ${m})`).matches)
        || navigator.standalone === true;
    const notifyPrefs = () => {
        try {
            const v = JSON.parse(localStorage.getItem(NOTIFY_PREFS) || '{}');
            return { mail: v.mail === true, calendar: v.calendar === true };
        } catch { return { mail: false, calendar: false }; }
    };
    const notifyState = () => ({
        supported: 'Notification' in window && 'serviceWorker' in navigator,
        installed: installed(),
        permission: 'Notification' in window ? Notification.permission : 'denied',
        ...notifyPrefs()
    });
    // ---- installing as an app ----------------------------------------------
    // Chromium browsers offer their install prompt once the page qualifies; keep it for the
    // Settings button instead of letting the browser show its own banner.
    let installPrompt = null, installWatcher = null;
    const installChanged = () => { if (installWatcher) installWatcher.invokeMethodAsync('OnInstallChanged').catch(() => { }); };
    window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); installPrompt = e; installChanged(); });
    window.addEventListener('appinstalled', () => { installPrompt = null; installChanged(); });
    const installState = () => {
        const ua = navigator.userAgent;
        const ios = /iPad|iPhone|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
        const platform = ios ? 'ios'
            : /Firefox\//.test(ua) ? 'firefox'
            : /Safari\//.test(ua) && !/Chrome\/|Chromium\/|Edg\//.test(ua) ? 'safari'
            : 'other';
        return { installed: installed(), canPrompt: !!installPrompt, platform };
    };

    /** Tags already shown (by this or another window), so a reminder pops up once. */
    const markNotified = (tag) => {
        let seen = {};
        try { seen = JSON.parse(localStorage.getItem(NOTIFIED) || '{}') || {}; } catch { }
        if (seen[tag]) return false;
        const now = Date.now();
        for (const [k, t] of Object.entries(seen)) if (now - t > 3 * 86400000) delete seen[k];
        seen[tag] = now;
        try { localStorage.setItem(NOTIFIED, JSON.stringify(seen)); } catch { }
        return true;
    };
    let swListener = null;
    function listenForNotificationClicks() {
        if (swListener || !('serviceWorker' in navigator)) return;
        swListener = (e) => {
            const d = e.data;
            if (d && d.type === 'notification-click' && dotnet) dotnet.invokeMethodAsync('OnNotificationClick', d.kind || '', d.id || '');
        };
        navigator.serviceWorker.addEventListener('message', swListener);
    }

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
            listenForNotificationClicks();
            try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch { return ''; }
        },

        dispose() {
            if (keyHandler) document.removeEventListener('keydown', keyHandler);
            if (events) events.close();
            if (swListener) navigator.serviceWorker.removeEventListener('message', swListener);
            keyHandler = null; events = null; dotnet = null; swListener = null;
        },

        async copyText(text) {
            try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
        },

        install: {
            state: installState,

            /** Show the browser's install prompt; returns 'accepted', 'dismissed' or 'unavailable'. */
            async prompt() {
                const p = installPrompt;
                if (!p) return 'unavailable';
                installPrompt = null; // each prompt can be shown once
                try {
                    await p.prompt();
                    const choice = await p.userChoice;
                    return choice.outcome;
                } catch { return 'unavailable'; }
            },

            /** Tell a component (OnInstallChanged) when installing becomes possible or is done. */
            watch(ref) { installWatcher = ref; },
        },

        notifications: {
            state: notifyState,

            /** Turn one kind ('mail' or 'calendar') on or off; turning on asks for permission first. */
            async set(kind, on) {
                if (on && 'Notification' in window && Notification.permission === 'default') {
                    try { await Notification.requestPermission(); } catch { }
                }
                const prefs = notifyPrefs();
                prefs[kind] = on && 'Notification' in window && Notification.permission === 'granted';
                try { localStorage.setItem(NOTIFY_PREFS, JSON.stringify(prefs)); } catch { }
                return notifyState();
            },

            /**
             * Show a notification of one kind, if it's turned on and this is the installed app.
             * With onlyWhenAway it's skipped while the user is looking at the app. Each tag is shown once.
             */
            async show(kind, tag, title, body, id, onlyWhenAway) {
                const st = notifyState();
                if (!st.supported || !st.installed || st.permission !== 'granted' || !st[kind]) return false;
                if (onlyWhenAway && document.visibilityState === 'visible' && document.hasFocus()) return false;
                if (!markNotified(tag)) return false;
                const options = { body, tag, icon: 'icons/icon-192.png', data: { kind, id } };
                try {
                    const reg = await navigator.serviceWorker.ready;
                    await reg.showNotification(title, options);
                } catch {
                    try {
                        const n = new Notification(title, options);
                        n.onclick = () => { window.focus(); if (dotnet) dotnet.invokeMethodAsync('OnNotificationClick', kind, id || ''); n.close(); };
                    } catch { return false; }
                }
                return true;
            },

            /** Send a sample, so the user sees what they've turned on. */
            async test() {
                if (!('Notification' in window) || Notification.permission !== 'granted') return false;
                const options = { body: 'Notifications are working.', tag: 'nullify-test', icon: 'icons/icon-192.png' };
                try { await (await navigator.serviceWorker.ready).showNotification(document.title, options); }
                catch { try { new Notification(document.title, options); } catch { return false; } }
                return true;
            }
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
         * Pointer work on the calendar, painted here without round trips and reported when the
         * button goes up:
         * - Drag across days ([data-day]) to highlight them: OnCalendarRange('day', first, last).
         * - Drag down the time grid (.tg-col[data-date]) to highlight a stretch of time, from the
         *   half hour where the drag began to the half-hour line nearest the pointer, exactly as
         *   painted: OnCalendarRange('slot', start, end). A click reports start == end.
         * - Drag an event ([data-ev]) to another day, OnEventDrop(key, 'day', fromDay, toDay), or on
         *   the time grid to another time, OnEventDrop(key, 'time', start, end); dragging its bottom
         *   edge (.tg-resize) changes when it ends. Esc cancels.
         * Clicks on days and events are left to the calendar. Touch only taps, so the page still scrolls.
         */
        calendarSelect(root, ref) {
            if (!root) return;
            if (root._calSel) { root._calSel.ref = ref; return; }
            const s = root._calSel = { ref, sel: null, drag: null, swallow: false };
            const pad = (n) => String(n).padStart(2, '0');
            const dayKey = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
            const hhmm = (d) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
            const fmt = (d) => `${dayKey(d)}T${hhmm(d)}`;
            const parse = (text) => {
                const [date, time = '00:00'] = text.split('T');
                const [y, m, d] = date.split('-').map(Number);
                const [h, mi] = time.split(':').map(Number);
                return new Date(y, m - 1, d, h, mi);
            };
            const at = (date, minutes) => { const d = parse(date); d.setMinutes(Math.round(minutes)); return d; };
            const addMin = (d, n) => new Date(d.getTime() + n * 60000);
            const quarter = 15 * 60000;
            const hitAt = (x, y, selector) => {
                const hit = document.elementFromPoint(x, y);
                const el = hit && hit.closest(selector);
                return el && root.contains(el) ? el : null;
            };
            const minutesIn = (col, y) => {
                const r = col.getBoundingClientRect();
                return Math.max(0, Math.min(1440, (y - r.top) / r.height * 1440));
            };
            const far = (e, from) => Math.hypot(e.clientX - from.x, e.clientY - from.y) >= 4;
            const swallowClick = () => { s.swallow = true; setTimeout(() => { s.swallow = false; }, 0); };
            const clearPaint = () => root.querySelectorAll('.sel-drag, .drop-target').forEach(el => el.classList.remove('sel-drag', 'drop-target'));
            const call = (method, ...args) => s.ref ? s.ref.invokeMethodAsync(method, ...args) : Promise.resolve();

            // ---- highlighting days and times

            const range = (v) => {
                if (v.kind === 'day') return v.anchor <= v.current ? [v.anchor, v.current] : [v.current, v.anchor];
                const slotEnd = addMin(v.anchor, 30);
                return v.current > v.anchor ? [v.anchor, v.current > slotEnd ? v.current : slotEnd] : [v.current, slotEnd];
            };
            const paintSelection = () => {
                const [lo, hi] = range(s.sel);
                if (s.sel.kind === 'day') {
                    root.querySelectorAll('[data-day]').forEach(el => el.classList.toggle('sel-drag', el.dataset.day >= lo && el.dataset.day <= hi));
                } else {
                    root.querySelectorAll('[data-slot]').forEach(el => {
                        const t = parse(el.dataset.slot);
                        el.classList.toggle('sel-drag', t >= lo && t < hi);
                    });
                }
            };

            // ---- moving and resizing events

            const ghostFor = (d) => {
                const g = document.createElement('div');
                g.className = 'cal-ghost' + (d.timed ? ' timed' : '');
                g.style.setProperty('--cal', d.el.style.getPropertyValue('--cal'));
                if (d.timed) {
                    const title = document.createElement('span');
                    title.className = 'ev-title';
                    title.textContent = (d.el.querySelector('.ev-title') || d.el).textContent;
                    const time = document.createElement('span');
                    time.className = 'ev-time';
                    g.append(title, time);
                } else {
                    g.append(...[...d.el.childNodes].map(n => n.cloneNode(true)));
                    g.style.width = d.el.getBoundingClientRect().width + 'px';
                }
                document.body.appendChild(g);
                return g;
            };
            const placeTimed = (d) => {
                const col = root.querySelector(`.tg-col[data-date="${dayKey(d.newStart)}"]`) || d.col;
                const r = col.getBoundingClientRect();
                const view = (col.closest('.tg-scroll') || col).getBoundingClientRect();
                const dayStart = at(col.dataset.date, 0);
                const startMin = Math.max(0, (d.newStart - dayStart) / 60000);
                const endMin = Math.min(1440, Math.max(startMin + 15, (d.newEnd - dayStart) / 60000));
                const top = Math.max(view.top, r.top + startMin / 1440 * r.height);
                const bottom = Math.min(view.bottom, r.top + endMin / 1440 * r.height);
                Object.assign(d.ghost.style, { left: r.left + 1 + 'px', width: r.width - 3 + 'px', top: top + 'px', height: Math.max(bottom - top, 4) + 'px' });
                d.ghost.querySelector('.ev-time').textContent = `${hhmm(d.newStart)} – ${hhmm(d.newEnd)}`;
            };
            const endDrag = (d) => {
                if (d.ghost) d.ghost.remove();
                d.el.classList.remove('drag-src');
                document.documentElement.classList.remove('cal-moving', 'cal-resizing');
                clearPaint();
            };

            root.addEventListener('pointerdown', (e) => {
                if (e.button !== 0 || s.drag || s.sel) return;
                const touch = e.pointerType === 'touch';
                const evEl = e.target.closest('[data-ev]');
                if (evEl && root.contains(evEl)) {
                    if (touch) return;
                    const col = evEl.closest('.tg-col[data-date]');
                    const d = { el: evEl, key: evEl.dataset.ev, x: e.clientX, y: e.clientY, started: false, timed: !!col, col };
                    if (col) {
                        d.start = parse(evEl.dataset.start);
                        d.end = parse(evEl.dataset.end);
                        d.resize = !!e.target.closest('.tg-resize');
                        d.grab = (at(col.dataset.date, minutesIn(col, e.clientY)) - d.start) / 60000;
                    } else {
                        const cell = evEl.closest('[data-day]');
                        if (!cell) return;
                        d.from = cell.dataset.day;
                        const r = evEl.getBoundingClientRect();
                        d.offset = { x: e.clientX - r.left, y: e.clientY - r.top };
                    }
                    s.drag = d;
                    return;
                }
                if (e.target.closest('button, a, input, select, .tg-event, .sel-toolbar')) return;
                const cell = e.target.closest('[data-day], .tg-col[data-date]');
                if (!cell || !root.contains(cell)) return;
                if (cell.dataset.day) {
                    s.sel = { kind: 'day', anchor: cell.dataset.day, current: cell.dataset.day, x: e.clientX, y: e.clientY, moved: false, touch };
                } else {
                    const start = at(cell.dataset.date, Math.floor(minutesIn(cell, e.clientY) / 30) * 30);
                    s.sel = { kind: 'slot', anchor: start, current: start, x: e.clientX, y: e.clientY, moved: false, touch };
                }
            });

            window.addEventListener('pointermove', (e) => {
                const v = s.sel;
                if (v) {
                    if (v.touch || (!v.moved && !far(e, v))) return;
                    if (v.kind === 'day') {
                        const cell = hitAt(e.clientX, e.clientY, '[data-day]');
                        if (!cell) return;
                        v.current = cell.dataset.day;
                    } else {
                        const col = hitAt(e.clientX, e.clientY, '.tg-col[data-date]');
                        if (!col) return;
                        v.current = at(col.dataset.date, Math.round(minutesIn(col, e.clientY) / 30) * 30);
                    }
                    v.moved = true;
                    paintSelection();
                    return;
                }
                const d = s.drag;
                if (!d || d.cancelled) return;
                if (!d.started) {
                    if (!far(e, d)) return;
                    d.started = true;
                    d.el.classList.add('drag-src');
                    d.ghost = ghostFor(d);
                    document.documentElement.classList.add(d.resize ? 'cal-resizing' : 'cal-moving');
                }
                if (d.timed) {
                    if (d.resize) {
                        let end = at(d.col.dataset.date, Math.round(minutesIn(d.col, e.clientY) / 15) * 15);
                        if (end < addMin(d.start, 15)) end = addMin(d.start, 15);
                        d.newStart = d.start;
                        d.newEnd = end;
                    } else {
                        const col = hitAt(e.clientX, e.clientY, '.tg-col[data-date]');
                        if (col) {
                            const pointer = at(col.dataset.date, minutesIn(col, e.clientY));
                            d.newStart = new Date(Math.round(addMin(pointer, -d.grab) / quarter) * quarter);
                            d.newEnd = new Date(d.newStart.getTime() + (d.end - d.start));
                        }
                    }
                    if (d.newStart) placeTimed(d);
                } else {
                    Object.assign(d.ghost.style, { left: e.clientX - d.offset.x + 'px', top: e.clientY - d.offset.y + 'px' });
                    const cell = hitAt(e.clientX, e.clientY, '[data-day]');
                    if (cell) d.to = cell.dataset.day;
                    root.querySelectorAll('[data-day]').forEach(el => el.classList.toggle('drop-target', !!cell && el === cell));
                }
            });

            window.addEventListener('pointerup', () => {
                const v = s.sel;
                if (v) {
                    s.sel = null;
                    if (v.moved) swallowClick();
                    if (v.kind === 'day') {
                        // A click on a day is the calendar's to handle.
                        if (!v.moved) return clearPaint();
                        const [lo, hi] = range(v);
                        call('OnCalendarRange', 'day', lo, hi).finally(clearPaint);
                    } else {
                        const [lo, hi] = v.moved ? range(v) : [v.anchor, v.anchor];
                        call('OnCalendarRange', 'slot', fmt(lo), fmt(hi)).finally(clearPaint);
                    }
                    return;
                }
                const d = s.drag;
                if (!d) return;
                s.drag = null;
                if (!d.started) return; // a click: the calendar opens the event
                swallowClick();
                if (d.cancelled) return;
                let args = null;
                if (d.timed && d.newStart && (+d.newStart !== +d.start || +d.newEnd !== +d.end)) args = ['time', fmt(d.newStart), fmt(d.newEnd)];
                else if (!d.timed && d.to && d.to !== d.from) args = ['day', d.from, d.to];
                // The ghost stays where it was dropped until the calendar has saved and redrawn.
                if (args) call('OnEventDrop', d.key, ...args).finally(() => endDrag(d));
                else endDrag(d);
            });

            window.addEventListener('pointercancel', () => {
                if (s.drag) endDrag(s.drag);
                s.sel = s.drag = null;
                clearPaint();
            });

            window.addEventListener('keydown', (e) => {
                if (e.key !== 'Escape') return;
                if (s.drag && s.drag.started && !s.drag.cancelled) {
                    s.drag.cancelled = true;
                    endDrag(s.drag);
                } else if (s.sel) {
                    s.sel = null;
                    clearPaint();
                }
            });

            root.addEventListener('click', (e) => {
                if (!s.swallow) return;
                s.swallow = false;
                e.stopPropagation();
            }, true);
        },

        /** Scroll a list so the rows under a sticky letter heading ([data-letter]) start at its top. */
        jumpToLetter(list, letter) {
            if (!list) return;
            const head = [...list.querySelectorAll('[data-letter]')].find(h => h.dataset.letter === letter);
            if (!head) return;
            const row = head.nextElementSibling || head;
            list.scrollTop += row.getBoundingClientRect().top - list.getBoundingClientRect().top - head.offsetHeight;
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
