// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

// The compose editor: a contenteditable body with a formatting toolbar, and photos and files
// that are pasted, dropped or picked. Files stay in the page until .NET takes them as streams
// (they would not fit in a circuit message), and the finished body goes back the same way.

const QUOTE_STYLE = 'margin:0 0 0 .8ex;border-left:2px solid #ccc;padding-left:1ex';
const SANS = "-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO = "Consolas,'Cascadia Mono','Courier New',monospace";
const MAX_IMAGE_EDGE = 2048;   // inline photos larger than this are scaled down before sending

// Formatting that pasted HTML may keep; everything else is reduced to its text.
const KEEP_TAGS = new Set(['B', 'STRONG', 'I', 'EM', 'U', 'S', 'STRIKE', 'DEL', 'SUB', 'SUP', 'BR', 'P', 'DIV',
    'SPAN', 'FONT', 'UL', 'OL', 'LI', 'BLOCKQUOTE', 'PRE', 'CODE', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'A',
    'TABLE', 'THEAD', 'TBODY', 'TR', 'TD', 'TH', 'HR']);
const DROP_TAGS = new Set(['SCRIPT', 'STYLE', 'HEAD', 'TITLE', 'META', 'LINK', 'IFRAME', 'OBJECT', 'EMBED',
    'SVG', 'MATH', 'TEMPLATE', 'NOSCRIPT', 'IMG', 'VIDEO', 'AUDIO', 'PICTURE', 'FORM', 'INPUT', 'BUTTON', 'SELECT', 'TEXTAREA']);
const KEEP_STYLES = ['color', 'background-color', 'font-weight', 'font-style', 'text-decoration', 'text-decoration-line',
    'font-size', 'font-family', 'text-align'];
const RICH = 'b,strong,i,em,u,s,strike,del,sub,sup,font,ul,ol,img,a,h1,h2,h3,h4,h5,h6,table,pre,hr,[style]';

let nextId = 1;

/**
 * Wire up one compose form. Returns the handle .NET keeps: content(), take(id), dropImage(cid),
 * focus(atStart), isDirty(), dispose().
 */
export function init(form, editor, toolbar, html, mono, dotnet) {
    const files = new Map();    // id -> File waiting for .NET
    const urls = new Map();     // cid -> object URL shown in the editor
    let saved = null;           // the last selection inside the editor
    let initial = '';

    document.execCommand('defaultParagraphSeparator', false, 'div');
    editor.innerHTML = html || '<div><br></div>';
    initial = editor.innerHTML;

    // ---- selection --------------------------------------------------------
    const inEditor = (node) => node && editor.contains(node.nodeType === 1 ? node : node.parentNode);
    const onSelection = () => {
        const sel = document.getSelection();
        if (sel.rangeCount && inEditor(sel.anchorNode)) {
            saved = sel.getRangeAt(0).cloneRange();
            reflect();
        }
    };
    document.addEventListener('selectionchange', onSelection);

    function restore() {
        editor.focus();
        if (!saved) return;
        const sel = document.getSelection();
        sel.removeAllRanges();
        sel.addRange(saved);
    }

    function exec(cmd, value = null, css = true) {
        restore();
        document.execCommand('styleWithCSS', false, css);
        document.execCommand(cmd, false, value);
        onSelection();
    }

    // Toolbar buttons light up for the formatting under the caret.
    function reflect() {
        for (const b of toolbar.querySelectorAll('[data-cmd]')) {
            const cmd = b.dataset.cmd;
            if (!['bold', 'italic', 'underline', 'strikeThrough', 'insertUnorderedList', 'insertOrderedList'].includes(cmd)) continue;
            let on = false;
            try { on = document.queryCommandState(cmd); } catch { }
            b.classList.toggle('on', on);
            b.setAttribute('aria-pressed', on);
        }
        const node = saved && (saved.startContainer.nodeType === 1 ? saved.startContainer : saved.startContainer.parentElement);
        if (!node) return;
        const style = getComputedStyle(node);
        const size = toolbar.querySelector('[data-size]');
        if (size) {
            const pt = Math.round(parseFloat(style.fontSize) * 0.75);
            size.value = [...size.options].some(o => o.value === String(pt)) ? String(pt) : '';
        }
        const font = toolbar.querySelector('[data-font]');
        if (font) {
            const first = style.fontFamily.split(',')[0].replace(/['"]/g, '').trim().toLowerCase();
            const match = [...font.options].find(o => o.value.split(',')[0].replace(/['"]/g, '').trim().toLowerCase() === first);
            font.value = match ? match.value : '';
        }
    }

    // ---- toolbar ----------------------------------------------------------
    const panels = () => toolbar.querySelectorAll('.fmt-panel');
    const closePanels = () => panels().forEach(p => { p.hidden = true; });

    // Buttons must not take focus, or the selection they act on is lost.
    toolbar.addEventListener('mousedown', (e) => {
        if (e.target.closest('button')) e.preventDefault();
    });

    toolbar.addEventListener('click', (e) => {
        const b = e.target.closest('button');
        if (!b) return;
        const d = b.dataset;
        if (d.panel) {
            const panel = toolbar.querySelector(`.fmt-panel[data-for="${d.panel}"]`);
            const open = panel.hidden;
            closePanels();
            panel.hidden = !open;
            b.setAttribute('aria-expanded', open);
            return;
        }
        if (d.cmd === 'createLink') return link();
        if (d.cmd === 'insertImage') return pickImages();
        if (d.cmd) exec(d.cmd, null, d.cmd !== 'removeFormat');
        if (d.fore != null) { exec('foreColor', d.fore); closePanels(); }
        if (d.back != null) { exec('hiliteColor', d.back || 'transparent'); closePanels(); }
    });

    toolbar.addEventListener('change', (e) => {
        const t = e.target;
        if (t.matches('[data-font]') && t.value) exec('fontName', t.value);
        else if (t.matches('[data-size]') && t.value) setSize(t.value);
        else if (t.matches('[data-fore-custom]')) { exec('foreColor', t.value); closePanels(); }
        else if (t.matches('[data-back-custom]')) { exec('hiliteColor', t.value); closePanels(); }
    });

    const onOutside = (e) => { if (!e.target.closest('.fmt-menu')) closePanels(); };
    document.addEventListener('mousedown', onOutside);

    // execCommand only knows sizes 1-7: apply 7 as a marker, then turn it into points.
    function setSize(pt) {
        exec('fontSize', '7', false);
        for (const f of editor.querySelectorAll('font[size="7"]')) {
            const span = document.createElement('span');
            span.style.fontSize = pt + 'pt';
            span.append(...f.childNodes);
            f.replaceWith(span);
        }
        onSelection();
    }

    function link() {
        const current = saved && saved.startContainer.parentElement?.closest('a');
        const url = window.prompt('Link address', current ? current.getAttribute('href') : 'https://');
        if (url == null) return restore();
        if (!url.trim() || url.trim() === 'https://') return exec('unlink');
        const safe = /^(https?:|mailto:)/i.test(url.trim()) ? url.trim() : 'https://' + url.trim();
        if (saved && saved.collapsed && !current) {
            restore();
            const a = document.createElement('a');
            a.href = safe;
            a.textContent = url.trim();
            document.execCommand('insertHTML', false, a.outerHTML);
        } else {
            exec('createLink', safe);
        }
    }

    // ---- keys -------------------------------------------------------------
    editor.addEventListener('keydown', (e) => {
        const mod = e.ctrlKey || e.metaKey;
        if (mod && !e.shiftKey && e.key.toLowerCase() === 'k') { e.preventDefault(); link(); }
        else if (mod && e.shiftKey && e.key.toLowerCase() === 'x') { e.preventDefault(); exec('strikeThrough'); }
        else if (mod && e.shiftKey && e.key === '*') { e.preventDefault(); exec('insertUnorderedList'); }
        else if (e.key === 'Tab' && !mod && !e.altKey) {
            const sel = document.getSelection();
            if (sel.anchorNode && (sel.anchorNode.nodeType === 1 ? sel.anchorNode : sel.anchorNode.parentElement).closest('li')) {
                e.preventDefault();
                exec(e.shiftKey ? 'outdent' : 'indent');
            }
        }
    });

    // ---- photos and files -------------------------------------------------
    function offer(list, inline, range) {
        const items = [];
        const imgs = [];
        for (const file of list) {
            const id = String(nextId++);
            files.set(id, file);
            const item = { id, name: file.name || 'file', type: file.type || 'application/octet-stream', size: file.size, cid: null };
            if (inline && file.type.startsWith('image/')) {
                item.cid = `img${id}.${crypto.randomUUID ? crypto.randomUUID() : Date.now()}@webmail`;
                if (!file.name || file.name === 'image.png') item.name = `image${id}.${extension(file.type)}`;
                const url = URL.createObjectURL(file);
                urls.set(item.cid, url);
                const img = document.createElement('img');
                img.src = url;
                img.alt = item.name;
                img.dataset.cid = item.cid;
                imgs.push(img.outerHTML);
            }
            items.push(item);
        }
        if (imgs.length) {
            if (range) { saved = range; }
            restore();
            document.execCommand('insertHTML', false, imgs.join(''));
        }
        if (items.length) dotnet.invokeMethodAsync('OnFilesOffered', items);
    }

    // Big photos are scaled down (which also drops their location and camera details).
    async function prepare(file) {
        if (!/^image\/(jpeg|png|webp)$/.test(file.type) || !window.createImageBitmap) return file;
        try {
            const bmp = await createImageBitmap(file);
            const scale = MAX_IMAGE_EDGE / Math.max(bmp.width, bmp.height);
            if (scale >= 1) { bmp.close(); return file; }
            const canvas = document.createElement('canvas');
            canvas.width = Math.round(bmp.width * scale);
            canvas.height = Math.round(bmp.height * scale);
            canvas.getContext('2d').drawImage(bmp, 0, 0, canvas.width, canvas.height);
            bmp.close();
            const type = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
            const blob = await new Promise(r => canvas.toBlob(r, type, 0.85));
            if (!blob || blob.size >= file.size) return file;
            const name = (file.name || 'image').replace(/\.[^.]*$/, '') + '.' + extension(type);
            return new File([blob], name, { type });
        } catch {
            return file;
        }
    }

    async function addInline(list, range) {
        offer(await Promise.all([...list].map(prepare)), true, range);
    }

    function pickImages() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'image/*';
        input.multiple = true;
        const range = saved;
        input.addEventListener('change', () => { if (input.files.length) addInline(input.files, range); });
        input.click();
    }

    editor.addEventListener('paste', (e) => {
        const dt = e.clipboardData;
        if (!dt) return;
        const pasted = [...dt.files];
        if (pasted.length) {
            e.preventDefault();
            const sel = document.getSelection();
            const here = sel.rangeCount ? sel.getRangeAt(0).cloneRange() : saved;
            const images = pasted.filter(f => f.type.startsWith('image/'));
            const others = pasted.filter(f => !f.type.startsWith('image/'));
            if (images.length) addInline(images, here);
            if (others.length) offer(others, false);
            return;
        }
        const html = dt.getData('text/html');
        if (html) {
            e.preventDefault();
            document.execCommand('insertHTML', false, clean(html));
        }
    });

    // Dropping photos on the message puts them in it; any other drop attaches the files.
    let depth = 0;
    const hasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
    const dropKind = (e) => editor.contains(e.target) && [...e.dataTransfer.items]
        .every(i => i.kind === 'file' && i.type.startsWith('image/')) ? 'inline' : 'attach';
    const onEnter = (e) => { if (hasFiles(e)) { depth++; form.dataset.drop = dropKind(e); } };
    const onLeave = (e) => { if (hasFiles(e) && --depth <= 0) { depth = 0; delete form.dataset.drop; } };
    const onOver = (e) => {
        if (!hasFiles(e)) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'copy';
        form.dataset.drop = dropKind(e);
    };
    const onDrop = (e) => {
        if (!hasFiles(e)) return;
        e.preventDefault();
        depth = 0;
        delete form.dataset.drop;
        const list = [...e.dataTransfer.files];
        if (!list.length) return;
        if (editor.contains(e.target) && list.every(f => f.type.startsWith('image/'))) {
            let range = null;
            if (document.caretRangeFromPoint) range = document.caretRangeFromPoint(e.clientX, e.clientY);
            else if (document.caretPositionFromPoint) {
                const p = document.caretPositionFromPoint(e.clientX, e.clientY);
                if (p) { range = document.createRange(); range.setStart(p.offsetNode, p.offset); }
            }
            addInline(list, range && inEditor(range.startContainer) ? range : saved);
        } else {
            offer(list, false);
        }
    };
    form.addEventListener('dragenter', onEnter);
    form.addEventListener('dragleave', onLeave);
    form.addEventListener('dragover', onOver);
    form.addEventListener('drop', onDrop);

    return {
        /** A waiting file's bytes, streamed to .NET once. */
        async take(id) {
            const f = files.get(String(id));
            files.delete(String(id));
            return f ? new Uint8Array(await f.arrayBuffer()) : new Uint8Array(0);
        },

        /** Take an inline image back out (it could not be added). */
        dropImage(cid) {
            for (const img of editor.querySelectorAll('img[data-cid]')) if (img.dataset.cid === cid) img.remove();
            const url = urls.get(cid);
            if (url) URL.revokeObjectURL(url);
            urls.delete(cid);
        },

        /** The message as UTF-8 JSON {html, text, rich, cids}. */
        content() {
            const body = editor.cloneNode(true);
            const cids = [];
            for (const img of body.querySelectorAll('img')) {
                if (img.dataset.cid) {
                    cids.push(img.dataset.cid);
                    img.src = 'cid:' + img.dataset.cid;
                    img.removeAttribute('data-cid');
                    img.style.maxWidth = '100%';
                } else {
                    img.remove();
                }
            }
            const rich = !!body.querySelector(RICH);
            const font = mono ? MONO : SANS;
            const size = mono ? '10pt' : '11pt';
            const html = '<!DOCTYPE html><html><head><meta charset="utf-8"></head>' +
                `<body><div style="font-family:${font};font-size:${size}">${body.innerHTML}</div></body></html>`;
            const json = JSON.stringify({ html, text: plainText(editor), rich, cids });
            return new TextEncoder().encode(json);
        },

        focus(atStart) {
            editor.focus();
            if (!atStart) return;
            const range = document.createRange();
            range.setStart(editor, 0);
            range.collapse(true);
            const sel = document.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
            editor.scrollTop = 0;
        },

        isDirty() { return editor.innerHTML !== initial; },

        dispose() {
            document.removeEventListener('selectionchange', onSelection);
            document.removeEventListener('mousedown', onOutside);
            form.removeEventListener('dragenter', onEnter);
            form.removeEventListener('dragleave', onLeave);
            form.removeEventListener('dragover', onOver);
            form.removeEventListener('drop', onDrop);
            for (const url of urls.values()) URL.revokeObjectURL(url);
            urls.clear();
            files.clear();
        },
    };
}

function extension(type) {
    return { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif', 'image/webp': 'webp' }[type] || 'img';
}

/** Pasted HTML reduced to plain formatting: no scripts, images, classes or remote anything. */
function clean(html) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const walk = (el) => {
        for (const child of [...el.childNodes]) {
            if (child.nodeType === 8) { child.remove(); continue; }
            if (child.nodeType !== 1) continue;
            if (DROP_TAGS.has(child.tagName)) { child.remove(); continue; }
            walk(child);
            if (!KEEP_TAGS.has(child.tagName)) { child.replaceWith(...child.childNodes); continue; }
            const keep = {};
            for (const p of KEEP_STYLES) {
                const v = child.style.getPropertyValue(p);
                if (v && !/url\(|expression/i.test(v)) keep[p] = v;
            }
            const href = child.tagName === 'A' ? child.getAttribute('href') : null;
            const color = child.tagName === 'FONT' ? child.getAttribute('color') : null;
            for (const a of [...child.attributes]) child.removeAttribute(a.name);
            for (const [p, v] of Object.entries(keep)) child.style.setProperty(p, v);
            if (href && /^(https?:|mailto:)/i.test(href.trim())) child.setAttribute('href', href.trim());
            if (color) child.setAttribute('color', color);
        }
    };
    walk(doc.body);
    return doc.body.innerHTML;
}

/** The body as plain text: block structure kept, lists bulleted, quotes marked with '>'. */
function plainText(root) {
    const lines = [];
    let line = '';
    let quote = 0;
    let indent = '';
    let mark = '';     // a list item's bullet, written with the item's first line
    const flush = (always) => {
        if (!line.length && !always && !mark) return;
        lines.push((quote ? '>'.repeat(quote) + ' ' : '') + indent + mark + line);
        if (mark) { indent += ' '.repeat(mark.length); mark = ''; }
        line = '';
    };
    const BLOCK = /^(DIV|P|H[1-6]|LI|BLOCKQUOTE|PRE|TABLE|TR)$/;

    const walk = (n, pre) => {
        if (n.nodeType === 3) {
            line += pre ? n.nodeValue : n.nodeValue.replace(/[\r\n]+/g, ' ');
            return;
        }
        if (n.nodeType !== 1) return;
        const tag = n.tagName;
        if (tag === 'BR') { flush(true); return; }
        if (tag === 'IMG') { line += `[${n.alt || 'image'}]`; return; }
        if (tag === 'HR') { flush(); line = '----------'; flush(); return; }
        const saved = { quote, indent };
        if (tag === 'UL' || tag === 'OL') {
            flush();
            let i = 0;
            for (const li of n.children) {
                if (li.tagName !== 'LI') { walk(li, pre); continue; }
                mark = tag === 'OL' ? `${++i}. ` : '• ';
                indent = saved.indent;
                for (const c of li.childNodes) walk(c, pre);
                flush();
            }
            indent = saved.indent;
            return;
        }
        const block = BLOCK.test(tag);
        if (block && line.length) flush();
        if (tag === 'BLOCKQUOTE') quote++;
        if ((tag === 'TD' || tag === 'TH') && n.previousElementSibling) line += '\t';
        for (const c of n.childNodes) walk(c, pre || tag === 'PRE');
        if (block && line.length) flush();
        quote = saved.quote;
        if (tag !== 'LI') indent = saved.indent;
    };

    for (const c of root.childNodes) walk(c, false);
    flush();
    while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
    return lines.map(l => l.replace(/\u00a0/g, ' ')).join('\n');
}
