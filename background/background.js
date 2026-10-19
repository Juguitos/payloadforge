// ============================================================================
// PayloadForge — background (context menus + injection bridge)
// `lib/payloads.js` is loaded first (see manifest), exposing PAYLOADS etc.
// ============================================================================

const api = typeof browser !== 'undefined' ? browser : chrome;

// ── Injection function (serialized and run in the page) ──────────────────────
// Self-contained: cannot reference anything outside its own body.
function pfInject(text) {
  const el = document.activeElement;
  const setNative = (node, value) => {
    const proto = node instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
    setter.call(node, value);
    node.dispatchEvent(new Event('input', { bubbles: true }));
    node.dispatchEvent(new Event('change', { bubbles: true }));
  };

  if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
    const start = el.selectionStart ?? el.value.length;
    const end = el.selectionEnd ?? el.value.length;
    const next = el.value.slice(0, start) + text + el.value.slice(end);
    setNative(el, next);
    const caret = start + text.length;
    try { el.setSelectionRange(caret, caret); } catch (_) {}
    return { ok: true, where: el.tagName.toLowerCase() };
  }

  if (el && el.isContentEditable) {
    document.execCommand('insertText', false, text);
    return { ok: true, where: 'contenteditable' };
  }

  return { ok: false, reason: 'no-editable-field' };
}

async function injectIntoTab(tabId, text) {
  if (!text) return { ok: false, reason: 'empty' };
  try {
    const [res] = await api.scripting.executeScript({
      target: { tabId },
      func: pfInject,
      args: [text],
    });
    return res && res.result ? res.result : { ok: false, reason: 'no-result' };
  } catch (e) {
    return { ok: false, reason: String(e && e.message || e) };
  }
}

// ── Placeholder values from storage ──────────────────────────────────────────
async function getPlaceholders() {
  try {
    const { pf_placeholders } = await api.storage.local.get('pf_placeholders');
    return pf_placeholders || {};
  } catch (_) { return {}; }
}

// ── Context menu tree ────────────────────────────────────────────────────────
const MENU_ROOT = 'pf-root';
const MENU_LAST = 'pf-last';

function buildMenus() {
  api.contextMenus.removeAll(() => {
    api.contextMenus.create({
      id: MENU_ROOT,
      title: 'PayloadForge — insert payload',
      contexts: ['editable'],
    });

    api.contextMenus.create({
      id: MENU_LAST,
      parentId: MENU_ROOT,
      title: 'Insert last generated payload',
      contexts: ['editable'],
    });
    api.contextMenus.create({
      id: 'pf-sep',
      parentId: MENU_ROOT,
      type: 'separator',
      contexts: ['editable'],
    });

    for (const cat of Object.keys(PAYLOADS)) {
      const catId = `pf-cat::${cat}`;
      api.contextMenus.create({
        id: catId,
        parentId: MENU_ROOT,
        title: cat,
        contexts: ['editable'],
      });
      for (const p of PAYLOADS[cat]) {
        api.contextMenus.create({
          id: `pf-pl::${p.id}`,
          parentId: catId,
          title: p.name,
          contexts: ['editable'],
        });
      }
    }
  });
}

function findPayloadById(id) {
  for (const list of Object.values(PAYLOADS)) {
    for (const p of list) if (p.id === id) return p;
  }
  return null;
}

api.runtime.onInstalled.addListener(buildMenus);
api.runtime.onStartup && api.runtime.onStartup.addListener(buildMenus);

// ── Context menu click ───────────────────────────────────────────────────────
api.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab || !tab.id) return;
  const vals = await getPlaceholders();
  let text = null;

  if (info.menuItemId === MENU_LAST) {
    const { pf_last } = await api.storage.local.get('pf_last');
    text = pf_last || null;
  } else if (String(info.menuItemId).startsWith('pf-pl::')) {
    const id = String(info.menuItemId).slice('pf-pl::'.length);
    const p = findPayloadById(id);
    text = p ? p.payload : null;
  }

  if (text != null) {
    text = applyPlaceholders(text, vals);
    await api.storage.local.set({ pf_last: text });
    await injectIntoTab(tab.id, text);
  }
});

// ── Messages from the popup ──────────────────────────────────────────────────
api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== 'inject') return;
  (async () => {
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];
    if (!tab || !tab.id) { sendResponse({ ok: false, reason: 'no-tab' }); return; }
    await api.storage.local.set({ pf_last: msg.text });
    const res = await injectIntoTab(tab.id, msg.text);
    sendResponse(res);
  })();
  return true; // keep the channel open for async sendResponse
});

// ── Keyboard command: inject last payload ────────────────────────────────────
api.commands && api.commands.onCommand.addListener(async (cmd) => {
  if (cmd !== 'inject-last') return;
  const tabs = await api.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab || !tab.id) return;
  const { pf_last } = await api.storage.local.get('pf_last');
  if (pf_last) await injectIntoTab(tab.id, pf_last);
});
