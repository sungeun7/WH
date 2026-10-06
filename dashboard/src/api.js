const json = async (res) => {
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json();
};

export const api = {
  stats: () => fetch("/api/v1/stats").then(json),
  health: () => fetch("/api/v1/health").then(json),
  alerts: () => fetch("/api/v1/alerts?status=open").then(json),
  confirmAlert: (id) => fetch(`/api/v1/alerts/${id}/confirm`, { method: "POST" }).then(json),
  resolveAlert: (id) => fetch(`/api/v1/alerts/${id}/resolve`, { method: "POST" }).then(json),
  resolveAllAlerts: () => fetch("/api/v1/alerts/resolve-all", { method: "POST" }).then(json),
  dismissAlert: (id) => fetch(`/api/v1/alerts/${id}/resolve`, { method: "POST" }).then(json),
  blockAlert: (id) => fetch(`/api/v1/alerts/${id}/block`, { method: "POST" }).then(json),
  surface: () => fetch("/api/v1/surface").then(json),
  mitigate: (id) => fetch(`/api/v1/surface/${id}/mitigate`, { method: "POST" }).then(json),
  patterns: () => fetch("/api/v1/patterns").then(json),
  drafts: () => fetch("/api/v1/patterns/drafts").then(json),
  approveDraft: (id) => fetch(`/api/v1/patterns/drafts/${id}/approve`, { method: "POST" }).then(json),
  rejectDraft: (id) => fetch(`/api/v1/patterns/drafts/${id}/reject`, { method: "POST" }).then(json),
  timeline: () => fetch("/api/v1/timeline").then(json),
  deleteTimeline: (id) => fetch(`/api/v1/timeline/${id}`, { method: "DELETE" }).then(json),
  clearTimeline: () => fetch("/api/v1/timeline", { method: "DELETE" }).then(json),
  blocks: () => fetch("/api/v1/blocks").then(json),
  removeBlock: (id) => fetch(`/api/v1/blocks/${id}`, { method: "DELETE" }).then(json),
  actions: () => fetch("/api/v1/actions").then(json),
  executeAction: (id) => fetch(`/api/v1/actions/${id}/execute`, { method: "POST" }).then(json),
  cancelAction: (id) => fetch(`/api/v1/actions/${id}`, { method: "DELETE" }).then(json),
  settings: () => fetch("/api/v1/settings").then(json),
  saveSettings: (body) =>
    fetch("/api/v1/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then(json),
  synthetic: (kind, extra = {}) =>
    fetch("/api/v1/events/synthetic", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind, ...extra }),
    }).then(json),
};

export function connectWs(onMessage, onOpen, onClose) {
  let closed = false;
  let ws;
  const connect = () => {
    if (closed) return;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/api/v1/ws`);
    ws.onopen = () => onOpen && onOpen();
    ws.onclose = () => {
      if (onClose) onClose();
      if (!closed) setTimeout(connect, 2000);
    };
    ws.onmessage = (ev) => {
      try {
        onMessage(JSON.parse(ev.data));
      } catch {
        /* ignore */
      }
    };
  };
  connect();
  return {
    close() {
      closed = true;
      if (ws) ws.close();
    },
  };
}
