// ─── API base URL ─────────────────────────────────────────────────────────────
const BASE = process.env.REACT_APP_API_URL || 'http://localhost:3001';
const WS_BASE = BASE.replace(/^http/, 'ws');

// ─── Token storage ────────────────────────────────────────────────────────────
export const getToken = () => localStorage.getItem('csw_token');
export const setToken = t => t ? localStorage.setItem('csw_token', t) : localStorage.removeItem('csw_token');

// ─── HTTP helper ──────────────────────────────────────────────────────────────
async function req(method, path, body, token) {
  const tok = token !== undefined ? token : getToken();
  const headers = { 'Content-Type': 'application/json' };
  if (tok) headers['Authorization'] = `Bearer ${tok}`;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
export const api = {
  auth: {
    register: (name, email, password, avatar) =>
      req('POST', '/api/auth/register', { name, email, password, avatar }),
    login: (email, password) =>
      req('POST', '/api/auth/login', { email, password }),
    me: () => req('GET', '/api/auth/me'),
  },
  users: {
    search: q => req('GET', `/api/users/search?q=${encodeURIComponent(q)}`),
    all: () => req('GET', '/api/users/all'),
    updateMe: patch => req('PATCH', '/api/users/me', patch),
    linkCouple: partnerId => req('POST', '/api/users/couple', { partnerId }),
    unlinkCouple: () => req('DELETE', '/api/users/couple'),
  },
  groups: {
    list: () => req('GET', '/api/groups'),
    create: data => req('POST', '/api/groups', data),
    update: (id, data) => req('PATCH', `/api/groups/${id}`, data),
    delete: id => req('DELETE', `/api/groups/${id}`),
  },
  expenses: {
    list: groupId => req('GET', `/api/expenses${groupId ? `?groupId=${groupId}` : ''}`),
    create: data => req('POST', '/api/expenses', data),
    update: (id, data) => req('PATCH', `/api/expenses/${id}`, data),
    delete: id => req('DELETE', `/api/expenses/${id}`),
    settleBatch: (debts, currency) => req('POST', '/api/expenses/settle-batch', { debts, currency }),
  },
  notifications: {
    list: () => req('GET', '/api/notifications'),
    readAll: () => req('POST', '/api/notifications/read-all'),
  },
  jointAccounts: {
    mine: () => req('GET', '/api/joint-accounts/mine'),
    forGroup: (groupId) => req('GET', `/api/joint-accounts/group/${groupId}`),
    create: () => req('POST', '/api/joint-accounts'),
    delete: () => req('DELETE', '/api/joint-accounts/mine'),
  },
};

// ─── WebSocket manager ────────────────────────────────────────────────────────
class WSManager {
  constructor() {
    this.ws = null;
    this.listeners = {};
    this.reconnectTimer = null;
    this.token = null;
    this.connected = false;
    this.intentionalClose = false;
  }

  connect(token) {
    this.token = token;
    this.intentionalClose = false;
    this._connect();
  }

  _connect() {
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close();
    }
    const ws = new window.WebSocket(`${WS_BASE}/ws`);
    this.ws = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'auth', token: this.token }));
    };

    ws.onmessage = evt => {
      try {
        const { event, data } = JSON.parse(evt.data);
        if (event === 'auth_ok') {
          this.connected = true;
          this._emit('connected', {});
        } else if (event === 'pong') {
          // heartbeat ok
        } else {
          this._emit(event, data);
        }
      } catch {}
    };

    ws.onclose = () => {
      this.connected = false;
      this._emit('disconnected', {});
      if (!this.intentionalClose) {
        this.reconnectTimer = setTimeout(() => this._connect(), 3000);
      }
    };

    ws.onerror = () => {};

    // Heartbeat
    this._heartbeatInterval = setInterval(() => {
      if (ws.readyState === window.WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, 25000);
  }

  disconnect() {
    this.intentionalClose = true;
    clearTimeout(this.reconnectTimer);
    clearInterval(this._heartbeatInterval);
    if (this.ws) this.ws.close();
    this.ws = null;
    this.connected = false;
    this.token = null;
  }

  on(event, fn) {
    if (!this.listeners[event]) this.listeners[event] = new Set();
    this.listeners[event].add(fn);
    return () => this.listeners[event]?.delete(fn);
  }

  _emit(event, data) {
    this.listeners[event]?.forEach(fn => fn(data));
    this.listeners['*']?.forEach(fn => fn(event, data));
  }
}

export const wsManager = new WSManager();
