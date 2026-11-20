const BACKEND_URL = window.location.origin;
let socket;

function connectSocket() {
  socket = io(BACKEND_URL, {
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionAttempts: Infinity,
  });
  window._socket = socket;

  socket.on('connect', () => setStatus('Connected — Live', true));
  socket.on('disconnect', () => {
    setStatus('Disconnected — Reconnecting…', false);
    scheduleReconnectNotice();
  });
  socket.on('connect_error', () => setStatus('Connection error', false));
  socket.on('packet', packet => addPacket(packet));
  socket.on('stats', stats => updateStats(stats));
  socket.on('history', packets => { if (Array.isArray(packets)) loadHistory(packets); });
  socket.on('packet_detail', packet => onPacketDetailReceived(packet));
}

function setStatus(message, healthy) {
  const pill = document.getElementById('statusPill');
  const dot = document.getElementById('pulseDot');
  const text = document.getElementById('statusText');
  if (text) text.textContent = message;
  pill?.classList.toggle('error', !healthy);
  dot?.classList.toggle('red', !healthy);
}

let reconnectTimer;
function scheduleReconnectNotice() {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(() => showToast('Backend offline', 'Start backend/app.py to resume live capture', true), 4000);
}

document.addEventListener('DOMContentLoaded', connectSocket);
