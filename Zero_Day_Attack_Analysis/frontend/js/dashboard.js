const state = {
  packets: [],
  sessionId: null,
  filterProto: 'ALL',
  autoScroll: true,
  paused: false,
  selectedRow: null,
  selectedPkt: null,
  activeTab: 'live',
  inspSubTab: 'info',
};

const PACKET_PAGE_SIZE = 250;
let renderedStartIndex = 0;
let aiEnabled = false;
let databaseEnabled = false;
const seenPacketIds = new Set();
const tbody = document.getElementById('packetTbody');
const tableContainer = document.getElementById('tableContainer');
const toastBox = document.getElementById('toastContainer');

function initTabs() {
  document.querySelectorAll('.tab-btn').forEach(button => {
    button.addEventListener('click', () => switchTab(button.dataset.tab));
  });
}

function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll('.tab-btn').forEach(button => {
    button.classList.toggle('active', button.dataset.tab === tabId);
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === `tab-${tabId}`);
  });
}

window.switchInspTab = function switchInspTab(tab) {
  state.inspSubTab = tab;
  document.getElementById('inspTabInfo')?.classList.toggle('active', tab === 'info');
  document.getElementById('inspTabHex')?.classList.toggle('active', tab === 'hex');
  document.getElementById('inspTabLayers')?.classList.toggle('active', tab === 'layers');
  document.getElementById('inspPanelInfo')?.classList.toggle('active', tab === 'info');
  document.getElementById('inspPanelHex')?.classList.toggle('active', tab === 'hex');
  document.getElementById('inspPanelLayers')?.classList.toggle('active', tab === 'layers');
};

function updateStats(stats) {
  syncCaptureSession(stats.session_id);
  animateNum('statTotal', stats.total || 0);
  setText('navPps', stats.pps || 0);
  setText('navBps', `${formatBytes(stats.bps || 0)}/s`);
  setText('trafficPps', `${stats.pps || 0} pps`);
  setText('trafficBps', `${formatBytes(stats.bps || 0)}/s`);
  setText('navRejects', formatNum(stats.validation_rejects || 0));
  document.getElementById('validationChip')?.classList.toggle('has-rejects', (stats.validation_rejects || 0) > 0);

  const elapsed = Number(stats.elapsed || 0);
  const hours = Math.floor(elapsed / 3600);
  const minutes = Math.floor((elapsed % 3600) / 60);
  setText('statElapsed', `Uptime: ${hours ? `${hours}h ` : ''}${minutes ? `${minutes}m ` : ''}${elapsed % 60}s`);

  const lastPacket = stats.last_packet_age_ms;
  setText('lastPacketAge', lastPacket == null ? 'Waiting for traffic' : `${(lastPacket / 1000).toFixed(1)}s ago`);
  updateCaptureStatus(stats);
  updateTrafficChart(stats.pps || 0, stats.bps || 0);
  updateProtoChart(stats.proto_counts || {});
  updateAIStats(stats.ai || {});
  updateDatabaseStatus(stats.database || {});
  if (stats.ai) {
    aiEnabled = Boolean(stats.ai.enabled);
    const aiButton = document.getElementById('aiToggle');
    if (aiButton && !aiButton.disabled) {
      aiButton.textContent = aiEnabled ? 'AI ON' : 'AI OFF';
      aiButton.setAttribute('aria-pressed', String(aiEnabled));
    }
  }
}

function updateDatabaseStatus(database) {
  const button = document.getElementById('databaseToggle');
  if (!button) return;
  databaseEnabled = Boolean(database.enabled);
  const hasError = Boolean(database.error);
  if (!button.disabled) button.textContent = databaseEnabled ? 'DB ON' : (hasError ? 'DB ERROR' : 'DB OFF');
  button.setAttribute('aria-pressed', String(databaseEnabled));
  button.classList.toggle('error', hasError && !databaseEnabled);
  const location = database.path ? ` Database file: ${database.path}` : '';
  button.title = databaseEnabled
    ? `SQLite storage is on. New validated packets are being saved.${location}`
    : `SQLite storage is off. CSV export continues normally.${location}`;
}

function updateCaptureStatus(stats) {
  const badge = document.getElementById('modeBadge');
  const engineTag = document.getElementById('engineTag');
  const restart = document.getElementById('restartCaptureBtn');
  const available = stats.mode === 'LIVE' && stats.engine !== 'NO_CAPTURE';
  if (badge) {
    badge.textContent = available
      ? (stats.real_traffic_seen ? `LIVE: ${shortEngine(stats.engine)}` : `LIVE: ${shortEngine(stats.engine)} • WAITING`)
      : 'CAPTURE UNAVAILABLE';
    badge.className = `mode-badge ${available ? 'live' : 'sim'}`;
  }
  if (engineTag) {
    engineTag.textContent = available
      ? (stats.real_traffic_seen ? `Live ${shortEngine(stats.engine)} capture` : `Waiting for live ${shortEngine(stats.engine)} capture`)
      : 'Live packet capture unavailable';
  }
  if (restart) restart.textContent = stats.capture_active ? 'Restart Capture' : 'Start Capture';
}

function shortEngine(engine) {
  return engine === 'NPCAP_L2' ? 'NPCAP' : engine === 'PCAP_L2' ? 'PCAP' : 'CAPTURE';
}

function addPacket(pkt) {
  if (!pkt || pkt.is_real !== true || !Number.isInteger(Number(pkt.id))) return;
  syncCaptureSession(pkt.session_id);
  const packetId = Number(pkt.id);
  if (seenPacketIds.has(packetId)) return;
  seenPacketIds.add(packetId);
  state.packets.push(pkt);
  if (state.paused || !passesFilter(pkt)) return;

  tbody?.prepend(buildRow(pkt));
  if (tbody?.rows.length > PACKET_PAGE_SIZE) {
    tbody.deleteRow(tbody.rows.length - 1);
    renderedStartIndex = Math.min(renderedStartIndex + 1, state.packets.filter(passesFilter).length);
  }
  if (state.autoScroll && tableContainer) tableContainer.scrollTop = 0;
}

function passesFilter(pkt) {
  return state.filterProto === 'ALL' || pkt.proto === state.filterProto;
}

function buildRow(pkt) {
  const row = document.createElement('tr');
  row.className = 'new-row';
  row.dataset.id = pkt.id;
  const src = String(pkt.src || '—');
  const dst = String(pkt.dst || '—');
  const proto = packetProtocol(pkt.proto);
  row.innerHTML = `
    <td style="color:var(--text-muted)">${escapeHtml(pkt.id)}</td>
    <td style="color:var(--text-muted);font-size:0.65rem">${escapeHtml(pkt.time)}</td>
    <td title="${escapeHtml(src)}">${escapeHtml(shorten(src, 20))}</td>
    <td title="${escapeHtml(dst)}">${escapeHtml(shorten(dst, 20))}</td>
    <td><span class="proto-badge proto-${proto}">${proto}</span></td>
    <td style="color:var(--text-secondary)">${escapeHtml(pkt.size)}B</td>
    <td style="color:var(--cyan);font-size:0.65rem">${escapeHtml(pkt.flags || '—')}</td>
    <td>${pkt.threat_pct == null ? '<span class="ai-na">—</span>' : `<span class="threat-pill ${escapeHtml(pkt.ai_band)}">${escapeHtml(pkt.threat_pct)}%</span>`}</td>
    <td><span class="real-packet-pill real">LIVE</span></td>
  `;
  const aiLabel = document.createElement('td');
  aiLabel.className = 'ai-label';
  aiLabel.textContent = pkt.attack_type && pkt.attack_type !== 'Not analyzed' ? pkt.attack_type : '—';
  row.insertBefore(aiLabel, row.lastElementChild);
  row.addEventListener('click', () => selectPacket(pkt, row));
  row.addEventListener('dblclick', () => fetchAndShowDetail(pkt));
  return row;
}

function selectPacket(pkt, row) {
  state.selectedRow?.classList.remove('selected');
  row?.classList.add('selected');
  state.selectedRow = row || null;
  state.selectedPkt = pkt;
  showInspector(pkt);
  window._socket?.emit('get_packet_detail', { id: pkt.id });
}

function rebuildTable() {
  if (!tbody) return;
  tbody.innerHTML = '';
  const packets = state.packets.filter(passesFilter);
  renderedStartIndex = Math.max(0, packets.length - PACKET_PAGE_SIZE);
  packets.slice(renderedStartIndex).reverse().forEach(packet => tbody.appendChild(buildRow(packet)));
}

function loadOlderPackets() {
  if (!tbody || renderedStartIndex <= 0) return;
  const packets = state.packets.filter(passesFilter);
  const olderStart = Math.max(0, renderedStartIndex - PACKET_PAGE_SIZE);
  const fragment = document.createDocumentFragment();
  packets.slice(olderStart, renderedStartIndex).reverse().forEach(packet => fragment.appendChild(buildRow(packet)));
  tbody.appendChild(fragment);
  renderedStartIndex = olderStart;
}

function renderFlagsPills(flags = '') {
  const definitions = [['S', 'SYN', 'active-syn'], ['A', 'ACK', 'active-ack'], ['P', 'PSH', 'active-psh'], ['F', 'FIN', 'active-fin'], ['R', 'RST', 'active-rst'], ['U', 'URG', 'active-urg']];
  return `<div class="tcp-flags-container">${definitions.map(([key, name, klass]) => `<span class="flag-pill ${flags.includes(key) ? klass : ''}">${name}</span>`).join('')}</div>`;
}

function showInspector(pkt) {
  const body = document.getElementById('inspectorBody');
  const hex = document.getElementById('inspectorHex');
  const layers = document.getElementById('inspectorLayers');
  if (!body) return;
  const fields = [
    ['Packet #', pkt.id, 'cyan'],
    ['Capture time', pkt.time, ''],
    ['Source', pkt.src || pkt.src_ip, 'cyan'],
    ['Destination', pkt.dst || pkt.dst_ip, ''],
    ['Protocol', packetProtocol(pkt.proto), 'cyan'],
    ['Frame size', `${pkt.size || 0} bytes`, ''],
    ['TTL / OS', `${pkt.ttl || 0} (${pkt.os_guess || 'Not available'})`, ''],
    ['TCP flags', renderFlagsPills(pkt.flags), ''],
    ['Flow rate', `${pkt.pkt_rate || 0} packets/s`, ''],
    ['Bandwidth', `${formatBytes(pkt.bandwidth_bps || 0)}/s`, ''],
    ['Capture source', '<span class="real-packet-pill real">LIVE CAPTURED</span>', ''],
  ];
  body.innerHTML = fields.map(([name, value, klass]) => `<div class="inspector-row"><span class="inspector-key">${escapeHtml(name)}</span><span class="inspector-value ${klass}">${value}</span></div>`).join('');
  if (hex) hex.innerHTML = buildHexDump(pkt.raw_hex || '', pkt.raw_ascii || '');
  if (layers) layers.innerHTML = buildLayerStack(pkt.layers || []);
}

function fetchAndShowDetail(pkt) {
  state.selectedPkt = pkt;
  switchTab('detail');
  renderPacketDetailTab(pkt);
  window._socket?.emit('get_packet_detail', { id: pkt.id });
}

function onPacketDetailReceived(pkt) {
  state.selectedPkt = pkt;
  showInspector(pkt);
  if (state.activeTab === 'detail') renderPacketDetailTab(pkt);
}

function renderPacketDetailTab(pkt) {
  const container = document.getElementById('detailContent');
  if (!container) return;
  const proto = packetProtocol(pkt.proto);
  const json = escapeHtml(buildJsonView(pkt));
  const payload = pkt.payload ? `<div style="margin-top:12px"><div style="font-size:0.65rem;font-weight:700;color:var(--text-muted);margin-bottom:4px;text-transform:uppercase">Payload ASCII Preview</div><pre style="background:rgba(0,0,0,0.4);border:1px solid rgba(255,255,255,0.06);padding:6px 8px;border-radius:4px;font-size:0.64rem;color:#a5f3fc;margin:0;max-height:80px;overflow-y:auto;white-space:pre-wrap;word-break:break-all">${escapeHtml(pkt.payload.slice(0, 300))}</pre></div>` : '';
  container.innerHTML = `
    <div style="padding:16px 22px 30px">
      <div class="detail-packet-header-card"><div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:14px"><div><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><h3 style="font-size:1.05rem;color:#fff;margin:0;font-weight:700">Packet #${escapeHtml(pkt.id)}</h3><span class="proto-badge proto-${proto}">${proto}</span><span class="real-packet-pill real">● LIVE CAPTURED</span><span style="font-size:0.75rem;color:var(--text-muted)">${escapeHtml(pkt.time)}</span></div><div style="font-size:0.85rem;color:var(--text-secondary);margin-top:4px;font-family:'JetBrains Mono', monospace"><span style="color:var(--cyan)">${escapeHtml(pkt.src)}</span><span style="color:var(--text-muted);margin:0 4px">➔</span><span style="color:#a5b4fc">${escapeHtml(pkt.dst)}</span></div></div><div style="display:flex;gap:8px"><button class="json-toggle-btn" onclick="copyToClipboard(document.getElementById('jsonRawView').textContent, 'Packet JSON')">Copy JSON</button><button class="json-toggle-btn" id="jsonToggleBtn" onclick="toggleJsonView()">Show JSON</button><button class="json-toggle-btn" onclick="switchTab('live')">← Live Stream</button></div></div></div>
      <pre class="json-view hidden" id="jsonRawView" style="margin:16px 0">${json}</pre>
      <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(320px, 1fr));gap:14px;margin-bottom:16px">
        <div class="panel" style="padding:14px"><h4 style="font-size:0.78rem;color:var(--cyan);margin-bottom:10px">Captured Packet Metadata</h4><div class="field-grid">${field('Packet ID', pkt.id, 'cyan')}${field('Timestamp', pkt.time, '')}${field('Protocol', proto, 'cyan')}${field('Frame size', `${pkt.size || 0} bytes`, '')}${field('TTL', pkt.ttl || 'N/A', '')}${field('OS hint from TTL', pkt.os_guess || 'Not available', '')}${field('Source MAC', pkt.src_mac || 'Not available', '')}${field('Destination MAC', pkt.dst_mac || 'Not available', '')}${field('Flow rate', `${pkt.pkt_rate || 0} packets/s`, '')}${field('Bandwidth', `${formatBytes(pkt.bandwidth_bps || 0)}/s`, '')}</div><div style="margin-top:12px"><div style="font-size:0.65rem;font-weight:700;color:var(--text-muted);margin-bottom:4px;text-transform:uppercase">TCP flags</div>${renderFlagsPills(pkt.flags)}</div>${payload}</div>
        <div class="panel" style="padding:14px"><h4 style="font-size:0.78rem;color:var(--cyan);margin-bottom:10px">Network Layer Stack</h4>${buildLayerStack(pkt.layers || [])}</div>
      </div>
      <div class="panel" style="padding:14px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><h4 style="font-size:0.78rem;color:var(--cyan);margin:0">Raw Hex and ASCII Data</h4><button class="json-toggle-btn" onclick="copyToClipboard('${escapeHtml(pkt.raw_hex || '')}', 'Raw hex')">Copy Raw Hex</button></div><div class="hex-dump-enhanced" style="max-height:260px;overflow-y:auto">${buildHexDump(pkt.raw_hex || '', pkt.raw_ascii || '')}</div></div>
    </div>`;
}

function field(label, value, klass = '') {
  return `<div class="inspector-row"><span class="inspector-key">${escapeHtml(label)}</span><span class="inspector-value ${klass}">${escapeHtml(value)}</span></div>`;
}

function buildHexDump(hexString, asciiString) {
  if (!hexString) return '<em style="color:var(--text-muted);font-size:0.62rem">No raw byte data available for this packet</em>';
  const bytes = hexString.split(' ').filter(Boolean);
  const chars = asciiString ? asciiString.split('') : [];
  let html = '';
  for (let index = 0; index < bytes.length; index += 16) {
    const hex = bytes.slice(index, index + 16);
    const left = hex.slice(0, 8).map(byte => `<span class="hex-byte">${escapeHtml(byte)}</span>`).join(' ');
    const right = hex.slice(8, 16).map(byte => `<span class="hex-byte">${escapeHtml(byte)}</span>`).join(' ');
    html += `<div class="hex-line"><span class="hex-addr">${index.toString(16).padStart(4, '0').toUpperCase()}</span><div class="hex-bytes-group"><span>${left}</span><span style="color:rgba(255,255,255,0.2)">|</span><span>${right}</span></div><span class="hex-ascii-text">${escapeHtml(chars.slice(index, index + 16).join('').padEnd(16, ' '))}</span></div>`;
  }
  return html;
}

function buildLayerStack(layers) {
  if (!layers?.length) return '<p style="color:var(--text-muted);font-size:0.62rem">No layer stack data</p>';
  return `<div class="layers-compact">${layers.map((layer, index) => {
    const fields = Object.entries(layer.fields || {}).map(([key, value]) => `<div class="layer-field"><span class="layer-field-key">${escapeHtml(key)}:</span><span class="layer-field-val">${escapeHtml(typeof value === 'object' ? JSON.stringify(value) : String(value))}</span></div>`).join('');
    return `<div class="layer-card" id="layer-${index}"><div class="layer-card-header" onclick="toggleLayer(${index})"><span class="layer-name-pill">${escapeHtml(layer.name)}</span><span class="layer-chevron">▾</span></div><div class="layer-fields">${fields || '<span style="color:var(--text-muted);font-size:0.58rem">No fields</span>'}</div></div>`;
  }).join('')}</div>`;
}

window.toggleLayer = index => document.getElementById(`layer-${index}`)?.classList.toggle('collapsed');

function buildJsonView(pkt) {
  const copy = { ...pkt };
  delete copy.raw_hex;
  delete copy.raw_ascii;
  delete copy.layers;
  return JSON.stringify(copy, null, 2);
}

window.toggleJsonView = function toggleJsonView() {
  const view = document.getElementById('jsonRawView');
  const button = document.getElementById('jsonToggleBtn');
  if (!view) return;
  const hidden = view.classList.toggle('hidden');
  if (button) button.textContent = hidden ? 'Show JSON' : 'Hide JSON';
};

window.copyToClipboard = function copyToClipboard(value, label = 'Copied') {
  const text = String(value || '');
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => showToast(label, 'Copied to clipboard')).catch(() => fallbackCopy(text, label));
  } else {
    fallbackCopy(text, label);
  }
};

function fallbackCopy(value, label) {
  const textarea = document.createElement('textarea');
  textarea.value = value;
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  textarea.remove();
  showToast(label, 'Copied to clipboard');
}

window.openCaptureModal = function openCaptureModal() {
  document.getElementById('captureModal')?.classList.add('open');
  fetch('/api/capture/status').then(response => response.json()).then(result => {
    const status = result.status || {};
    const diagnostics = result.diagnostics || {};
    setText('diagEngine', diagnostics.engine_label || status.engine || 'Unavailable');
    setText('diagMode', status.mode || 'LIVE');
    setText('diagAdmin', diagnostics.is_admin ? 'Yes (Administrator)' : 'No (Standard User)');
    setText('diagIp', diagnostics.default_ip || 'Auto');
    setText('diagNpcap', diagnostics.npcap_service || 'Not installed');
    setText('diagDll', diagnostics.wpcap_dll ? 'Installed' : 'Missing');
  }).catch(() => showToast('Diagnostics unavailable', 'The capture service could not be reached', true));
  fetchValidationStats();
};

window.closeCaptureModal = () => document.getElementById('captureModal')?.classList.remove('open');

window.restartCapture = function restartCapture() {
  fetch('/api/capture/restart', { method: 'POST' }).then(async response => {
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Unable to restart capture');
    return data;
  }).then(data => {
    showToast('Capture restarted', `Live ${shortEngine(data.capture?.engine)} capture is starting`);
    closeCaptureModal();
  }).catch(error => showToast('Capture restart failed', error.message, true));
};

function fetchValidationStats() {
  fetch('/api/validation/stats').then(response => response.json()).then(stats => {
    setText('diagValReceived', formatNum(stats.total_received || 0));
    setText('diagValAccepted', formatNum(stats.total_accepted || 0));
    setText('diagValRejected', formatNum(stats.total_rejected || 0));
    setText('diagValLastReject', stats.last_reject_reason || 'None');
  }).catch(() => {});
}

window.purgeInvalidPackets = function purgeInvalidPackets() {
  fetch('/api/packets/purge_invalid', { method: 'POST' }).then(response => response.json()).then(data => {
    showToast('Validation complete', `${data.removed || 0} invalid records removed`);
    fetchValidationStats();
  }).catch(error => showToast('Purge failed', error.message, true));
};

window.resetValidationStats = function resetValidationStats() {
  fetch('/api/validation/reset', { method: 'POST' }).then(response => response.json()).then(() => {
    showToast('Validation counters reset');
    fetchValidationStats();
  }).catch(error => showToast('Reset failed', error.message, true));
};

function setText(id, value) {
  const element = document.getElementById(id);
  if (element && element.textContent !== String(value)) element.textContent = value;
}

function animateNum(id, value) {
  const element = document.getElementById(id);
  if (!element) return;
  element.textContent = formatNum(value);
  element.classList.remove('num-update');
  void element.offsetWidth;
  element.classList.add('num-update');
}

function formatNum(value) {
  return value >= 1000 ? `${(value / 1000).toFixed(1)}k` : String(value || 0);
}

function formatBytes(bytes) {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes || 0} B`;
}

function packetProtocol(value) {
  return ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP', 'HTTP', 'UNKNOWN'].includes(value) ? value : 'UNKNOWN';
}

function shorten(value, limit) {
  return value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[char]);
}

function showToast(title, description = '', isError = false) {
  if (!toastBox) return;
  const toast = document.createElement('div');
  toast.className = `toast ${isError ? 'error' : ''}`;
  toast.innerHTML = `<div class="toast-title">${escapeHtml(title)}</div>${description ? `<div class="toast-desc">${escapeHtml(description)}</div>` : ''}`;
  toastBox.appendChild(toast);
  setTimeout(() => toast.remove(), 3500);
}

function updateAIStats(ai) {
  setText('aiAnalyzed', formatNum(ai.analyzed || 0));
  setText('aiSafe', formatNum(ai.safe || 0));
  setText('aiThreat', formatNum(ai.threat || 0));
  const total = (ai.safe || 0) + (ai.threat || 0);
  const percent = total ? Math.round((ai.safe || 0) * 100 / total) : 0;
  const bar = document.getElementById('aiSafeBar');
  if (bar) bar.style.width = `${percent}%`;
  setText('aiPercent', ai.enabled ? `${percent}% safe packet observations` : 'Enable AI to analyze captured flows');
  setText('aiStatus', ai.enabled ? 'ON' : 'OFF');
}

async function toggleAI() {
  const button = document.getElementById('aiToggle');
  const enabled = !aiEnabled;
  button.disabled = true;
  button.textContent = enabled ? 'TRAINING…' : 'AI OFF';
  try {
    const response = await fetch('/api/ai/toggle', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({enabled})});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'AI model could not be enabled');
    aiEnabled = result.enabled;
    button.textContent = aiEnabled ? 'AI ON' : 'AI OFF';
    button.setAttribute('aria-pressed', String(aiEnabled));
    document.getElementById('aiStatus').textContent = aiEnabled ? 'ON' : 'OFF';
    const f1 = result.quality?.holdout_macro_f1_pct;
    const qualityNote = f1 == null ? '' : ' Random held-out dataset macro-F1: ' + f1 + '%.';
    showToast(aiEnabled ? 'AI analysis enabled' : 'AI analysis disabled',
      aiEnabled ? 'Dataset labels are BENIGN and DDoS. Live flow scores are estimates.' + qualityNote : 'Live capture continues without AI scoring');
  } catch (error) {
    button.textContent = 'AI OFF';
    showToast('AI model unavailable', error.message, true);
  } finally { button.disabled = false; }
}

async function toggleDatabase() {
  const button = document.getElementById('databaseToggle');
  if (!button) return;
  const enabled = !databaseEnabled;
  button.disabled = true;
  button.textContent = enabled ? 'CONNECTING…' : 'DB OFF';
  try {
    const response = await fetch('/api/database/toggle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({enabled}),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Could not update database storage');
    updateDatabaseStatus(result.database || {});
    const path = result.database?.path || 'the local SQLite database';
    showToast(enabled ? 'Database storage enabled' : 'Database storage disabled',
      enabled ? `New live packets are now saved in ${path}` : 'New packets will not be stored. CSV export still includes this live session.');
  } catch (error) {
    button.classList.add('error');
    button.textContent = 'DB ERROR';
    showToast('Database connection failed', error.message, true);
  } finally {
    button.disabled = false;
  }
}

function syncCaptureSession(sessionId) {
  if (!sessionId) return;
  if (state.sessionId && state.sessionId !== sessionId) {
    state.packets = [];
    seenPacketIds.clear();
    renderedStartIndex = 0;
    state.selectedPkt = null;
    state.selectedRow = null;
    if (tbody) tbody.innerHTML = '';
    const inspector = document.getElementById('inspectorBody');
    if (inspector) inspector.innerHTML = '<p class="inspector-hint">Waiting for a live packet from this capture session.</p>';
    if (state.activeTab === 'detail') switchTab('live');
    showToast('Capture session restarted', 'Packet history now contains only captures from the new session');
  }
  state.sessionId = sessionId;
}

function loadHistory(packets) {
  const sessionPacket = packets.find(packet => packet?.session_id);
  if (sessionPacket) syncCaptureSession(sessionPacket.session_id);
  packets.forEach(packet => {
    if (packet?.is_real !== true || !Number.isInteger(Number(packet.id))) return;
    const id = Number(packet.id);
    if (seenPacketIds.has(id)) return;
    seenPacketIds.add(id);
    state.packets.push(packet);
  });
  state.packets.sort((a, b) => Number(a.id) - Number(b.id));
  rebuildTable();
}

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initCharts();
  tableContainer?.addEventListener('scroll', () => {
    if (tableContainer.scrollTop + tableContainer.clientHeight >= tableContainer.scrollHeight - 24) loadOlderPackets();
  });
  document.getElementById('filterProto')?.addEventListener('change', event => {
    state.filterProto = event.target.value;
    rebuildTable();
  });
  document.getElementById('autoScroll')?.addEventListener('change', event => { state.autoScroll = event.target.checked; });
  document.getElementById('restartCaptureBtn')?.addEventListener('click', restartCapture);
  document.getElementById('aiToggle')?.addEventListener('click', toggleAI);
  document.getElementById('databaseToggle')?.addEventListener('click', toggleDatabase);
  document.getElementById('modeBadge')?.addEventListener('click', openCaptureModal);
  document.getElementById('openDetailTabBtn')?.addEventListener('click', () => state.selectedPkt ? fetchAndShowDetail(state.selectedPkt) : switchTab('detail'));
  document.getElementById('clearBtn')?.addEventListener('click', () => { state.packets = []; seenPacketIds.clear(); renderedStartIndex = 0; if (tbody) tbody.innerHTML = ''; showToast('Packet display cleared'); });
  document.getElementById('toggleCapture')?.addEventListener('click', () => {
    state.paused = !state.paused;
    const icon = document.getElementById('captureIcon');
    if (icon) icon.innerHTML = state.paused ? '<polygon points="5 3 19 12 5 21 5 3"/>' : '<rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/>';
    if (!state.paused) rebuildTable();
    showToast(state.paused ? 'Display paused' : 'Display resumed', 'Live capture continues in the background');
  });
});
