Chart.defaults.color = '#8892b0';
Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
Chart.defaults.animation.duration = 300;

const COLORS = { cyan: '#00d4ff', purple: '#a855f7', green: '#10b981', yellow: '#f59e0b', red: '#ef4444' };
const TOOLTIP = { backgroundColor: 'rgba(8,11,24,0.96)', borderColor: 'rgba(0,212,255,0.3)', borderWidth: 1, titleColor: '#e2e8f8', bodyColor: '#94a3c8', padding: 10 };
let trafficChart;
let protoChart;
const WINDOW = 60;
const packetHistory = new Array(WINDOW).fill(0);
const byteHistory = new Array(WINDOW).fill(0);

function initTrafficChart() {
  const canvas = document.getElementById('trafficChart');
  if (!canvas) return;
  const context = canvas.getContext('2d');
  const ppsGradient = context.createLinearGradient(0, 0, 0, 80);
  ppsGradient.addColorStop(0, 'rgba(0,212,255,0.35)');
  ppsGradient.addColorStop(1, 'rgba(0,212,255,0)');
  const bpsGradient = context.createLinearGradient(0, 0, 0, 80);
  bpsGradient.addColorStop(0, 'rgba(168,85,247,0.25)');
  bpsGradient.addColorStop(1, 'rgba(168,85,247,0)');
  trafficChart = new Chart(context, {
    type: 'line',
    data: {
      labels: Array.from({ length: WINDOW }, (_, index) => index === WINDOW - 1 ? 'now' : ''),
      datasets: [
        { label: 'Packets/s', data: [...packetHistory], borderColor: COLORS.cyan, backgroundColor: ppsGradient, borderWidth: 2, pointRadius: 0, tension: 0.45, fill: true, yAxisID: 'pps' },
        { label: 'Bytes/s', data: [...byteHistory], borderColor: COLORS.purple, backgroundColor: bpsGradient, borderWidth: 1.5, pointRadius: 0, tension: 0.45, fill: true, borderDash: [4, 2], yAxisID: 'bps' },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: 'index', intersect: false },
      scales: {
        x: { display: false, grid: { display: false } },
        pps: { type: 'linear', position: 'left', beginAtZero: true, grid: { color: 'rgba(0,212,255,0.05)', drawBorder: false }, ticks: { color: COLORS.cyan, maxTicksLimit: 3, font: { size: 9 } } },
        bps: { type: 'linear', position: 'right', beginAtZero: true, grid: { display: false }, ticks: { color: COLORS.purple, maxTicksLimit: 3, font: { size: 9 }, callback: value => value >= 1000 ? `${(value / 1000).toFixed(0)}K` : value } },
      },
      plugins: { legend: { display: false }, tooltip: { ...TOOLTIP, callbacks: { label: item => item.datasetIndex === 0 ? ` Packets/s: ${item.raw}` : ` Bytes/s: ${formatChartBytes(item.raw)}` } } },
    },
  });
}

function updateTrafficChart(pps, bps) {
  if (!trafficChart) return;
  packetHistory.shift(); packetHistory.push(pps);
  byteHistory.shift(); byteHistory.push(bps);
  trafficChart.data.datasets[0].data = [...packetHistory];
  trafficChart.data.datasets[1].data = [...byteHistory];
  trafficChart.update('none');
}

function initProtoChart() {
  const canvas = document.getElementById('protoChart');
  if (!canvas) return;
  protoChart = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: { labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP'], datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: [COLORS.cyan, COLORS.purple, COLORS.yellow, COLORS.green, COLORS.red].map(color => `${color}99`), borderColor: [COLORS.cyan, COLORS.purple, COLORS.yellow, COLORS.green, COLORS.red], borderWidth: 1, borderRadius: 4, borderSkipped: false }] },
    options: { responsive: true, maintainAspectRatio: false, scales: { x: { grid: { display: false }, ticks: { font: { size: 11 } } }, y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)', drawBorder: false }, ticks: { maxTicksLimit: 4, font: { size: 10 } } } }, plugins: { legend: { display: false }, tooltip: TOOLTIP } },
  });
}

function updateProtoChart(counts) {
  if (!protoChart) return;
  protoChart.data.datasets[0].data = ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP'].map(protocol => counts[protocol] || 0);
  protoChart.update('none');
}

function initCharts() {
  initTrafficChart();
  initProtoChart();
}

function formatChartBytes(bytes) {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB/s`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB/s`;
  return `${bytes || 0} B/s`;
}
