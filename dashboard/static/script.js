/* ==========================================
   CYBERSENTINEL SOC DASHBOARD — SCRIPT.JS
   ========================================== */

// ─── State ──────────────────────────────────
const MAX_LINE_POINTS   = 30;
const MAX_TABLE_ROWS    = 60;
const REFRESH_INTERVAL  = 2000;

let allLogs      = [];
let currentFilter = 'all';
let rowIndex      = 0;

let attackHistory  = [];
let normalHistory  = [];
let trafficHistory = [];
let timeLabels     = [];

let spark1Data = [], spark2Data = [], spark3Data = [], spark4Data = [];

let lineChart, pieChart, barChart;
let spark1, spark2, spark3, spark4;

let prevAttack = 0, prevNormal = 0, prevTraffic = 0;

// ─── Mock data generator (simulates /api/data) ──
function mockApiData() {
  const ipPool = [
    '192.168.10.20','10.0.0.45','172.16.5.88','203.45.67.12','185.220.101.5',
    '91.108.4.200','45.33.22.11','198.51.100.9','104.21.67.89','66.254.114.4',
    '195.54.160.100','185.107.82.44','94.102.61.55','77.88.8.8','1.1.1.1',
    '8.8.8.8','23.227.38.65','104.16.85.20','172.217.12.46','31.13.72.36'
  ];
  const batchSize = Math.floor(Math.random() * 5) + 1;
  const logs = [];
  let attackCount = 0, normalCount = 0;

  for (let i = 0; i < batchSize; i++) {
    const ip     = ipPool[Math.floor(Math.random() * ipPool.length)];
    const attack = Math.random() < 0.35;
    const rate   = attack
      ? +(Math.random() * 450 + 50).toFixed(1)
      : +(Math.random() * 40 + 0.5).toFixed(1);
    const ts = Math.floor(Date.now() / 1000);
    logs.push({ ip, rate, attack, timestamp: ts });
    if (attack) attackCount++; else normalCount++;
  }
  return { logs, attack_count: attackCount, normal_count: normalCount };
}

// Attempt real API, fallback to mock
async function fetchData() {
  try {
    const res = await fetch('/api/data');
    if (!res.ok) throw new Error('non-200');
    return await res.json();
  } catch {
    return mockApiData();
  }
}

// ─── Clock ──────────────────────────────────
function updateClock() {
  const el = document.getElementById('clock');
  if (!el) return;  // 🔥 prevents crash

  const now  = new Date();
  const pad  = n => String(n).padStart(2, '0');
  el.textContent =
    `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}
setInterval(updateClock, 1000);
updateClock();

// ─── Chart defaults ─────────────────────────
Chart.defaults.color          = '#5a7a9a';
Chart.defaults.borderColor    = '#0d2847';
Chart.defaults.font.family    = "'Share Tech Mono', monospace";
Chart.defaults.font.size      = 10;

// ─── Sparkline factory ──────────────────────
function makeSparkline(id, color) {
  const ctx = document.getElementById(id).getContext('2d');
  return new Chart(ctx, {
    type: 'line',
    data: {
      labels: Array(12).fill(''),
      datasets: [{
        data: Array(12).fill(0),
        borderColor: color,
        borderWidth: 1.5,
        pointRadius: 0,
        tension: 0.4,
        fill: true,
        backgroundColor: hexToRgba(color, 0.1),
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 400 },
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: {
        x: { display: false },
        y: { display: false, beginAtZero: true }
      }
    }
  });
}
function hexToRgba(hex, alpha) {
  const r = parseInt(hex.slice(1,3),16);
  const g = parseInt(hex.slice(3,5),16);
  const b = parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${alpha})`;
}
function pushSparkline(chart, val) {
  chart.data.datasets[0].data.push(val);
  if (chart.data.datasets[0].data.length > 12)
    chart.data.datasets[0].data.shift();
  chart.update('none');
}

// ─── Line chart ─────────────────────────────
function initLineChart() {
  const ctx = document.getElementById('lineChart').getContext('2d');
  const blueGrad = ctx.createLinearGradient(0, 0, 0, 200);
  blueGrad.addColorStop(0, 'rgba(0,170,255,0.25)');
  blueGrad.addColorStop(1, 'rgba(0,170,255,0)');
  const redGrad = ctx.createLinearGradient(0, 0, 0, 200);
  redGrad.addColorStop(0, 'rgba(255,34,68,0.2)');
  redGrad.addColorStop(1, 'rgba(255,34,68,0)');

  lineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Total Traffic',
          data: [],
          borderColor: '#00aaff',
          backgroundColor: blueGrad,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: '#00aaff',
          pointBorderColor: '#020b18',
          pointBorderWidth: 1,
          tension: 0.4,
          fill: true,
        },
        {
          label: 'Attacks',
          data: [],
          borderColor: '#ff2244',
          backgroundColor: redGrad,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: '#ff2244',
          pointBorderColor: '#020b18',
          pointBorderWidth: 1,
          tension: 0.4,
          fill: true,
        }
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 600 },
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          display: true,
          position: 'top',
          align: 'end',
          labels: { boxWidth: 10, padding: 16, color: '#5a7a9a', font: { size: 10 } }
        },
        tooltip: {
          backgroundColor: '#071428',
          borderColor: '#0d2847',
          borderWidth: 1,
          titleColor: '#00aaff',
          bodyColor: '#c8e0f8',
          padding: 10,
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(13,40,71,0.7)', drawTicks: false },
          ticks: { maxTicksLimit: 8, color: '#5a7a9a', maxRotation: 0 }
        },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(13,40,71,0.7)', drawTicks: false },
          ticks: { color: '#5a7a9a' }
        }
      }
    }
  });
}

// ─── Pie chart ──────────────────────────────
function initPieChart() {
  const ctx = document.getElementById('pieChart').getContext('2d');
  pieChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Attacks', 'Normal'],
      datasets: [{
        data: [0, 1],
        backgroundColor: ['rgba(255,34,68,0.8)', 'rgba(0,255,136,0.7)'],
        borderColor: ['#ff2244', '#00ff88'],
        borderWidth: 1.5,
        hoverOffset: 6,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '68%',
      animation: { animateRotate: true, duration: 600 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#071428',
          borderColor: '#0d2847',
          borderWidth: 1,
          titleColor: '#c8e0f8',
          bodyColor: '#c8e0f8',
          callbacks: {
            label: ctx => ` ${ctx.parsed} events (${Math.round(ctx.parsed / ctx.dataset.data.reduce((a,b)=>a+b,0) * 100)}%)`
          }
        }
      }
    }
  });
}

// ─── Bar chart ──────────────────────────────
function initBarChart() {
  const ctx = document.getElementById('barChart').getContext('2d');
  barChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Hit Count',
        data: [],
        backgroundColor: 'rgba(255,34,68,0.6)',
        borderColor: '#ff2244',
        borderWidth: 1,
        borderRadius: 3,
        borderSkipped: false,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 500 },
      indexAxis: 'y',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#071428',
          borderColor: '#0d2847',
          borderWidth: 1,
          titleColor: '#ff2244',
          bodyColor: '#c8e0f8',
        }
      },
      scales: {
        x: {
          beginAtZero: true,
          grid: { color: 'rgba(13,40,71,0.7)', drawTicks: false },
          ticks: { color: '#5a7a9a' }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#00aaff', font: { size: 9 } }
        }
      }
    }
  });
}

// ─── Update bar chart with top IPs ──────────
function updateBarChart() {
  const ipMap = {};
  allLogs.filter(l => l.attack).forEach(l => {
    ipMap[l.ip] = (ipMap[l.ip] || 0) + 1;
  });
  const sorted = Object.entries(ipMap).sort((a,b) => b[1]-a[1]).slice(0, 6);
  barChart.data.labels = sorted.map(e => e[0]);
  barChart.data.datasets[0].data = sorted.map(e => e[1]);
  barChart.update();
}

// ─── Cards ──────────────────────────────────
function updateCards(totalTraffic, attackCount, normalCount) {
  const activeThreats = new Set(allLogs.filter(l => l.attack).map(l => l.ip)).size;

  animateValue('total-traffic', totalTraffic);
  animateValue('total-attacks', attackCount);
  animateValue('total-normal', normalCount);
  animateValue('active-threats', activeThreats);

  // Trends
  const trafficPct = prevTraffic ? Math.round((totalTraffic - prevTraffic) / prevTraffic * 100) : 0;
  const attackPct  = prevAttack  ? Math.round((attackCount - prevAttack) / prevAttack * 100)   : 0;
  document.getElementById('traffic-trend').textContent =
    `${trafficPct >= 0 ? '↑' : '↓'} ${Math.abs(trafficPct)}% this cycle`;
  document.getElementById('attack-trend').textContent =
    `${attackPct >= 0 ? '↑' : '↓'} ${Math.abs(attackPct)}% this cycle`;
  document.getElementById('threat-ips').textContent =
    `${activeThreats} unique IP${activeThreats !== 1 ? 's' : ''} flagged`;

  // Threat level badge
  const tlEl = document.getElementById('threat-level');
  const ratio = totalTraffic > 0 ? attackCount / totalTraffic : 0;
  if (ratio > 0.5)       { tlEl.textContent = 'CRITICAL'; tlEl.className = 'sys-val danger'; }
  else if (ratio > 0.25) { tlEl.textContent = 'ELEVATED'; tlEl.className = 'sys-val danger'; }
  else                   { tlEl.textContent = 'NORMAL';   tlEl.className = 'sys-val ok'; }

  prevTraffic = totalTraffic; prevAttack = attackCount; prevNormal = normalCount;

  // Sparklines
  pushSparkline(spark1, totalTraffic);
  pushSparkline(spark2, attackCount);
  pushSparkline(spark3, normalCount);
  pushSparkline(spark4, activeThreats);
}

let animFrames = {};
function animateValue(id, target) {
  const el = document.getElementById(id);
  const current = parseInt(el.textContent) || 0;
  if (animFrames[id]) cancelAnimationFrame(animFrames[id]);
  const diff = target - current;
  const steps = 20;
  let step = 0;
  function tick() {
    step++;
    el.textContent = Math.round(current + diff * (step / steps));
    if (step < steps) animFrames[id] = requestAnimationFrame(tick);
    else el.textContent = target;
  }
  animFrames[id] = requestAnimationFrame(tick);
}

// ─── Line chart update ──────────────────────
let cumulativeTraffic = 0, cumulativeAttacks = 0;
function updateLineChart(attackCount, totalTraffic) {
  cumulativeTraffic += totalTraffic;
  cumulativeAttacks += attackCount;

  const now  = new Date();
  const label = `${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;

  timeLabels.push(label);
  trafficHistory.push(cumulativeTraffic);
  attackHistory.push(cumulativeAttacks);

  if (timeLabels.length > MAX_LINE_POINTS) {
    timeLabels.shift(); trafficHistory.shift(); attackHistory.shift();
  }

  lineChart.data.labels                   = [...timeLabels];
  lineChart.data.datasets[0].data         = [...trafficHistory];
  lineChart.data.datasets[1].data         = [...attackHistory];
  lineChart.update();
}

// ─── Pie chart update ───────────────────────
let totalAttacks = 0, totalNormal = 0;
function updatePieChart(attackCount, normalCount) {
  totalAttacks += attackCount;
  totalNormal  += normalCount;
  pieChart.data.datasets[0].data = [totalAttacks, totalNormal];
  pieChart.update();
}

// ─── Table ──────────────────────────────────
   function formatTs(ts) {
  if (!ts) return "--:--:--";

  return ts.split(" ")[1];
}
function riskColor(rate, isAttack) {
  if (!isAttack) return '#00ff88';
  if (rate > 300) return '#ff2244';
  if (rate > 150) return '#ff8c00';
  return '#ffcc00';
}
function riskLabel(rate, isAttack) {
  if (!isAttack) return 0;
  return Math.min(100, Math.round(rate / 5));
}

function appendRows(logs) {
  const tbody = document.getElementById('alert-tbody');
  logs.forEach(log => {
    console.log(log);

    if (!log.features) 
       console.error("BAD LOG:", log);
    allLogs.push(log);
    rowIndex++;

    if (allLogs.length > MAX_TABLE_ROWS)
      allLogs.shift();

    const risk = riskLabel(log.features.packet_rate, log.attack);
    const col  = riskColor(log.features.packet_rate, log.attack);

    const tr = document.createElement('tr');
    tr.className = log.attack ? 'row-attack row-new' : 'row-new';
    tr.dataset.type = log.attack ? 'attack' : 'normal';

    tr.innerHTML = `
      <td style="color:#5a7a9a">${rowIndex}</td>
      <td class="ip-cell">${log.ip}</td>
      <td class="rate-cell">${log.features.packet_rate.toFixed(1)} <span style="color:#5a7a9a;font-size:0.6rem">Mbps</span></td>
      <td>
        <span class="badge ${log.attack ? 'badge-attack' : 'badge-normal'}">
          ${log.attack ? 'ATTACK' : 'NORMAL'}
        </span>
      </td>
      <td style="color:#5a7a9a">${formatTs(log.timestamp)}</td>
      <td>
        <div class="risk-bar">
          <div class="risk-fill" style="width:${risk}px;background:${col};box-shadow:0 0 4px ${col}"></div>
          <span class="risk-num">${risk}%</span>
        </div>
      </td>`;

    // Apply filter
    if (currentFilter === 'attack' && !log.attack) tr.style.display = 'none';
    if (currentFilter === 'normal' &&  log.attack) tr.style.display = 'none';

    tbody.insertBefore(tr, tbody.firstChild);

    // Remove extra rows from DOM
    while (tbody.children.length > MAX_TABLE_ROWS)
      tbody.removeChild(tbody.lastChild);
  });

  document.getElementById('alert-count').textContent = `${rowIndex} events`;
}

window.filterTable = function(type) {
  currentFilter = type;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#alert-tbody tr').forEach(tr => {
    if (type === 'all') tr.style.display = '';
    else tr.style.display = tr.dataset.type === type ? '' : 'none';
  });
};

window.clearTable = function() {
  document.getElementById('alert-tbody').innerHTML = '';
  allLogs = [];
  rowIndex = 0;
  totalAttacks = 0; totalNormal = 0;
  cumulativeTraffic = 0; cumulativeAttacks = 0;
  document.getElementById('alert-count').textContent = '0 events';
  pieChart.data.datasets[0].data = [0, 1];
  pieChart.update();
};

// ─── Last refresh ────────────────────────────
function updateRefreshTime() {
  const now = new Date();
  document.getElementById('last-refresh').textContent =
    now.toLocaleTimeString('en-US', { hour12: false });
}


async function fetchBlockedIPs() {
  try {
    const res = await fetch('/api/blocked');
    if (!res.ok) throw new Error();
    const data = await res.json();

    const tbody = document.getElementById('blocked-tbody');
    tbody.innerHTML = "";

    data.blocked_ips.forEach((ip, index) => {
      const tr = document.createElement('tr');

      tr.innerHTML = `
        <td style="color:#5a7a9a">${index + 1}</td>
        <td class="ip-cell">${ip}</td>
        <td>
          <span class="badge badge-attack">BLOCKED</span>
        </td>
      `;

      tbody.appendChild(tr);
    });

  } catch (e) {
    console.log("Blocked IP fetch error");
  }
}


// ─── Main poll loop ──────────────────────────
async function poll() {
  try {
    const data = await fetchData();
    const { logs, attack_count, normal_count } = data;
    const totalTraffic = attack_count + normal_count;

    updateCards(totalTraffic, attack_count, normal_count);
    updateLineChart(attack_count, totalTraffic);
    updatePieChart(attack_count, normal_count);
    appendRows(logs);

    updateBarChart();
    fetchBlockedIPs();   // ✅ ADD HERE
    updateRefreshTime();

  } catch (e) {
    console.error('Poll error:', e);
  }
}

// ─── Loader & init ──────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => {
    const loader = document.getElementById('loader');
    const app = document.getElementById('app');

    // FORCE SHOW UI
    loader.style.display = 'none';
    app.classList.remove('hidden');
    app.classList.add('show');

    // Init charts safely
    try {
      initLineChart();
      initPieChart();
      initBarChart();

      spark1 = makeSparkline('spark1', '#00aaff');
      spark2 = makeSparkline('spark2', '#ff2244');
      spark3 = makeSparkline('spark3', '#00ff88');
      spark4 = makeSparkline('spark4', '#ff8c00');

      poll();
      setInterval(poll, REFRESH_INTERVAL);
    } catch (e) {
      console.log("INIT ERROR:", e);
    }

  }, 1000);
});
