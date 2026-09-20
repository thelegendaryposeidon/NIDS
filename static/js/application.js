/**
 * Modern NIDS Dashboard Controller
 * Real-Time Socket.IO Telemetry, KPI Calculations, and Flow Table
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize State
    const maxFlows = 50;
    const flows = [];
    const uniqueApps = new Set();
    let totalCount = 0;
    let benignCount = 0;
    let threatCount = 0;

    // DOM Elements
    const kpiTotal = document.getElementById('kpi-total');
    const kpiBenign = document.getElementById('kpi-benign');
    const kpiThreats = document.getElementById('kpi-threats');
    const kpiApps = document.getElementById('kpi-apps');
    const detailsBody = document.getElementById('details-body');
    const searchInput = document.getElementById('flow-search');

    // 2. Initialize Chart.js with Dark Cybersecurity Theme
    const ctx = document.getElementById('myChart').getContext('2d');
    
    // Create gradient
    const gradient = ctx.createLinearGradient(0, 0, 0, 200);
    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.85)');
    gradient.addColorStop(1, 'rgba(56, 189, 248, 0.25)');

    const chartConfig = {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Flow Count',
                data: [],
                backgroundColor: gradient,
                borderColor: 'rgba(99, 102, 241, 1)',
                borderWidth: 1.5,
                borderRadius: 6,
                maxBarThickness: 45
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1e293b',
                    titleColor: '#f8fafc',
                    bodyColor: '#94a3b8',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1,
                    padding: 10,
                    displayColors: false,
                    callbacks: {
                        label: (context) => ` Captured Flows: ${context.parsed.y}`
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.04)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#94a3b8',
                        font: { family: "'JetBrains Mono', monospace", size: 11 }
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.04)',
                        drawBorder: false
                    },
                    ticks: {
                        color: '#94a3b8',
                        stepSize: 1,
                        font: { family: "'JetBrains Mono', monospace", size: 11 }
                    }
                }
            }
        }
    };

    const myChart = new Chart(ctx, chartConfig);

    // 3. Connect to WebSocket
    const socket = io.connect(`${window.location.protocol}//${document.domain}:${location.port}/test`);

    socket.on('connect', () => {
        console.log('Connected to NIDS Socket.IO telemetry stream.');
    });

    socket.on('disconnect', () => {
        console.warn('Disconnected from NIDS telemetry stream.');
    });

    // 4. Handle Incoming Result
    socket.on('newresult', (msg) => {
        if (!msg || !msg.result) return;

        const raw = msg.result;
        // Structure: [flow_count, src, src_port, dst, dst_port, proto, start_time, last_seen, pname, pid, classification, proba_score, risk]
        const flowId = raw[0];
        const srcIpHtml = raw[1] || '';
        const srcPort = raw[2] || '';
        const dstIpHtml = raw[3] || '';
        const dstPort = raw[4] || '';
        const protocol = (raw[5] || 'TCP').toUpperCase();
        const startTime = raw[6] || '';
        const lastSeen = raw[7] || '';
        const pName = raw[8] || '';
        const pid = raw[9] || '';
        const classification = raw[10] || 'Benign';
        const probaScore = typeof raw[11] === 'number' ? raw[11] : parseFloat(raw[11]) || 0;
        const riskHtml = raw[12] || '';

        // Extract raw text for search indexing
        const searchText = `${flowId} ${srcIpHtml.replace(/<[^>]+>/g, '')} ${srcPort} ${dstIpHtml.replace(/<[^>]+>/g, '')} ${dstPort} ${protocol} ${pName} ${pid} ${classification}`.toLowerCase();

        // Update KPIs
        totalCount++;
        const isBenign = classification.toLowerCase().includes('benign');
        if (isBenign) {
            benignCount++;
        } else {
            threatCount++;
        }

        if (pName && pName !== 'None' && pName !== '') {
            uniqueApps.add(pName);
        }

        if (kpiTotal) kpiTotal.textContent = totalCount;
        if (kpiBenign) kpiBenign.textContent = benignCount;
        if (kpiThreats) kpiThreats.textContent = threatCount;
        if (kpiApps) kpiApps.textContent = uniqueApps.size;

        // Flow Object
        const flowObj = {
            flowId,
            srcIpHtml,
            srcPort,
            dstIpHtml,
            dstPort,
            protocol,
            startTime,
            lastSeen,
            pName,
            pid,
            classification,
            probaScore,
            riskHtml,
            searchText
        };

        // Add to array (newest first)
        flows.unshift(flowObj);
        if (flows.length > maxFlows) {
            flows.pop();
        }

        // Render Table
        renderTable();

        // Update Chart
        if (msg.ips && Array.isArray(msg.ips)) {
            const labels = [];
            const data = [];
            msg.ips.slice(0, 10).forEach(item => {
                labels.push(item.SourceIP || 'Unknown');
                data.push(item.count || 0);
            });
            myChart.data.labels = labels;
            myChart.data.datasets[0].data = data;
            myChart.update();
        }
    });

    // 5. Helper: Render Table Rows
    function renderTable() {
        if (!detailsBody) return;

        const query = (searchInput ? searchInput.value : '').trim().toLowerCase();
        const filteredFlows = query ? flows.filter(f => f.searchText.includes(query)) : flows;

        if (filteredFlows.length === 0) {
            detailsBody.innerHTML = `
                <tr>
                    <td colspan="10" class="empty-table-state">
                        <i class="fa-solid fa-magnifying-glass"></i>
                        <p>${query ? 'No network flows match your filter.' : 'Awaiting captured network flows...'}</p>
                    </td>
                </tr>
            `;
            return;
        }

        let html = '';
        filteredFlows.forEach(f => {
            // Threat Badge Style
            const isBenign = f.classification.toLowerCase().includes('benign');
            const isProbe = f.classification.toLowerCase().includes('probe') || f.classification.toLowerCase().includes('scan');
            const threatClass = isBenign ? 'threat-benign' : (isProbe ? 'threat-probe' : 'threat-attack');
            const threatIcon = isBenign ? 'fa-circle-check' : (isProbe ? 'fa-triangle-exclamation' : 'fa-skull-crossbones');

            // Protocol Badge Style
            const protoClass = f.protocol === 'UDP' ? 'proto-udp' : 'proto-tcp';

            // Process attribution
            let processHtml = '<span class="pid-tag">System / Kernel</span>';
            if (f.pName && f.pName !== 'None' && f.pName !== '') {
                const pidStr = (f.pid && f.pid !== 'None') ? ` (${f.pid})` : '';
                processHtml = `<span class="app-badge"><i class="fa-solid fa-cube"></i> ${escapeHtml(f.pName)}${pidStr}</span>`;
            }

            // Confidence format
            const confidencePercent = (f.probaScore * 100).toFixed(1) + '%';

            // Risk parsing
            let riskBadge = parseRisk(f.riskHtml);

            html += `
                <tr>
                    <td class="flow-id-cell">#${f.flowId}</td>
                    <td>
                        <span class="ip-cell">${f.srcIpHtml}</span>
                        <span class="port-tag">:${f.srcPort}</span>
                    </td>
                    <td>
                        <span class="ip-cell">${f.dstIpHtml}</span>
                        <span class="port-tag">:${f.dstPort}</span>
                    </td>
                    <td><span class="proto-badge ${protoClass}">${f.protocol}</span></td>
                    <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-secondary);">${formatTime(f.lastSeen)}</td>
                    <td>${processHtml}</td>
                    <td>
                        <span class="threat-badge ${threatClass}">
                            <i class="fa-solid ${threatIcon}"></i>
                            ${escapeHtml(f.classification)}
                        </span>
                    </td>
                    <td style="font-family: var(--font-mono); font-weight: 600;">${confidencePercent}</td>
                    <td>${riskBadge}</td>
                    <td>
                        <a href="/flow-detail?flow_id=${f.flowId}" class="btn-detail" title="Inspect flow details & XAI features">
                            <i class="fa-solid fa-chart-pie"></i> Inspect
                        </a>
                    </td>
                </tr>
            `;
        });

        detailsBody.innerHTML = html;
    }

    // 6. Search Filter Event
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            renderTable();
        });
    }

    // Utility: Parse Risk HTML into Modern Badge
    function parseRisk(riskStr) {
        const lower = (riskStr || '').toLowerCase();
        if (lower.includes('very high')) return '<span class="risk-pill risk-very-high">Very High</span>';
        if (lower.includes('high')) return '<span class="risk-pill risk-high">High</span>';
        if (lower.includes('medium')) return '<span class="risk-pill risk-medium">Medium</span>';
        if (lower.includes('low')) return '<span class="risk-pill risk-low">Low</span>';
        return '<span class="risk-pill risk-minimal">Minimal</span>';
    }

    // Utility: Format Timestamp
    function formatTime(timeStr) {
        if (!timeStr) return '-';
        // If string contains full date, extract time part
        const parts = timeStr.toString().split(' ');
        return parts.length > 1 ? parts[1].split('.')[0] : timeStr;
    }

    // Utility: HTML Escaping
    function escapeHtml(str) {
        if (!str) return '';
        return str.toString()
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
});
