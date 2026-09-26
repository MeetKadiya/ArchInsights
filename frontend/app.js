/**
 * ArchInsights — AI-Powered Architectural Debt Visualizer
 * Interactive D3.js force graph + AI Copilot panel
 */

// ===================== Application State =====================
const state = {
    nodes: [],
    links: [],
    metrics: null,
    antipatterns: [],
    refactorings: [],
    aiSummary: null,
    activeFilter: 'all',
    searchQuery: '',
    sizeMode: 'complexity',
    selectedNode: null,
    hotspotMode: false,
    simulation: null,
    svg: null,
    g: null,
    zoom: null,
    copilotTab: 'summary',
};

// ===================== DOM Elements =====================
const el = {
    svg: document.getElementById('d3Svg'),
    emptyState: document.getElementById('emptyState'),
    tooltip: document.getElementById('graphTooltip'),
    metricTooltip: document.getElementById('metricTooltip'),

    // Metrics Ribbon
    valHealthGrade: document.getElementById('valHealthGrade'),
    valDebtScore: document.getElementById('valDebtScore'),
    valTotalModules: document.getElementById('valTotalModules'),
    valAvgComplexity: document.getElementById('valAvgComplexity'),
    valAvgMI: document.getElementById('valAvgMI'),
    valSmellsCount: document.getElementById('valSmellsCount'),
    cardHealthGrade: document.getElementById('cardHealthGrade'),

    // Pills
    pillCriticalCount: document.getElementById('pillCriticalCount'),
    pillCycleCount: document.getElementById('pillCycleCount'),
    pillGodCount: document.getElementById('pillGodCount'),
    pillCouplingCount: document.getElementById('pillCouplingCount'),
    pillSecurityCount: document.getElementById('pillSecurityCount'),
    pillShotgunCount: document.getElementById('pillShotgunCount'),
    pillOrphanCount: document.getElementById('pillOrphanCount'),

    // Controls
    inputSearch: document.getElementById('inputSearch'),
    selectSizeMode: document.getElementById('selectSizeMode'),
    btnZoomIn: document.getElementById('btnZoomIn'),
    btnZoomOut: document.getElementById('btnZoomOut'),
    btnResetView: document.getElementById('btnResetView'),
    btnFocusHotspots: document.getElementById('btnFocusHotspots'),

    // Responsive Mobile Controls & Drawers
    btnToggleControls: document.getElementById('btnToggleControls'),
    btnCloseControls: document.getElementById('btnCloseControls'),
    leftControls: document.getElementById('leftControls'),
    drawerBackdrop: document.getElementById('drawerBackdrop'),

    // Floating Canvas Controls
    canvasFloatingControls: document.getElementById('canvasFloatingControls'),
    btnFloatZoomIn: document.getElementById('btnFloatZoomIn'),
    btnFloatZoomOut: document.getElementById('btnFloatZoomOut'),
    btnFloatReset: document.getElementById('btnFloatReset'),
    btnFloatHotspots: document.getElementById('btnFloatHotspots'),

    // AI Copilot Panel
    btnAiCopilot: document.getElementById('btnAiCopilot'),
    aiCopilotPanel: document.getElementById('aiCopilotPanel'),
    btnCloseCopilot: document.getElementById('btnCloseCopilot'),
    copilotBody: document.getElementById('copilotBody'),

    // Summary tab
    copilotIdleMsg: document.getElementById('copilotIdleMsg'),
    copilotSummaryContent: document.getElementById('copilotSummaryContent'),
    gradeCircle: document.getElementById('gradeCircle'),
    gradeLetterLarge: document.getElementById('gradeLetterLarge'),
    gradeHeadline: document.getElementById('gradeHeadline'),
    gradeRepo: document.getElementById('gradeRepo'),
    aiSimpleBreakdown: document.getElementById('aiSimpleBreakdown'),
    aiNarrative: document.getElementById('aiNarrative'),
    aiStrengths: document.getElementById('aiStrengths'),
    aiRisks: document.getElementById('aiRisks'),

    // Action plan tab
    actionsIdleMsg: document.getElementById('actionsIdleMsg'),
    actionPlanList: document.getElementById('actionPlanList'),

    // Inspector tab
    inspectorIdleMsg: document.getElementById('inspectorIdleMsg'),
    inspectorContent: document.getElementById('inspectorContent'),

    // Modals
    btnSample: document.getElementById('btnSampleCodebase'),
    btnScanModal: document.getElementById('btnScanModal'),
    scanModal: document.getElementById('scanModal'),
    btnCloseModal: document.getElementById('btnCloseModal'),
    btnCancelScan: document.getElementById('btnCancelScan'),
    btnExecuteScan: document.getElementById('btnExecuteScan'),
    inputRepoPath: document.getElementById('inputRepoPath'),
    inputRepoName: document.getElementById('inputRepoName'),
    checkNeo4jSync: document.getElementById('checkNeo4jSync'),
    scanBtnSpinner: document.getElementById('scanBtnSpinner'),
    scanBtnText: document.getElementById('scanBtnText'),

    // Domain Scan Modal
    btnScanDomainModal: document.getElementById('btnScanDomainModal'),
    domainScanModal: document.getElementById('domainScanModal'),
    btnCloseDomainModal: document.getElementById('btnCloseDomainModal'),
    btnCancelDomainScan: document.getElementById('btnCancelDomainScan'),
    btnExecuteDomainScan: document.getElementById('btnExecuteDomainScan'),
    inputDomainTarget: document.getElementById('inputDomainTarget'),
    checkDomainNeo4jSync: document.getElementById('checkDomainNeo4jSync'),
    domainScanBtnSpinner: document.getElementById('domainScanBtnSpinner'),
    domainScanBtnText: document.getElementById('domainScanBtnText'),

    // Empty state buttons
    btnEmptyScan: document.getElementById('btnEmptyScan'),
    btnEmptyDomainScan: document.getElementById('btnEmptyDomainScan'),
    btnEmptySample: document.getElementById('btnEmptySample'),
};

// ===================== Init =====================
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initD3();
    bindEvents();
    bindCopilotTabs();
    bindInfoTips();
    checkHealthAndAutoLoad();
});

// ===================== Theme System =====================
function initTheme() {
    const savedTheme = localStorage.getItem('archinsights_theme') || 'emerald';
    applyTheme(savedTheme);
}

function applyTheme(theme) {
    document.body.classList.remove('theme-emerald', 'theme-amber', 'theme-crimson', 'theme-nord');
    document.body.classList.add(`theme-${theme}`);
    localStorage.setItem('archinsights_theme', theme);
    document.querySelectorAll('.theme-opt').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.theme === theme);
    });
    if (state.g) {
        state.g.selectAll('.nodes g circle').attr('fill', d => getNodeColor(d));
    }
}

// Setup D3 Canvas, SVG Defs, and Zoom
function initD3() {
    state.svg = d3.select('#d3Svg');
    state.svg.selectAll('*').remove();

    const defs = state.svg.append('defs');

    defs.append('marker')
        .attr('id', 'arrow-default')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 22).attr('refY', 0)
        .attr('markerWidth', 6).attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path').attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', 'rgba(148,163,184,0.4)');

    defs.append('marker')
        .attr('id', 'arrow-cycle')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 22).attr('refY', 0)
        .attr('markerWidth', 7).attr('markerHeight', 7)
        .attr('orient', 'auto')
        .append('path').attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', '#ef4444');

    state.g = state.svg.append('g').attr('class', 'zoom-container');

    state.zoom = d3.zoom()
        .scaleExtent([0.1, 5])
        .on('zoom', (event) => { state.g.attr('transform', event.transform); });

    state.svg.call(state.zoom).on('dblclick.zoom', null);
}

// ===================== Event Binding =====================
function bindEvents() {
    // Theme toggle & palette selection
    const btnThemeToggle = document.getElementById('btnThemeToggle');
    const themeDropdown = document.getElementById('themeDropdown');
    if (btnThemeToggle && themeDropdown) {
        btnThemeToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            themeDropdown.classList.toggle('hidden');
        });
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.theme-switcher-wrapper')) {
                themeDropdown.classList.add('hidden');
            }
        });
        document.querySelectorAll('.theme-opt').forEach(btn => {
            btn.addEventListener('click', () => {
                const selected = btn.dataset.theme;
                applyTheme(selected);
                themeDropdown.classList.add('hidden');
            });
        });
    }

    // Left Controls Mobile Drawer toggle
    if (el.btnToggleControls && el.leftControls) {
        el.btnToggleControls.addEventListener('click', () => {
            const isOpen = el.leftControls.classList.toggle('open');
            el.btnToggleControls.classList.toggle('active', isOpen);
            if (isOpen) {
                if (window.innerWidth <= 900) {
                    el.aiCopilotPanel.classList.remove('open');
                    el.btnAiCopilot.classList.remove('active');
                    if (el.drawerBackdrop) el.drawerBackdrop.classList.add('active');
                }
            } else {
                if (el.drawerBackdrop && !el.aiCopilotPanel.classList.contains('open')) {
                    el.drawerBackdrop.classList.remove('active');
                }
            }
        });
    }

    if (el.btnCloseControls && el.leftControls) {
        el.btnCloseControls.addEventListener('click', () => {
            el.leftControls.classList.remove('open');
            if (el.btnToggleControls) el.btnToggleControls.classList.remove('active');
            if (el.drawerBackdrop && !el.aiCopilotPanel.classList.contains('open')) {
                el.drawerBackdrop.classList.remove('active');
            }
        });
    }

    // Backdrop click closes all mobile drawers
    if (el.drawerBackdrop) {
        el.drawerBackdrop.addEventListener('click', () => {
            if (el.leftControls) el.leftControls.classList.remove('open');
            if (el.btnToggleControls) el.btnToggleControls.classList.remove('active');
            el.aiCopilotPanel.classList.remove('open');
            el.btnAiCopilot.classList.remove('active');
            el.drawerBackdrop.classList.remove('active');
        });
    }

    // AI Copilot toggle
    el.btnAiCopilot.addEventListener('click', () => {
        const open = el.aiCopilotPanel.classList.toggle('open');
        el.btnAiCopilot.classList.toggle('active', open);
        if (open && window.innerWidth <= 900) {
            if (el.leftControls) el.leftControls.classList.remove('open');
            if (el.btnToggleControls) el.btnToggleControls.classList.remove('active');
            if (el.drawerBackdrop) el.drawerBackdrop.classList.add('active');
        } else if (!open) {
            if (el.drawerBackdrop && (!el.leftControls || !el.leftControls.classList.contains('open'))) {
                el.drawerBackdrop.classList.remove('active');
            }
        }
    });

    el.btnCloseCopilot.addEventListener('click', () => {
        el.aiCopilotPanel.classList.remove('open');
        el.btnAiCopilot.classList.remove('active');
        if (el.drawerBackdrop && (!el.leftControls || !el.leftControls.classList.contains('open'))) {
            el.drawerBackdrop.classList.remove('active');
        }
    });

    // Zoom
    el.btnZoomIn.addEventListener('click', () => state.svg.transition().duration(300).call(state.zoom.scaleBy, 1.35));
    el.btnZoomOut.addEventListener('click', () => state.svg.transition().duration(300).call(state.zoom.scaleBy, 0.75));
    el.btnResetView.addEventListener('click', resetZoom);

    // Floating Canvas Zoom Controls
    if (el.btnFloatZoomIn)  el.btnFloatZoomIn.addEventListener('click', () => state.svg.transition().duration(300).call(state.zoom.scaleBy, 1.35));
    if (el.btnFloatZoomOut) el.btnFloatZoomOut.addEventListener('click', () => state.svg.transition().duration(300).call(state.zoom.scaleBy, 0.75));
    if (el.btnFloatReset)   el.btnFloatReset.addEventListener('click', resetZoom);
    if (el.btnFloatHotspots) el.btnFloatHotspots.addEventListener('click', toggleHotspotFocus);

    // Focus Hotspots toggle
    el.btnFocusHotspots.addEventListener('click', toggleHotspotFocus);

    // Responsive Window Resize & Orientation Handling
    let resizeTimer = null;
    window.addEventListener('resize', () => {
        if (resizeTimer) clearTimeout(resizeTimer);
        resizeTimer = setTimeout(handleWindowResize, 150);
    });

    // Search filter
    el.inputSearch.addEventListener('input', (e) => {
        state.searchQuery = e.target.value.toLowerCase();
        applyFilters();
    });

    // Size mode
    el.selectSizeMode.addEventListener('change', (e) => {
        state.sizeMode = e.target.value;
        updateNodeSizes();
    });

    // Filter pills
    document.querySelectorAll('.filter-pills .pill').forEach(pill => {
        pill.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-pills .pill').forEach(p => p.classList.remove('active'));
            const target = e.currentTarget;
            target.classList.add('active');
            state.activeFilter = target.getAttribute('data-filter');
            applyFilters();
        });
    });

    // Codebase Scan Modal
    el.btnScanModal.addEventListener('click', () => el.scanModal.classList.add('active'));
    el.btnCloseModal.addEventListener('click', () => el.scanModal.classList.remove('active'));
    el.btnCancelScan.addEventListener('click', () => el.scanModal.classList.remove('active'));

    el.btnExecuteScan.addEventListener('click', () => {
        const path = el.inputRepoPath.value.trim();
        const name = el.inputRepoName.value.trim();
        const syncNeo4j = el.checkNeo4jSync.checked;
        if (!path) { alert('Please enter a path or GitHub URL.'); return; }
        triggerScan(path, name, syncNeo4j);
    });

    // Domain Scan Modal
    if (el.btnScanDomainModal) {
        el.btnScanDomainModal.addEventListener('click', () => el.domainScanModal.classList.add('active'));
    }
    if (el.btnCloseDomainModal) {
        el.btnCloseDomainModal.addEventListener('click', () => el.domainScanModal.classList.remove('active'));
    }
    if (el.btnCancelDomainScan) {
        el.btnCancelDomainScan.addEventListener('click', () => el.domainScanModal.classList.remove('active'));
    }
    if (el.btnExecuteDomainScan) {
        el.btnExecuteDomainScan.addEventListener('click', () => {
            const domain = el.inputDomainTarget.value.trim();
            const syncNeo4j = el.checkDomainNeo4jSync ? el.checkDomainNeo4jSync.checked : false;
            if (!domain) { alert('Please enter a domain or URL to scan.'); return; }
            triggerDomainScan(domain, syncNeo4j);
        });
    }

    // Quick Domain Presets
    document.querySelectorAll('.preset-domain-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            if (el.inputDomainTarget) {
                el.inputDomainTarget.value = e.currentTarget.dataset.domain;
            }
        });
    });

    el.btnSample.addEventListener('click', () => triggerScan('tests/sample_codebase', 'SampleArchInsights', false));
    if (el.btnEmptyScan) el.btnEmptyScan.addEventListener('click', () => el.scanModal.classList.add('active'));
    if (el.btnEmptyDomainScan) el.btnEmptyDomainScan.addEventListener('click', () => el.domainScanModal.classList.add('active'));
    if (el.btnEmptySample) el.btnEmptySample.addEventListener('click', () => triggerScan('tests/sample_codebase', 'SampleArchInsights', false));
}

// AI Copilot Tabs
function bindCopilotTabs() {
    document.querySelectorAll('.drawer-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.drawer-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            state.copilotTab = tab.dataset.tab;

            document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
            const pane = document.getElementById(`tab${capitalize(tab.dataset.tab)}`);
            if (pane) pane.classList.remove('hidden');
        });
    });
}

// Metric info tips hover
// Metric info tips hover & mobile tap
function bindInfoTips() {
    document.querySelectorAll('.info-tip[data-tip]').forEach(tip => {
        const show = (e) => {
            el.metricTooltip.innerHTML = tip.getAttribute('data-tip');
            el.metricTooltip.style.display = 'block';
            positionMetricTooltip(e);
        };
        const hide = () => { el.metricTooltip.style.display = 'none'; };

        tip.addEventListener('mouseenter', show);
        tip.addEventListener('mousemove', positionMetricTooltip);
        tip.addEventListener('mouseleave', hide);

        // Mobile touch tap support
        tip.addEventListener('click', (e) => {
            e.stopPropagation();
            if (el.metricTooltip.style.display === 'block') {
                hide();
            } else {
                show(e);
            }
        });
    });

    document.addEventListener('click', (e) => {
        if (!e.target.closest('.info-tip')) {
            el.metricTooltip.style.display = 'none';
        }
    });
}

function positionMetricTooltip(e) {
    const tipWidth = el.metricTooltip.offsetWidth || 220;
    const tipHeight = el.metricTooltip.offsetHeight || 60;
    const margin = 10;

    const clientX = e.clientX !== undefined ? e.clientX : (e.touches && e.touches[0] ? e.touches[0].clientX : window.innerWidth / 2);
    const clientY = e.clientY !== undefined ? e.clientY : (e.touches && e.touches[0] ? e.touches[0].clientY : 60);

    let left = clientX + 12;
    let top = clientY + 12;

    if (left + tipWidth > window.innerWidth - margin) {
        left = Math.max(margin, window.innerWidth - tipWidth - margin);
    }
    if (top + tipHeight > window.innerHeight - margin) {
        top = Math.max(margin, clientY - tipHeight - 12);
    }

    el.metricTooltip.style.left = `${left}px`;
    el.metricTooltip.style.top  = `${top}px`;
}

// ===================== Health Check & Auto Load =====================
async function checkHealthAndAutoLoad() {
    try {
        const res = await fetch('/api/health');
        if (res.ok) {
            const data = await res.json();
            if (data.scanned_modules > 0) {
                await refreshAllData();
            } else {
                renderGraph();
            }
        }
    } catch (e) {
        console.warn('Backend not ready:', e);
        renderGraph();
    }
}

// ===================== Scan =====================
async function triggerScan(repoPath, repoName, syncNeo4j = true) {
    const isRemote = repoPath.startsWith('http') || repoPath.startsWith('git@') || repoPath.includes('github.com');
    el.scanBtnSpinner.classList.remove('hidden');
    el.scanBtnText.textContent = isRemote ? 'Streaming & Parsing ASTs...' : 'Parsing ASTs...';
    el.btnExecuteScan.disabled = true;

    showToast(isRemote ? 'Streaming repository & parsing ASTs in memory...' : 'Parsing ASTs with Tree-sitter...');

    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ repo_path: repoPath, repo_name: repoName || undefined, sync_to_neo4j: syncNeo4j }),
        });

        if (!res.ok) {
            const err = await res.json();
            alert(`Scan failed: ${err.detail || 'Unknown error'}`);
            return;
        }

        el.scanModal.classList.remove('active');
        showToast('Scan complete — loading AI analysis...');
        await refreshAllData();
        showToast('AI Copilot ready', 2000);
    } catch (e) {
        alert(`Scan error: ${e.message}`);
    } finally {
        el.scanBtnSpinner.classList.add('hidden');
        el.scanBtnText.textContent = 'Start Tree-sitter Ingestion';
        el.btnExecuteScan.disabled = false;
    }
}

// ===================== Domain Scan =====================
async function triggerDomainScan(domain, syncNeo4j = false) {
    if (el.domainScanBtnSpinner) el.domainScanBtnSpinner.classList.remove('hidden');
    if (el.domainScanBtnText) el.domainScanBtnText.textContent = 'Recon & Fingerprinting...';
    if (el.btnExecuteDomainScan) el.btnExecuteDomainScan.disabled = true;

    showToast(`Probing ${domain} (DNS, SSL, Ports, Tech Stack)...`);

    try {
        const res = await fetch('/api/domain/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain, sync_to_neo4j: syncNeo4j }),
        });

        if (!res.ok) {
            const err = await res.json();
            alert(`Domain scan failed: ${err.detail || 'Unknown error'}`);
            return;
        }

        const data = await res.json();
        if (el.domainScanModal) el.domainScanModal.classList.remove('active');
        showToast(`Discovered ${data.technologies_detected.length} techs & ${data.total_nodes} nodes — loading topology...`);
        await refreshAllData();
        showToast('Domain architecture mapped!', 2500);
    } catch (e) {
        alert(`Domain scan error: ${e.message}`);
    } finally {
        if (el.domainScanBtnSpinner) el.domainScanBtnSpinner.classList.add('hidden');
        if (el.domainScanBtnText) el.domainScanBtnText.textContent = 'Start Reconnaissance & Mapping';
        if (el.btnExecuteDomainScan) el.btnExecuteDomainScan.disabled = false;
    }
}

// ===================== Refresh All Data =====================
async function refreshAllData() {
    try {
        const [graphRes, metricsRes, antipatternsRes, refactoringsRes, aiSummaryRes] = await Promise.all([
            fetch('/api/graph?level=all'),
            fetch('/api/metrics'),
            fetch('/api/antipatterns'),
            fetch('/api/refactorings'),
            fetch('/api/ai/summary'),
        ]);

        const graphData   = await graphRes.json();
        state.metrics     = await metricsRes.json();
        state.antipatterns = await antipatternsRes.json();
        state.refactorings = await refactoringsRes.json();

        if (aiSummaryRes.ok) {
            state.aiSummary = await aiSummaryRes.json();
        } else {
            state.aiSummary = null;
        }

        state.nodes = graphData.nodes || [];
        state.links = graphData.links || [];

        updateMetricsRibbon();
        renderGraph();
        renderAiCopilot();

        // Auto-open copilot after scan
        el.aiCopilotPanel.classList.add('open');
        el.btnAiCopilot.classList.add('active');
    } catch (e) {
        console.error('Data load failed:', e);
    }
}

// ===================== Metrics Ribbon =====================
function updateMetricsRibbon() {
    if (!state.metrics || !state.metrics.total_modules) return;

    const m = state.metrics;
    const score = m.debt_score;

    // Debt score (plain number)
    el.valDebtScore.innerHTML = `${score}<span class="metric-unit">/100</span>`;

    // Health Grade
    const { letter, cls } = debtScoreToGrade(score);
    el.valHealthGrade.textContent = letter;
    el.valHealthGrade.className = `health-grade-letter ${cls}`;

    el.valTotalModules.textContent = m.total_modules;
    el.valAvgComplexity.textContent = m.average_complexity;
    el.valAvgMI.textContent = m.average_maintainability_index;
    el.valSmellsCount.textContent = state.antipatterns.length;

    const criticals = state.antipatterns.filter(a => a.severity === 'CRITICAL').length;
    const cycles    = state.antipatterns.filter(a => a.type === 'CIRCULAR_DEPENDENCY').length;
    const gods      = state.antipatterns.filter(a => a.type === 'GOD_CLASS').length;
    const coupling  = state.antipatterns.filter(a => a.type === 'TIGHT_COUPLING').length;
    const security  = state.antipatterns.filter(a => [
        'EXPOSED_DATABASE_PORT', 'MISSING_SECURITY_HEADERS', 'INSECURE_OR_EXPIRING_TLS',
        'EMAIL_SPOOFING_VULNERABILITY', 'INFORMATION_DISCLOSURE', 'SINGLE_POINT_OF_FAILURE'
    ].includes(a.type)).length;
    const shotgun   = state.antipatterns.filter(a => a.type === 'SHOTGUN_SURGERY').length;
    const orphans   = state.antipatterns.filter(a => a.type === 'ORPHAN_MODULE').length;

    if (el.pillCriticalCount) el.pillCriticalCount.textContent = criticals;
    if (el.pillCycleCount)    el.pillCycleCount.textContent    = cycles;
    if (el.pillGodCount)      el.pillGodCount.textContent      = gods;
    if (el.pillCouplingCount) el.pillCouplingCount.textContent = coupling;
    if (el.pillSecurityCount) el.pillSecurityCount.textContent = security;
    if (el.pillShotgunCount)  el.pillShotgunCount.textContent  = shotgun;
    if (el.pillOrphanCount)   el.pillOrphanCount.textContent   = orphans;
}

function debtScoreToGrade(score) {
    if (score <= 15) return { letter: 'A+', cls: 'grade-ap' };
    if (score <= 25) return { letter: 'A',  cls: 'grade-a'  };
    if (score <= 45) return { letter: 'B',  cls: 'grade-b'  };
    if (score <= 65) return { letter: 'C',  cls: 'grade-c'  };
    if (score <= 80) return { letter: 'D',  cls: 'grade-d'  };
    return { letter: 'F', cls: 'grade-f' };
}

// ===================== AI Copilot Panel =====================
function renderAiCopilot() {
    if (!state.aiSummary) {
        // Show idle state in all tabs
        el.copilotIdleMsg.classList.remove('hidden');
        el.copilotSummaryContent.classList.add('hidden');
        el.actionsIdleMsg.classList.remove('hidden');
        el.actionPlanList.classList.add('hidden');
        return;
    }

    const s = state.aiSummary;

    // --- Summary Tab ---
    el.copilotIdleMsg.classList.add('hidden');
    el.copilotSummaryContent.classList.remove('hidden');

    const { letter, cls } = debtScoreToGrade(s.debt_score || 0);
    const grade = s.health_grade || letter;
    const gradeCls = gradeLetterToCls(grade);

    el.gradeLetterLarge.textContent = grade;
    el.gradeCircle.className = `grade-circle ${gradeCls}`;
    el.gradeHeadline.textContent = s.headline || 'Architectural Assessment Ready';
    el.gradeRepo.textContent = s.repository_name || '';

    // Plain English breakdown callout
    if (el.aiSimpleBreakdown) {
        if (s.simple_breakdown) {
            el.aiSimpleBreakdown.innerHTML = `
                <div class="ai-simple-breakdown-title"><ion-icon name="bulb-outline"></ion-icon> The Big Picture (In Plain English)</div>
                <div>${cleanMarkdown(s.simple_breakdown)}</div>
            `;
            el.aiSimpleBreakdown.classList.remove('hidden');
        } else {
            el.aiSimpleBreakdown.classList.add('hidden');
        }
    }

    el.aiNarrative.innerHTML = cleanMarkdown(s.executive_summary || '');

    el.aiStrengths.innerHTML = (s.key_strengths || [])
        .map(t => `<li>${cleanMarkdown(t)}</li>`).join('');
    el.aiRisks.innerHTML = (s.critical_risks || [])
        .map(t => `<li>${cleanMarkdown(t)}</li>`).join('');

    // --- Action Plan Tab ---
    el.actionsIdleMsg.classList.add('hidden');
    el.actionPlanList.classList.remove('hidden');
    renderActionPlan(s.prioritized_actions || []);
}

function gradeLetterToCls(grade) {
    const map = { 'A+': 'grade-ap', 'A': 'grade-a', 'B': 'grade-b', 'C': 'grade-c', 'D': 'grade-d', 'F': 'grade-f' };
    return map[grade] || 'grade-f';
}

function renderActionPlan(actions) {
    if (!actions.length) {
        el.actionPlanList.innerHTML = '<div class="copilot-idle" style="padding:1.5rem 0;"><div class="copilot-idle-icon"><ion-icon name="checkmark-circle-outline" style="color:var(--color-green);"></ion-icon></div><p>No critical actions required — your architecture is in great shape!</p></div>';
        return;
    }

    el.actionPlanList.innerHTML = actions.map((action, idx) => {
        const severity = action.severity || 'Medium';
        const priorityCls = `priority-${severity.toLowerCase()}`;
        const diffBadge = action.difficulty ? `<span class="difficulty-badge"><ion-icon name="time-outline"></ion-icon> ${escapeHtml(action.difficulty)}</span>` : '';
        const debtBadge = action.debt_reduction_pct ? `<span class="difficulty-badge" style="color:#10b981;background:rgba(16,185,129,0.12)">-${action.debt_reduction_pct}% Debt</span>` : '';

        const stepsHtml = (action.action_steps || []).map((step, sIdx) => `
            <li class="action-step-item">
                <span class="action-step-num">${sIdx + 1}.</span>
                <span>${cleanMarkdown(step)}</span>
            </li>
        `).join('');

        const targetId = action.target_id || '';
        const targetName = action.target_name || '';

        return `
        <div class="action-item-card" data-node-id="${escapeHtml(targetId)}">
            <div class="action-item-header">
                <span class="action-priority-badge ${priorityCls}">#${idx + 1} ${severity}</span>
                ${diffBadge}
                ${debtBadge}
            </div>
            <div class="action-item-title">${escapeHtml(action.title || '')}</div>
            <div class="action-item-body">${cleanMarkdown(action.plain_english_summary || '')}</div>

            ${action.analogy ? `<div class="analogy-box"><ion-icon name="bulb-outline"></ion-icon> ${cleanMarkdown(action.analogy)}</div>` : ''}
            ${action.why_it_matters ? `<div class="why-box"><ion-icon name="alert-circle-outline"></ion-icon> <strong>Why this matters:</strong> ${cleanMarkdown(action.why_it_matters)}</div>` : ''}

            ${action.action_steps && action.action_steps.length ? `
            <div class="action-steps-box">
                <div class="action-steps-title"><ion-icon name="construct-outline"></ion-icon> Step-by-Step Fix</div>
                <ul class="action-steps-list">${stepsHtml}</ul>
            </div>` : ''}

            <div class="action-item-footer">
                ${targetName ? `<span class="action-item-target"><ion-icon name="document-text-outline"></ion-icon> ${escapeHtml(targetName)}</span>` : '<span></span>'}
                ${targetId ? `<button class="action-focus-btn" onclick="focusNode('${escapeHtml(targetId)}')"><ion-icon name="locate-outline"></ion-icon> Focus in Graph</button>` : ''}
            </div>
        </div>`;
    }).join('');
}

// Focus a node in the graph by ID
function focusNode(nodeId) {
    const node = state.nodes.find(n => n.id === nodeId);
    if (!node) return;

    // Highlight it
    state.g.selectAll('.node').each(function(d) {
        if (d.id === nodeId) {
            // Zoom to node position
            const w = el.svg.clientWidth;
            const h = el.svg.clientHeight;
            const tx = w / 2 - d.x;
            const ty = h / 2 - d.y;
            state.svg.transition().duration(600).call(
                state.zoom.transform,
                d3.zoomIdentity.translate(tx, ty).scale(1.8)
            );
            // Trigger selection
            selectNode(d);
        }
    });
}

// ===================== Node Inspector (AI Explain) =====================
async function openNodeInspector(d) {
    // Switch to Inspector tab
    document.querySelectorAll('.drawer-tab').forEach(t => t.classList.remove('active'));
    document.querySelector('[data-tab="inspector"]').classList.add('active');
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
    document.getElementById('tabInspector').classList.remove('hidden');
    state.copilotTab = 'inspector';

    // Open the panel
    el.aiCopilotPanel.classList.add('open');
    el.btnAiCopilot.classList.add('active');

    // Show loading state
    el.inspectorIdleMsg.classList.add('hidden');
    el.inspectorContent.classList.remove('hidden');

    const smells = state.antipatterns.filter(a =>
        a.entity_id === d.id ||
        (a.metrics && a.metrics.cycle_path && a.metrics.cycle_path.includes(d.id))
    );

    const plans = state.refactorings.filter(rp =>
        rp.target_id === d.id || smells.some(s => s.entity_id === rp.target_id)
    );

    // Render static metrics first
    el.inspectorContent.innerHTML = buildInspectorHTML(d, smells, plans);

    // Then fetch AI explanation
    const aiBox = document.getElementById('nodeAiExplain');
    if (aiBox) {
        aiBox.innerHTML = `<div class="ai-loading"><div class="spinner"></div> Generating AI analysis…</div>`;
        try {
            const res = await fetch('/api/ai/explain-node', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ node_id: d.id }),
            });
            if (res.ok) {
                const explanation = await res.json();
                renderNodeAiExplanation(aiBox, explanation);
            } else {
                aiBox.innerHTML = `<div class="inspector-card" style="color:var(--text-muted)">AI explanation unavailable.</div>`;
            }
        } catch (e) {
            aiBox.innerHTML = `<div class="inspector-card" style="color:var(--text-muted)">AI service error.</div>`;
        }
    }
}

function buildInspectorHTML(d, smells, plans) {
    const miColor = (d.maintainability || 100) < 65 ? 'text-red' : ((d.maintainability || 100) < 80 ? 'text-amber' : 'text-green');
    const ccColor = (d.complexity || 1) > 15 ? 'text-red' : ((d.complexity || 1) > 10 ? 'text-amber' : '');

    let html = `
    <div class="inspector-node-header">
        <div class="inspector-node-name">${escapeHtml(d.name)}</div>
        <div class="inspector-node-type">${d.label} · ${escapeHtml(d.file_path || d.id)}</div>
    </div>

    <div class="inspector-stat-row">
        <div class="inspector-stat">
            <div class="inspector-stat-label">Cyclomatic Complexity</div>
            <div class="inspector-stat-val ${ccColor}">${d.complexity ?? '--'}</div>
        </div>
        <div class="inspector-stat">
            <div class="inspector-stat-label">Maintainability Index</div>
            <div class="inspector-stat-val ${miColor}">${d.maintainability ?? '--'}</div>
        </div>
        <div class="inspector-stat">
            <div class="inspector-stat-label">Lines of Code</div>
            <div class="inspector-stat-val">${d.loc ?? '--'}</div>
        </div>
    </div>`;

    if (smells.length > 0) {
        html += `<div class="inspector-section"><div class="inspector-section-title">Detected Anti-Patterns</div>`;
        smells.forEach(s => {
            html += `<div class="inspector-card danger">
                <strong>${s.severity}: ${s.type}</strong><br>
                <span>${escapeHtml(s.description)}</span><br>
                <span style="font-size:0.7rem;color:var(--text-muted)">💡 ${escapeHtml(s.refactoring_suggestion)}</span>
            </div>`;
        });
        html += `</div>`;
    }

    if (plans.length > 0) {
        html += `<div class="inspector-section"><div class="inspector-section-title">Refactoring Blueprint</div>`;
        plans.forEach(plan => {
            html += `<div class="refactor-card">
                <span class="refactor-badge" style="background:rgba(16,185,129,0.2);color:#10b981;">-${plan.debt_reduction_pct}% Debt</span>
                <div class="refactor-title">${escapeHtml(plan.title)}</div>
                <div style="font-size:0.72rem;color:#818cf8;margin-bottom:5px;">Pattern: ${escapeHtml(plan.pattern)}</div>
                <ul class="refactor-steps">${plan.steps.map(s => `<li>▸ ${escapeHtml(s)}</li>`).join('')}</ul>
                <div class="diff-preview-box">${colorDiff(escapeHtml(plan.code_diff_preview))}</div>
            </div>`;
        });
        html += `</div>`;
    }

    // AI Explanation placeholder
    html += `<div class="inspector-section">
        <div class="inspector-section-title">✨ AI Deep Dive</div>
        <div id="nodeAiExplain"></div>
    </div>`;

    return html;
}

function renderNodeAiExplanation(container, exp) {
    const stepsHtml = (exp.easy_fix_steps || []).map(step => `
        <li class="action-step-item">
            <span>▸ ${cleanMarkdown(step)}</span>
        </li>
    `).join('');

    container.innerHTML = `
        ${exp.plain_english_role ? `<div class="plain-role-badge"><ion-icon name="information-circle-outline"></ion-icon> ${cleanMarkdown(exp.plain_english_role)}</div>` : ''}

        <div class="inspector-card" style="margin-top:0.4rem;">
            <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.3rem;">Status & Diagnosis</div>
            <div style="font-size:0.78rem;line-height:1.5;">${cleanMarkdown(exp.diagnosis || '')}</div>
        </div>

        ${exp.analogy ? `<div class="analogy-box" style="margin-top:0.45rem;"><ion-icon name="bulb-outline"></ion-icon> ${cleanMarkdown(exp.analogy)}</div>` : ''}

        ${exp.why_it_matters ? `
        <div class="why-box" style="margin-top:0.45rem;">
            <ion-icon name="alert-circle-outline"></ion-icon> <strong>Why this matters:</strong> ${cleanMarkdown(exp.why_it_matters)}
        </div>` : ''}

        <div class="inspector-card suggestion" style="margin-top:0.45rem;">
            <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;color:var(--color-indigo);margin-bottom:0.3rem;"><ion-icon name="construct-outline"></ion-icon> How To Fix It</div>
            <div style="font-size:0.78rem;line-height:1.45;">${cleanMarkdown(exp.recommended_refactoring || '')}</div>
            ${exp.suggested_pattern ? `<div style="margin-top:0.35rem;font-size:0.7rem;color:var(--color-cyan);"><ion-icon name="git-merge-outline"></ion-icon> Pattern: ${escapeHtml(exp.suggested_pattern)}</div>` : ''}
        </div>

        ${exp.easy_fix_steps && exp.easy_fix_steps.length ? `
        <div class="action-steps-box" style="margin-top:0.45rem;">
            <div class="action-steps-title"><ion-icon name="checkbox-outline"></ion-icon> Recommended Action Steps</div>
            <ul class="action-steps-list">${stepsHtml}</ul>
        </div>` : ''}

        ${exp.refactoring_diff ? `
        <div style="margin-top:0.6rem;">
            <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;color:var(--text-muted);margin-bottom:0.3rem;"><ion-icon name="code-slash-outline"></ion-icon> Before & After Code Transformation</div>
            <div class="diff-preview-box">${colorDiff(escapeHtml(exp.refactoring_diff))}</div>
        </div>` : ''}
    `;
}

// ===================== Graph Rendering =====================
function renderGraph() {
    if (!state.nodes || state.nodes.length === 0) {
        el.emptyState.classList.remove('hidden');
        return;
    }
    el.emptyState.classList.add('hidden');

    const width  = el.svg.clientWidth  || window.innerWidth;
    const height = el.svg.clientHeight || window.innerHeight;

    // Annotate nodes with smell flags
    const cycleIds    = new Set(state.antipatterns.filter(a => a.type === 'CIRCULAR_DEPENDENCY').map(a => a.entity_id));
    const godIds      = new Set(state.antipatterns.filter(a => a.type === 'GOD_CLASS').map(a => a.entity_id));
    const couplingIds = new Set(state.antipatterns.filter(a => a.type === 'TIGHT_COUPLING').map(a => a.entity_id));

    const simulationNodes = state.nodes.map(d => ({
        ...d,
        _isCycle:    d.is_in_cycle || cycleIds.has(d.id),
        _isGod:      godIds.has(d.id),
        _isCoupling: couplingIds.has(d.id),
    }));

    const nodeMap = new Map(simulationNodes.map(n => [n.id, n]));

    const simulationLinks = state.links
        .filter(l => nodeMap.has(l.source) && nodeMap.has(l.target))
        .map(l => ({
            source: nodeMap.get(l.source),
            target: nodeMap.get(l.target),
            type: l.type,
            is_cycle: l.is_cycle,
        }));

    state.g.selectAll('*').remove();
    if (state.simulation) state.simulation.stop();

    state.simulation = d3.forceSimulation(simulationNodes)
        .force('link', d3.forceLink(simulationLinks).id(d => d.id).distance(d => d.is_cycle ? 80 : 130))
        .force('charge', d3.forceManyBody().strength(-380))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => getNodeRadius(d) + 20));

    // Links
    const link = state.g.append('g').attr('class', 'links')
        .selectAll('line').data(simulationLinks).enter().append('line')
        .attr('class', d => `link ${d.is_cycle ? 'cycle-link' : ''}`)
        .attr('marker-end', d => d.is_cycle ? 'url(#arrow-cycle)' : 'url(#arrow-default)');

    // Nodes
    const node = state.g.append('g').attr('class', 'nodes')
        .selectAll('g').data(simulationNodes).enter().append('g')
        .attr('class', d => {
            let cls = 'node';
            if (d._isCycle)    cls += ' in-cycle';
            if (d._isGod)      cls += ' god-class';
            if (d._isCoupling) cls += ' tight-coupling';
            return cls;
        })
        .call(d3.drag()
            .on('start', (event, d) => { if (!event.active) state.simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
            .on('drag',  (event, d) => { d.fx = event.x; d.fy = event.y; })
            .on('end',   (event, d) => { if (!event.active) state.simulation.alphaTarget(0); d.fx = null; d.fy = null; })
        );

    node.append('circle')
        .attr('r', d => getNodeRadius(d))
        .attr('fill', d => getNodeColor(d));

    node.append('text')
        .attr('dx', d => getNodeRadius(d) + 4)
        .attr('dy', '.35em')
        .text(d => d.name);

    // Tooltip
    node.on('mouseenter', (event, d) => showNodeTooltip(event, d))
        .on('mousemove',  (event) => moveTooltip(event))
        .on('mouseleave', () => hideTooltip());

    // Click → AI Inspector
    node.on('click', (event, d) => {
        event.stopPropagation();
        state.selectedNode = d;
        highlightSelectedNode(d.id);
        openNodeInspector(d);
    });

    // Canvas click deselects
    state.svg.on('click', () => {
        state.selectedNode = null;
        highlightSelectedNode(null);
    });

    state.simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    resetZoom();
}

function getNodeRadius(d) {
    if (state.sizeMode === 'uniform') return d.label === 'Package' ? 16 : 11;
    if (state.sizeMode === 'loc')     return Math.max(8, Math.min(32, Math.sqrt(d.loc || 10) * 3));
    return Math.max(9, Math.min(30, (d.complexity || 1) * 2.2 + 6));
}

function getActiveThemePalette() {
    if (document.body.classList.contains('theme-amber')) {
        return {
            Package: '#f59e0b', Module: '#fbbf24', Class: '#fcd34d', Function: '#d97706',
            Edge: '#fbbf24', Gateway: '#f59e0b', Service: '#38bdf8',
            Infrastructure: '#b45309', Database: '#ea580c', ThirdParty: '#c084fc'
        };
    }
    if (document.body.classList.contains('theme-crimson')) {
        return {
            Package: '#f43f5e', Module: '#fb7185', Class: '#fda4af', Function: '#e11d48',
            Edge: '#fb7185', Gateway: '#f43f5e', Service: '#38bdf8',
            Infrastructure: '#be123c', Database: '#f59e0b', ThirdParty: '#e879f9'
        };
    }
    if (document.body.classList.contains('theme-nord')) {
        return {
            Package: '#0284c7', Module: '#38bdf8', Class: '#7dd3fc', Function: '#0369a1',
            Edge: '#38bdf8', Gateway: '#0284c7', Service: '#0ea5e9',
            Infrastructure: '#075985', Database: '#f59e0b', ThirdParty: '#818cf8'
        };
    }
    // Default: theme-emerald
    return {
        Package: '#10b981', Module: '#00f5a0', Class: '#06d6a0', Function: '#34d399',
        Edge: '#00f5a0', Gateway: '#10b981', Service: '#38bdf8',
        Infrastructure: '#059669', Database: '#f59e0b', ThirdParty: '#a855f7'
    };
}

function getNodeColor(d) {
    if (d._isCycle)    return '#ef4444';
    if (d._isGod)      return '#f59e0b';
    if (d._isCoupling) return '#06b6d4';
    const palette = getActiveThemePalette();
    if (palette[d.label]) return palette[d.label];
    const mi = d.maintainability || 100;
    if (mi >= 70) return palette.Infrastructure || '#10b981';
    if (mi >= 50) return '#f59e0b';
    return '#ef4444';
}

// ===================== Tooltip =====================
function showNodeTooltip(event, d) {
    const smells = state.antipatterns.filter(a => a.entity_id === d.id);
    const smellBadgeClass = (type) => {
        if (type === 'CIRCULAR_DEPENDENCY') return 'smell-cycle';
        if (type === 'GOD_CLASS') return 'smell-god';
        if (type === 'TIGHT_COUPLING') return 'smell-coupling';
        if (type === 'SHOTGUN_SURGERY') return 'smell-shotgun';
        if (type === 'ORPHAN_MODULE') return 'smell-orphan';
        if (['EXPOSED_DATABASE_PORT', 'INSECURE_OR_EXPIRING_TLS'].includes(type)) return 'smell-critical';
        return 'smell-security';
    };
    const smellBadges = smells.map(s => {
        const cls = smellBadgeClass(s.type);
        return `<span class="tooltip-smell ${cls}">${s.type.replace(/_/g, ' ')}</span>`;
    }).join(' ');

    el.tooltip.innerHTML = `
        <div class="tooltip-title">${escapeHtml(d.name)}</div>
        <div class="tooltip-row"><span class="tooltip-key">Type</span><span class="tooltip-val">${d.label}</span></div>
        ${d.tier ? `<div class="tooltip-row"><span class="tooltip-key">Tier</span><span class="tooltip-val">${escapeHtml(d.tier)}</span></div>` : ''}
        ${d.category ? `<div class="tooltip-row"><span class="tooltip-key">Category</span><span class="tooltip-val">${escapeHtml(d.category)}</span></div>` : ''}
        <div class="tooltip-row"><span class="tooltip-key">${d.tier ? 'Health Score' : 'LOC'}</span><span class="tooltip-val">${d.loc ?? '--'}</span></div>
        <div class="tooltip-row"><span class="tooltip-key">${d.tier ? 'Risk/Complexity' : 'CC'}</span><span class="tooltip-val">${d.complexity ?? '--'}</span></div>
        <div class="tooltip-row"><span class="tooltip-key">${d.tier ? 'Resilience Index' : 'MI'}</span><span class="tooltip-val">${d.maintainability ?? '--'}</span></div>
        ${smellBadges ? `<div style="margin-top:5px;">${smellBadges}</div>` : ''}
        ${smells.length === 0 ? '<div style="margin-top:5px;font-size:0.68rem;color:#64748b;">Click to open AI Inspector</div>' : ''}
    `;
    el.tooltip.style.display = 'block';
    moveTooltip(event);
}

function moveTooltip(event) {
    const tooltipWidth = el.tooltip.offsetWidth || 260;
    const tooltipHeight = el.tooltip.offsetHeight || 130;
    const margin = 12;

    const pageX = event.pageX !== undefined ? event.pageX : (event.touches && event.touches[0] ? event.touches[0].pageX : window.innerWidth / 2);
    const pageY = event.pageY !== undefined ? event.pageY : (event.touches && event.touches[0] ? event.touches[0].pageY : window.innerHeight / 2);

    let left = pageX + 14;
    let top = pageY + 14;

    if (left + tooltipWidth > window.innerWidth - margin) {
        left = Math.max(margin, pageX - tooltipWidth - 14);
    }
    if (top + tooltipHeight > window.innerHeight - margin) {
        top = Math.max(margin, pageY - tooltipHeight - 14);
    }

    el.tooltip.style.left = `${left}px`;
    el.tooltip.style.top  = `${top}px`;
}

function hideTooltip() { el.tooltip.style.display = 'none'; }

// ===================== Node Selection =====================
function selectNode(d) {
    state.selectedNode = d;
    highlightSelectedNode(d.id);
    openNodeInspector(d);
}

function highlightSelectedNode(nodeId) {
    if (!state.g) return;
    state.g.selectAll('.node')
        .classed('selected', d => d.id === nodeId);
}

// ===================== Hotspot Focus Mode =====================
function toggleHotspotFocus() {
    state.hotspotMode = !state.hotspotMode;
    const bg = state.hotspotMode ? 'rgba(239,68,68,0.2)' : '';
    const border = state.hotspotMode ? 'var(--color-red)' : '';
    const color = state.hotspotMode ? 'var(--color-red)' : '';

    if (el.btnFocusHotspots) {
        el.btnFocusHotspots.style.background = bg;
        el.btnFocusHotspots.style.borderColor = border;
        el.btnFocusHotspots.style.color = color;
    }
    if (el.btnFloatHotspots) {
        el.btnFloatHotspots.style.background = bg;
        el.btnFloatHotspots.style.borderColor = border;
        el.btnFloatHotspots.style.color = color;
    }
    applyFilters();
}

// ===================== Filters =====================
function applyFilters() {
    if (!state.g) return;

    const criticalIds = new Set(state.antipatterns.filter(a => a.severity === 'CRITICAL').map(a => a.entity_id));
    const cycleIds    = new Set(state.antipatterns.filter(a => a.type === 'CIRCULAR_DEPENDENCY').map(a => a.entity_id));
    const godIds      = new Set(state.antipatterns.filter(a => a.type === 'GOD_CLASS').map(a => a.entity_id));
    const couplingIds = new Set(state.antipatterns.filter(a => a.type === 'TIGHT_COUPLING').map(a => a.entity_id));
    const securityIds = new Set(state.antipatterns.filter(a => [
        'EXPOSED_DATABASE_PORT', 'MISSING_SECURITY_HEADERS', 'INSECURE_OR_EXPIRING_TLS',
        'EMAIL_SPOOFING_VULNERABILITY', 'INFORMATION_DISCLOSURE', 'SINGLE_POINT_OF_FAILURE'
    ].includes(a.type)).map(a => a.entity_id));
    const shotgunIds  = new Set(state.antipatterns.filter(a => a.type === 'SHOTGUN_SURGERY').map(a => a.entity_id));
    const orphanIds   = new Set(state.antipatterns.filter(a => a.type === 'ORPHAN_MODULE').map(a => a.entity_id));

    state.g.selectAll('.node').style('opacity', d => {
        const matchSearch = !state.searchQuery || d.name.toLowerCase().includes(state.searchQuery);
        if (!matchSearch) return 0.12;

        if (state.hotspotMode) {
            const isHotspot = d.is_in_cycle || criticalIds.has(d.id) || cycleIds.has(d.id) || godIds.has(d.id) || couplingIds.has(d.id) || securityIds.has(d.id) || shotgunIds.has(d.id) || orphanIds.has(d.id);
            if (!isHotspot) return 0.1;
        }

        if (state.activeFilter === 'critical') return criticalIds.has(d.id) ? 1.0 : 0.12;
        if (state.activeFilter === 'cycle')    return (d.is_in_cycle || cycleIds.has(d.id)) ? 1.0 : 0.12;
        if (state.activeFilter === 'god')      return godIds.has(d.id)      ? 1.0 : 0.12;
        if (state.activeFilter === 'coupling') return couplingIds.has(d.id) ? 1.0 : 0.12;
        if (state.activeFilter === 'security') return securityIds.has(d.id) ? 1.0 : 0.12;
        if (state.activeFilter === 'shotgun')  return shotgunIds.has(d.id)  ? 1.0 : 0.12;
        if (state.activeFilter === 'orphan')   return orphanIds.has(d.id)   ? 1.0 : 0.12;
        return 1.0;
    });

    state.g.selectAll('.link').style('opacity', d => {
        if (state.activeFilter === 'cycle') return d.is_cycle ? 1.0 : 0.05;
        if (state.hotspotMode) return 0.12;
        return 0.5;
    });
}

function updateNodeSizes() {
    if (!state.g) return;
    state.g.selectAll('.node circle').transition().duration(250).attr('r', d => getNodeRadius(d));
    state.g.selectAll('.node text').attr('dx', d => getNodeRadius(d) + 4);
}

function resetZoom() {
    if (!state.svg || !state.zoom) return;
    state.svg.transition().duration(500).call(state.zoom.transform, d3.zoomIdentity.translate(0, 0).scale(1));
}

// ===================== Utilities =====================
function escapeHtml(text) {
    if (!text) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function cleanMarkdown(text) {
    if (!text) return '';
    let formatted = escapeHtml(text);
    // Replace **bold** with <strong>bold</strong>
    formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:#fff;">$1</strong>');
    // Replace *italic* with <em>italic</em>
    formatted = formatted.replace(/\*([^*]+)\*/g, '<em>$1</em>');
    // Strip any remaining raw asterisks so they never display
    formatted = formatted.replace(/\*/g, '');
    return formatted;
}

function colorDiff(escapedText) {
    return escapedText.split('\n').map(line => {
        if (line.startsWith('+')) return `<span class="diff-add">${line}</span>`;
        if (line.startsWith('-')) return `<span class="diff-remove">${line}</span>`;
        if (line.startsWith('#')) return `<span class="diff-comment">${line}</span>`;
        return line;
    }).join('\n');
}

function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

// Toast notification
let toastTimer = null;
function showToast(message, duration = 3500) {
    let toast = document.querySelector('.scan-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.className = 'scan-toast';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('show');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), duration);
}

// Window resize & device orientation handler
function handleWindowResize() {
    if (!state.simulation || !state.nodes || state.nodes.length === 0) return;
    const width  = el.svg.clientWidth  || window.innerWidth;
    const height = el.svg.clientHeight || window.innerHeight;
    state.simulation.force('center', d3.forceCenter(width / 2, height / 2));
    state.simulation.alpha(0.15).restart();
}
