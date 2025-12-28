// Threat Intelligence Platform - Frontend
// API Configuration - CHANGE THIS WHEN DEPLOYED TO RENDER
const API_BASE_URL = 'http://localhost:5000'; // Local development
// const API_BASE_URL = 'https://threat-intel-api.onrender.com'; // Production

// State
let currentResults = null;

// DOM Elements
const form = document.getElementById('analyze-form');
const iocInput = document.getElementById('ioc-input');
const analyzeBtn = document.getElementById('analyze-btn');
const loadingSpinner = document.getElementById('loading-spinner');
const resultsContainer = document.getElementById('results-container');
const rateLimitBanner = document.getElementById('rate-limit-banner');
const rateLimitExceeded = document.getElementById('rate-limit-exceeded');
const cachedIndicator = document.getElementById('cached-indicator');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkRateLimit();
    setupEventListeners();
});

// Event Listeners
function setupEventListeners() {
    form.addEventListener('submit', handleSubmit);
    
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
    
    // Copy JSON button
    document.getElementById('copy-json-btn')?.addEventListener('click', copyJSON);
}

// Handle Form Submission
async function handleSubmit(e) {
    e.preventDefault();
    
    const ioc = iocInput.value.trim();
    if (!ioc) return;
    
    // Show loading
    analyzeBtn.disabled = true;
    loadingSpinner.classList.remove('hidden');
    resultsContainer.classList.add('hidden');
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ioc })
        });
        
        const data = await response.json();
        
        if (response.status === 429) {
            // Rate limit exceeded
            showRateLimitExceeded(data);
            return;
        }
        
        if (!response.ok) {
            throw new Error(data.message || 'Analysis failed');
        }
        
        // Update rate limit info
        updateRateLimitDisplay(data.rate_limit);
        
        // Display results
        displayResults(data);
        
    } catch (error) {
        console.error('Analysis error:', error);
        alert(`Error: ${error.message}`);
    } finally {
        analyzeBtn.disabled = false;
        loadingSpinner.classList.add('hidden');
    }
}

// Display Results
function displayResults(data) {
    currentResults = data;
    
    const results = data.results;
    const score = results.normalized_score;
    
    // Show cached indicator
    if (data.cached) {
        cachedIndicator.classList.remove('hidden');
    } else {
        cachedIndicator.classList.add('hidden');
    }
    
    // Score
    document.getElementById('score-value').textContent = score.final_score;
    const scoreBar = document.getElementById('score-bar');
    scoreBar.style.width = `${score.final_score}%`;
    scoreBar.className = `h-2 rounded-full transition-all duration-500 score-${score.severity.toLowerCase()}`;
    
    // Severity
    const severityBadge = document.getElementById('severity-badge');
    const severityIcon = document.getElementById('severity-icon');
    severityBadge.textContent = score.severity;
    severityBadge.className = `text-3xl font-bold mb-2 badge badge-${score.severity.toLowerCase()}`;
    
    const icons = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️',
        'MEDIUM': '🔍',
        'LOW': '📊',
        'MINIMAL': '✅'
    };
    severityIcon.textContent = icons[score.severity] || '•';
    
    // Sources
    const sourcesCount = Object.keys(results.intelligence_sources || {}).length;
    document.getElementById('sources-count').textContent = sourcesCount;
    
    // Key Findings
    displayKeyFindings(results);
    
    // Detection Rules
    displayDetectionRules(results.detection_rules);
    
    // Raw JSON
    document.getElementById('raw-json').textContent = JSON.stringify(data, null, 2);
    
    // Show results
    resultsContainer.classList.remove('hidden');
    resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Display Key Findings
function displayKeyFindings(results) {
    const container = document.getElementById('key-findings');
    container.innerHTML = '';
    
    const findings = [];
    
    // Score factors
    if (results.normalized_score?.contributing_factors) {
        results.normalized_score.contributing_factors.forEach(factor => {
            let cssClass = 'finding-item';
            
            if (factor.includes('USOM')) cssClass += ' usom';
            else if (factor.includes('C2')) cssClass += ' c2';
            else if (factor.includes('CRITICAL') || factor.includes('🚨')) cssClass += ' critical';
            else if (factor.includes('HIGH') || factor.includes('⚠️')) cssClass += ' high';
            
            findings.push({ text: factor, class: cssClass });
        });
    }
    
    // Malware families
    if (results._malware_families && results._malware_families.length > 0) {
        findings.push({
            text: `🦠 Malware Families: ${results._malware_families.join(', ')}`,
            class: 'finding-item high'
        });
    }
    
    // MITRE tactics
    if (results._mitre_tactics && results._mitre_tactics.length > 0) {
        const tactics = results._mitre_tactics.map(t => t.tactic).join(', ');
        findings.push({
            text: `🎯 MITRE ATT&CK: ${results._mitre_tactics.length} tactics (${tactics})`,
            class: 'finding-item'
        });
    }
    
    // Domain analysis
    if (results._domain_analysis?.is_suspicious) {
        findings.push({
            text: `🔍 ${results._domain_analysis.verdict} (Entropy: ${results._domain_analysis.metrics.entropy})`,
            class: 'finding-item high'
        });
    }
    
    // Render findings
    if (findings.length === 0) {
        container.innerHTML = '<p class="text-gray-400">No significant findings</p>';
    } else {
        findings.forEach(finding => {
            const div = document.createElement('div');
            div.className = finding.class;
            div.innerHTML = `
                <span class="mr-2 flex-shrink-0">${finding.text.match(/^[🇹🇷🚨⚠️🔍💬⚡🦠🎯]/)?.[0] || '•'}</span>
                <span class="flex-1">${finding.text.replace(/^[🇹🇷🚨⚠️🔍💬⚡🦠🎯]\s*/, '')}</span>
            `;
            container.appendChild(div);
        });
    }
}

// Display Detection Rules
function displayDetectionRules(rules) {
    if (!rules) return;
    
    const tabs = ['kql', 'spl', 'sigma', 'xql', 'yara'];
    const labels = {
        'kql': 'Microsoft Defender EDR',
        'spl': 'Splunk',
        'sigma': 'Universal SIEM',
        'xql': 'Cortex XDR',
        'yara': 'Malware Detection'
    };
    
    tabs.forEach(tab => {
        const container = document.getElementById(`tab-${tab}`);
        const queries = rules[`${tab}_queries`] || rules[`${tab}_rules`] || [];
        
        if (queries.length === 0) {
            container.innerHTML = `<p class="text-gray-400">No ${labels[tab]} rules generated</p>`;
            return;
        }
        
        container.innerHTML = '';
        queries.forEach((query, index) => {
            const div = document.createElement('div');
            div.className = 'code-block';
            div.innerHTML = `
                <button class="copy-btn" onclick="copyCode(this, ${tab}-${index})">
                    📋 Copy
                </button>
                <pre>${escapeHtml(query)}</pre>
            `;
            container.appendChild(div);
        });
    });
}

// Copy Code Function
window.copyCode = function(button, id) {
    const pre = button.nextElementSibling;
    const text = pre.textContent;
    
    navigator.clipboard.writeText(text).then(() => {
        button.textContent = '✅ Copied!';
        button.classList.add('copied');
        setTimeout(() => {
            button.textContent = '📋 Copy';
            button.classList.remove('copied');
        }, 2000);
    });
};

// Copy JSON
function copyJSON() {
    const json = document.getElementById('raw-json').textContent;
    
    navigator.clipboard.writeText(json).then(() => {
        const btn = document.getElementById('copy-json-btn');
        btn.innerHTML = '<span>✅</span><span>Copied!</span>';
        setTimeout(() => {
            btn.innerHTML = '<span>📋</span><span>Copy JSON</span>';
        }, 2000);
    });
}

// Switch Tab
function switchTab(tabName) {
    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    // Update panes
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
        pane.classList.add('hidden');
    });
    
    const activePane = document.getElementById(`tab-${tabName}`);
    activePane.classList.remove('hidden');
    activePane.classList.add('active');
}

// Rate Limit Functions
async function checkRateLimit() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/stats`);
        const data = await response.json();
        
        updateRateLimitDisplay({
            remaining: data.your_stats.remaining_today,
            limit: 5
        });
    } catch (error) {
        console.log('Could not fetch rate limit info');
    }
}

function updateRateLimitDisplay(rateLimit) {
    if (!rateLimit) return;
    
    const remaining = rateLimit.remaining;
    const limit = rateLimit.limit;
    
    document.getElementById('queries-remaining').textContent = remaining;
    
    if (remaining === 0) {
        rateLimitBanner.classList.add('hidden');
        rateLimitExceeded.classList.remove('hidden');
    } else if (remaining <= 2) {
        rateLimitBanner.classList.remove('hidden');
        rateLimitExceeded.classList.add('hidden');
    } else {
        rateLimitBanner.classList.add('hidden');
        rateLimitExceeded.classList.add('hidden');
    }
}

function showRateLimitExceeded(data) {
    rateLimitExceeded.classList.remove('hidden');
    
    if (data.reset_hours) {
        document.getElementById('retry-after').textContent = data.reset_hours;
    }
    
    resultsContainer.classList.add('hidden');
}

// Utility
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
