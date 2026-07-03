/**
 * Live Monitor Dashboard
 * Real-time monitoring with WebSocket connection
 */

class LiveMonitor {
    constructor() {
        this.ws = null;
        this.charts = {};
        this.eventsPaused = false;
        this.currentFilter = 'all';
        this.maxEvents = 100;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.trafficData = {
            labels: [],
            upload: [],
            download: []
        };
        this.operationsData = {
            labels: [],
            values: []
        };
        // Track active operations for display
        this.activeOperations = new Map(); // operation_id -> operation data
    }

    init() {
        console.log('Initializing Live Monitor...');
        this.setupEventListeners();
        this.connectWebSocket();
        this.initializeCharts();
        this.startMetricsPolling();
    }

    setupEventListeners() {
        // Event filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.currentFilter = e.target.dataset.filter;
                this.filterEvents();
            });
        });

        // Pause events button
        const pauseBtn = document.getElementById('pause-events-btn');
        if (pauseBtn) {
            pauseBtn.addEventListener('click', () => {
                this.eventsPaused = !this.eventsPaused;
                pauseBtn.innerHTML = this.eventsPaused 
                    ? '<i class="fas fa-play"></i> Resume'
                    : '<i class="fas fa-pause"></i> Pause';
                pauseBtn.classList.toggle('btn-warning', this.eventsPaused);
            });
        }

        // Clear activity button
        const clearBtn = document.getElementById('clear-activity-btn');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.clearEvents();
            });
        }

        // Graph time range controls
        document.querySelectorAll('.btn-graph-control').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const parent = e.target.closest('.graph-controls');
                parent.querySelectorAll('.btn-graph-control').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                const range = e.target.dataset.range;
                this.updateTimeRange(range);
            });
        });
    }

    connectWebSocket() {
        const token = localStorage.getItem('psftp_token') || sessionStorage.getItem('psftp_token');
        if (!token) {
            console.warn('No access token found - waiting for authentication');
            this.updateStatus('disconnected', 'Waiting for login');
            // Don't auto-retry - let the navigation to monitoring view trigger initialization
            return;
        }

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        // Security: Don't pass token in URL (prevents logging/leaking)
        const wsUrl = `${protocol}//${window.location.host}/ws/monitor`;
        
        console.log('Connecting to WebSocket:', wsUrl);
        this.updateStatus('connecting', 'Connecting...');

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('WebSocket connected - sending authentication...');
            // Security: Send token in first message instead of URL
            this.ws.send(JSON.stringify({
                type: 'auth',
                token: token
            }));
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                
                // Handle authentication response
                if (data.type === 'connected') {
                    console.log('WebSocket authenticated:', data.message);
                    this.reconnectAttempts = 0;
                    this.updateStatus('connected', 'Connected');
                } else if (data.type === 'error' && data.message.includes('token')) {
                    console.error('WebSocket authentication failed:', data.message);
                    this.updateStatus('disconnected', 'Auth failed');
                    // Don't reconnect on auth errors
                    return;
                } else {
                    this.handleWebSocketMessage(data);
                }
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.updateStatus('disconnected', 'Connection error');
        };

        this.ws.onclose = () => {
            console.log('WebSocket closed');
            this.updateStatus('disconnected', 'Disconnected');
            this.attemptReconnect();
        };
    }

    attemptReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
            console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
            setTimeout(() => this.connectWebSocket(), delay);
        } else {
            console.error('Max reconnection attempts reached');
            this.updateStatus('disconnected', 'Connection failed');
        }
    }

    handleWebSocketMessage(data) {
        console.log('WebSocket message:', data);
        
        // Dispatch custom event for other components to listen
        window.dispatchEvent(new CustomEvent('live-monitor-event', { detail: data }));
        
        // Update metrics if provided
        if (data.metrics) {
            console.log('Updating metrics:', data.metrics);
            this.updateMetrics(data.metrics);
        }

        // Track active operations from events
        if (data.event && data.event.operation_id) {
            if (data.event.completed || data.event.cancelled) {
                // Remove from active operations if completed or cancelled
                console.log('[OPERATIONS] Removing operation:', data.event.operation_id, 'cancelled:', data.event.cancelled);
                this.activeOperations.delete(data.event.operation_id);
            } else {
                // Add or update active operation
                this.activeOperations.set(data.event.operation_id, {
                    operation_id: data.event.operation_id,
                    type: data.event.type,
                    file_name: data.event.file_name || 'Unknown file',
                    user: data.event.user,
                    bytes_uploaded: data.event.bytes_uploaded || 0,
                    timestamp: data.event.timestamp,
                    cancelled: data.event.cancelled || false
                });
            }
            // Update operations list display
            this.updateActiveOperationsList();
        }

        // Add event to feed
        if (data.event && !this.eventsPaused) {
            this.addEvent(data.event);
        }

        // Update graphs
        if (data.traffic) {
            console.log('Updating traffic graph:', data.traffic);
            this.updateTrafficGraph(data.traffic);
        }

        if (data.operations !== undefined) {
            console.log('Updating operations graph:', data.operations);
            this.updateOperationsGraph(data.operations);
        }

        // Update last activity timestamp
        this.updateLastActivity();
    }

    updateStatus(status, text) {
        const statusDot = document.getElementById('status-dot');
        const statusText = document.getElementById('status-text');
        
        if (statusDot) {
            statusDot.className = 'status-dot';
            if (status === 'disconnected') {
                statusDot.classList.add('disconnected');
            }
        }

        if (statusText) {
            statusText.textContent = text;
        }
    }

    updateLastActivity() {
        const lastUpdate = document.getElementById('last-update');
        if (lastUpdate) {
            const now = new Date();
            lastUpdate.textContent = `Last update: ${now.toLocaleTimeString()}`;
        }
    }

    updateMetrics(metrics) {
        const metricElements = {
            'metric-active-users': metrics.activeUsers || 0,
            'metric-temp-creds': metrics.tempCreds || 0,
            'metric-upload': this.formatBytes(metrics.uploadTraffic || 0),
            'metric-download': this.formatBytes(metrics.downloadTraffic || 0),
            'metric-operations': metrics.activeOperations || 0,
            'metric-total-files': metrics.totalFiles || 0
        };

        Object.entries(metricElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
            }
        });

        // Update temp creds change text
        const tempChange = document.getElementById('metric-temp-change');
        if (tempChange && metrics.tempCredsActive !== undefined) {
            tempChange.textContent = `${metrics.tempCredsActive} active`;
        }
    }

    async startMetricsPolling() {
        // Initial fetch
        try {
            const token = localStorage.getItem('psftp_token') || sessionStorage.getItem('psftp_token');
            if (!token) {
                console.warn('No token for metrics polling');
                return;
            }
            
            const response = await fetch('/api/monitoring/metrics', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.updateMetrics(data);
            }
        } catch (error) {
            console.error('Error fetching initial metrics:', error);
        }
        
        // Poll for metrics every 10 seconds as backup to WebSocket
        // Using cache manager with ETag support for efficient polling
        setInterval(async () => {
            try {
                const token = localStorage.getItem('psftp_token') || sessionStorage.getItem('psftp_token');
                if (!token) return;
                
                // Use cache manager if available (enables 304 Not Modified responses)
                let data;
                if (window.cacheManager) {
                    data = await window.cacheManager.fetch('/api/monitoring/metrics', {
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });
                } else {
                    // Fallback to direct fetch
                    const response = await fetch('/api/monitoring/metrics', {
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });
                    
                    if (response.ok) {
                        data = await response.json();
                    } else {
                        return;
                    }
                }
                
                if (data) {
                    this.updateMetrics(data);
                }
            } catch (error) {
                console.error('Error fetching metrics:', error);
            }
        }, 10000);
    }

    initializeCharts() {
        // Check if Chart.js is loaded
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded yet. Retrying in 1 second...');
            setTimeout(() => this.initializeCharts(), 1000);
            return;
        }
        
        // Traffic Over Time Chart
        const trafficCtx = document.getElementById('traffic-chart');
        if (trafficCtx) {
            this.charts.traffic = new Chart(trafficCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Upload',
                            data: [],
                            borderColor: '#4facfe',
                            backgroundColor: 'rgba(79, 172, 254, 0.1)',
                            tension: 0.4,
                            fill: true
                        },
                        {
                            label: 'Download',
                            data: [],
                            borderColor: '#43e97b',
                            backgroundColor: 'rgba(67, 233, 123, 0.1)',
                            tension: 0.4,
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top'
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            callbacks: {
                                label: (context) => {
                                    return `${context.dataset.label}: ${this.formatBytes(context.raw)}`;
                                }
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                callback: (value) => this.formatBytes(value)
                            }
                        }
                    },
                    interaction: {
                        mode: 'nearest',
                        axis: 'x',
                        intersect: false
                    }
                }
            });
        }

        // Active Operations Chart
        const opsCtx = document.getElementById('operations-chart');
        if (opsCtx) {
            this.charts.operations = new Chart(opsCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Active Operations',
                        data: [],
                        borderColor: '#f5576c',
                        backgroundColor: 'rgba(245, 87, 108, 0.2)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1
                            }
                        }
                    }
                }
            });
        }
    }

    updateTrafficGraph(trafficData) {
        if (!this.charts.traffic) return;

        const now = new Date();
        const timeLabel = now.toLocaleTimeString();

        // Add new data point
        this.trafficData.labels.push(timeLabel);
        this.trafficData.upload.push(trafficData.upload || 0);
        this.trafficData.download.push(trafficData.download || 0);

        // Keep only last 20 data points
        if (this.trafficData.labels.length > 20) {
            this.trafficData.labels.shift();
            this.trafficData.upload.shift();
            this.trafficData.download.shift();
        }

        this.charts.traffic.data.labels = this.trafficData.labels;
        this.charts.traffic.data.datasets[0].data = this.trafficData.upload;
        this.charts.traffic.data.datasets[1].data = this.trafficData.download;
        this.charts.traffic.update('none'); // Update without animation for smooth real-time
    }

    updateOperationsGraph(operationsCount) {
        if (!this.charts.operations) return;

        const now = new Date();
        const timeLabel = now.toLocaleTimeString();

        this.operationsData.labels.push(timeLabel);
        this.operationsData.values.push(operationsCount);

        if (this.operationsData.labels.length > 20) {
            this.operationsData.labels.shift();
            this.operationsData.values.shift();
        }

        this.charts.operations.data.labels = this.operationsData.labels;
        this.charts.operations.data.datasets[0].data = this.operationsData.values;
        this.charts.operations.update('none');
    }

    addEvent(event) {
        const feed = document.getElementById('activity-feed');
        if (!feed) return;

        // Remove empty state if present
        const emptyState = feed.querySelector('.empty-state');
        if (emptyState) {
            emptyState.remove();
        }

        // Check if this event has an operation_id and if we should update existing event
        if (event.operation_id) {
            const existingEvent = feed.querySelector(`[data-operation-id="${event.operation_id}"]`);
            
            if (existingEvent) {
                // Update existing event instead of creating new one
                const contentDiv = existingEvent.querySelector('.event-content');
                if (contentDiv) {
                    const titleDiv = contentDiv.querySelector('.event-title');
                    const descDiv = contentDiv.querySelector('.event-description');
                    const timestamp = new Date(event.timestamp || Date.now());
                    const metaDiv = contentDiv.querySelector('.event-meta');
                    
                    if (titleDiv) titleDiv.textContent = event.title || event.action;
                    if (descDiv) descDiv.textContent = event.description || '';
                    if (metaDiv) {
                        metaDiv.innerHTML = `
                            <span><i class="fas fa-clock"></i> ${timestamp.toLocaleTimeString()}</span>
                            ${event.user ? `<span><i class="fas fa-user"></i> ${this.escapeHtml(event.user)}</span>` : ''}
                            ${event.ip ? `<span><i class="fas fa-network-wired"></i> ${this.escapeHtml(event.ip)}</span>` : ''}
                        `;
                    }
                    
                    // If completed, move to chronological position (otherwise keep at top)
                    if (event.completed) {
                        existingEvent.classList.add('completed');
                        // Move after other active events (find first completed event and insert before it)
                        const completedEvents = feed.querySelectorAll('.event-item.completed');
                        if (completedEvents.length > 0) {
                            // Insert after last non-completed or at beginning
                            const activeEvents = feed.querySelectorAll('.event-item:not(.completed)');
                            if (activeEvents.length > 0) {
                                const lastActive = activeEvents[activeEvents.length - 1];
                                lastActive.after(existingEvent);
                            }
                        }
                    } else {
                        // Keep at top - ensure it stays there
                        if (existingEvent !== feed.firstChild) {
                            feed.insertBefore(existingEvent, feed.firstChild);
                        }
                    }
                }
                return;
            }
        }

        // Create new event element
        const eventEl = this.createEventElement(event);
        
        // If event is in progress (has operation_id but not completed), add to top
        // If event is completed or no operation_id, add chronologically
        if (event.operation_id && !event.completed) {
            // Active operation - add to top
            feed.insertBefore(eventEl, feed.firstChild);
        } else {
            // Completed or instant event - add after active operations
            const activeEvents = feed.querySelectorAll('.event-item:not(.completed)');
            if (activeEvents.length > 0) {
                const lastActive = activeEvents[activeEvents.length - 1];
                lastActive.after(eventEl);
            } else {
                feed.insertBefore(eventEl, feed.firstChild);
            }
        }

        // Limit number of events
        const events = feed.querySelectorAll('.event-item');
        if (events.length > this.maxEvents) {
            events[events.length - 1].remove();
        }

        // Apply current filter
        this.filterEvents();
    }

    createEventElement(event) {
        const div = document.createElement('div');
        div.className = `event-item ${event.type}${event.completed ? ' completed' : ''}`;
        div.dataset.type = event.type;
        
        // Add operation_id as data attribute for tracking
        if (event.operation_id) {
            div.dataset.operationId = event.operation_id;
        }
        
        // Add cancelled class if event is cancelled
        if (event.cancelled) {
            div.classList.add('cancelled');
        }

        const icon = this.getEventIcon(event.type, event.cancelled);
        const timestamp = new Date(event.timestamp || Date.now());

        div.innerHTML = `
            <div class="event-icon ${event.type} ${event.cancelled ? 'cancelled' : ''}">
                <i class="fas ${icon}"></i>
            </div>
            <div class="event-content">
                <div class="event-title">${this.escapeHtml(event.title || event.action)}</div>
                <div class="event-description">${this.escapeHtml(event.description || '')}</div>
                <div class="event-meta">
                    <span><i class="fas fa-clock"></i> ${timestamp.toLocaleTimeString()}</span>
                    ${event.user ? `<span><i class="fas fa-user"></i> ${this.escapeHtml(event.user)}</span>` : ''}
                    ${event.ip ? `<span><i class="fas fa-network-wired"></i> ${this.escapeHtml(event.ip)}</span>` : ''}
                    ${event.cancelled ? `<span class="cancelled-badge"><i class="fas fa-ban"></i> CANCELLED</span>` : ''}
                </div>
            </div>
        `;

        return div;
    }

    getEventIcon(type, cancelled = false) {
        if (cancelled) {
            return 'fa-ban';  // Show ban icon for cancelled operations
        }
        
        const icons = {
            'login': 'fa-sign-in-alt',
            'upload': 'fa-upload',
            'download': 'fa-download',
            'error': 'fa-exclamation-triangle',
            'delete': 'fa-trash',
            'rename': 'fa-edit',
            'mkdir': 'fa-folder-plus',
            'operation_cancelled': 'fa-ban'
        };
        return icons[type] || 'fa-info-circle';
    }

    filterEvents() {
        const feed = document.getElementById('activity-feed');
        if (!feed) return;

        const events = feed.querySelectorAll('.event-item');
        events.forEach(event => {
            if (this.currentFilter === 'all' || event.dataset.type === this.currentFilter) {
                event.style.display = 'flex';
            } else {
                event.style.display = 'none';
            }
        });
    }

    clearEvents() {
        const feed = document.getElementById('activity-feed');
        if (!feed) return;

        feed.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-inbox fa-3x"></i>
                <p>Waiting for events...</p>
                <small>Events will appear here in real-time</small>
            </div>
        `;
    }

    updateTimeRange(range) {
        console.log('Time range changed to:', range);
        // Implementation for different time ranges
        // This would fetch historical data based on the selected range
    }

    updateActiveOperationsList() {
        const container = document.getElementById('operations-list');
        const badge = document.getElementById('active-ops-count');
        
        if (!container) return;

        const activeOps = Array.from(this.activeOperations.values());
        
        // Update badge count
        if (badge) {
            badge.textContent = activeOps.length;
        }

        if (activeOps.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>No active operations</p>
                </div>
            `;
            return;
        }

        // Create operation items with cancel button
        container.innerHTML = activeOps.map(op => {
            const icon = op.type === 'upload' ? 'fa-upload' : 'fa-download';
            const color = op.type === 'upload' ? '#4facfe' : '#43e97b';
            const elapsed = Math.floor((new Date() - new Date(op.timestamp)) / 1000);
            
            return `
                <div class="operation-item" data-operation-id="${this.escapeHtml(op.operation_id)}">
                    <div class="operation-icon ${op.type}">
                        <i class="fas ${icon}"></i>
                    </div>
                    <div class="operation-details">
                        <div class="operation-file">${this.escapeHtml(op.file_name)}</div>
                        <div class="operation-user">
                            <i class="fas fa-user"></i> ${this.escapeHtml(op.user)} • 
                            <i class="fas fa-clock"></i> ${elapsed}s ago
                        </div>
                    </div>
                    <div class="operation-progress">
                        <div class="progress-info">
                            <span class="progress-text">${this.formatBytes(op.bytes_uploaded || 0)} uploaded</span>
                        </div>
                        <div class="operation-spinner">
                            <i class="fas fa-spinner fa-spin" style="color: ${color}"></i>
                        </div>
                    </div>
                    <button class="btn-cancel-operation" data-operation-id="${op.operation_id}" title="Cancel operation">
                        <i class="fas fa-times"></i> Cancel
                    </button>
                </div>
            `;
        }).join('');
        
        // Add event listeners to cancel buttons using event delegation
        container.querySelectorAll('.btn-cancel-operation').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const opId = e.currentTarget.getAttribute('data-operation-id');
                if (opId) {
                    this.cancelOperation(opId);
                }
            });
        });
    }

    async cancelOperation(operationId) {
        console.log('[CANCEL] Attempting to cancel operation:', operationId);
        
        if (!confirm('Are you sure you want to cancel this operation?')) {
            console.log('[CANCEL] User cancelled the confirmation');
            return;
        }

        try {
            const token = localStorage.getItem('psftp_token') || sessionStorage.getItem('psftp_token');
            console.log('[CANCEL] Sending cancel request to:', `/api/operations/${operationId}/cancel`);
            
            const response = await fetch(`/api/operations/${operationId}/cancel`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            console.log('[CANCEL] Response status:', response.status);
            
            if (response.ok) {
                const result = await response.json();
                console.log('[CANCEL] Operation cancelled successfully:', result);
                // Remove from active operations
                this.activeOperations.delete(operationId);
                this.updateActiveOperationsList();
            } else {
                const error = await response.json();
                console.error('[CANCEL] Failed to cancel operation:', error);
                alert(`Failed to cancel operation: ${error.detail || 'Unknown error'}`);
            }
        } catch (error) {
            console.error('[CANCEL] Error cancelling operation:', error);
            alert(`Error cancelling operation: ${error.message}`);
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Initialize monitor when page loads
let liveMonitor = null;

// Function to initialize monitor (called after login)
function initializeLiveMonitor() {
    const monitorMetrics = document.getElementById('monitor-metrics');
    if (monitorMetrics && !liveMonitor) {
        console.log('Initializing Live Monitor after authentication...');
        liveMonitor = new LiveMonitor();
        liveMonitor.init();
    }
}

// Expose function globally so dashboard can call it
window.initializeLiveMonitor = initializeLiveMonitor;

// Auto-initialize if already authenticated on page load
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize if token exists
    const token = localStorage.getItem('psftp_token') || sessionStorage.getItem('psftp_token');
    if (token) {
        // Small delay to ensure DOM is ready
        setTimeout(initializeLiveMonitor, 100);
    }
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (liveMonitor) {
        liveMonitor.disconnect();
    }
});
