/**
 * BiTek AI Security Guard - Admin Dashboard JavaScript
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

(function($) {
    'use strict';

    // Main Dashboard object
    const BiTekDashboard = {
        
        // Initialize dashboard
        init: function() {
            this.bindEvents();
            this.startAutoRefresh();
            this.initCharts();
            this.loadDashboardData();
        },

        // Bind event handlers
        bindEvents: function() {
            // Test API Connection
            $(document).on('click', '#test-connection', this.testAPIConnection);
            
            // Configure AI button
            $(document).on('click', '#configure-ai', this.configureAI);
            
            // Run security scan
            $(document).on('click', '#run-scan', this.runSecurityScan);
            
            // Export logs
            $(document).on('click', '#export-logs', this.exportLogs);
            
            // Block IP
            $(document).on('click', '#block-ip', this.showBlockIPDialog);
            
            // Refresh threats
            $(document).on('click', '#refresh-threats', this.refreshThreats);
            
            // Log filters
            $(document).on('change', '#log-type-filter, #log-date-filter', this.filterLogs);
            $(document).on('click', '#apply-filters', this.applyLogFilters);
            $(document).on('click', '#clear-logs', this.clearLogs);
            
            // Settings tabs
            $(document).on('click', '.nav-tab', this.switchSettingsTab);
            
            // Emergency mode
            $(document).on('click', '#emergency-mode', this.enableEmergencyMode);
            
            // Tool actions
            $(document).on('click', '#run-full-scan', this.runFullScan);
            $(document).on('click', '#export-security-logs', this.exportSecurityLogs);
            $(document).on('click', '#manage-blacklist', this.manageBlacklist);
            
            // Log details
            $(document).on('click', '.bitek-view-details', this.viewLogDetails);
            $(document).on('click', '.bitek-block-ip', this.blockIP);
        },

        // Auto-refresh dashboard data
        startAutoRefresh: function() {
            setInterval(() => {
                this.refreshDashboardMetrics();
            }, 30000);
        },

        // Load initial dashboard data
        loadDashboardData: function() {
            this.showLoading();
            
            $.ajax({
                url: bitekAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'bitek_get_dashboard_data',
                    nonce: bitekAjax.nonce
                },
                success: (response) => {
                    if (response.success) {
                        this.updateDashboardData(response.data);
                    }
                    this.hideLoading();
                },
                error: () => {
                    this.hideLoading();
                    this.showNotice('Failed to load dashboard data', 'error');
                }
            });
        },

        // Update dashboard with new data
        updateDashboardData: function(data) {
            // Update metric cards
            $('.bitek-metric-number').each(function(index) {
                const metricKeys = ['high_risk_events', 'blocked_requests', 'spam_comments', 'blocked_ips'];
                const metricValue = data[metricKeys[index]];
                if (metricValue !== undefined) {
                    BiTekDashboard.animateNumber(this, metricValue);
                }
            });

            // Update recent events
            if (data.recent_events) {
                this.updateRecentEvents(data.recent_events);
            }

            // Update threat statistics
            if (data.malicious_ips || data.suspicious_domains || data.attack_patterns) {
                this.updateThreatStats({
                    malicious_ips: data.malicious_ips,
                    suspicious_domains: data.suspicious_domains,
                    attack_patterns: data.attack_patterns
                });
            }
        },

        // Animate number changes
        animateNumber: function(element, newValue) {
            const $element = $(element);
            const currentValue = parseInt($element.text()) || 0;
            
            if (currentValue !== newValue) {
                $({ counter: currentValue }).animate({
                    counter: newValue
                }, {
                    duration: 1000,
                    easing: 'swing',
                    step: function() {
                        $element.text(Math.ceil(this.counter));
                    },
                    complete: function() {
                        $element.text(newValue);
                    }
                });
            }
        },

        // Update recent events section
        updateRecentEvents: function(events) {
            const $container = $('.bitek-events-content');
            
            if (events.length === 0) {
                $container.html('<p class="bitek-no-events">No recent security events.</p>');
                return;
            }

            let html = '';
            events.forEach(event => {
                html += `
                    <div class="bitek-event-item">
                        <div class="bitek-event-type bitek-event-${event.type}">
                            ${event.type.charAt(0).toUpperCase() + event.type.slice(1)}
                        </div>
                        <div class="bitek-event-details">
                            <div class="bitek-event-message">${this.escapeHtml(event.message)}</div>
                            <div class="bitek-event-time">${event.time}</div>
                        </div>
                    </div>
                `;
            });
            
            $container.html(html);
        },

        // Update threat statistics
        updateThreatStats: function(stats) {
            if (stats.malicious_ips !== undefined) {
                $('.bitek-threat-stat').eq(0).find('.bitek-threat-number').text(stats.malicious_ips);
            }
            if (stats.suspicious_domains !== undefined) {
                $('.bitek-threat-stat').eq(1).find('.bitek-threat-number').text(stats.suspicious_domains);
            }
            if (stats.attack_patterns !== undefined) {
                $('.bitek-threat-stat').eq(2).find('.bitek-threat-number').text(stats.attack_patterns);
            }
        },

        // Test API connection
        testAPIConnection: function(e) {
            e.preventDefault();
            const $button = $(this);
            const originalText = $button.text();
            
            $button.prop('disabled', true).html('<span class="bitek-loading"></span>Testing...');
            
            $.ajax({
                url: bitekAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'bitek_test_api',
                    nonce: bitekAjax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        BiTekDashboard.showNotice('API connection successful!', 'success');
                        $('.bitek-status-dot').removeClass('bitek-status-offline').addClass('bitek-status-online');
                    } else {
                        BiTekDashboard.showNotice('API connection failed. Please check your settings.', 'error');
                    }
                },
                error: function() {
                    BiTekDashboard.showNotice('API test failed. Please try again.', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        },

        // Configure AI settings
        configureAI: function(e) {
            e.preventDefault();
            window.location.href = bitekAjax.settingsUrl || 'admin.php?page=bitek-security-settings';
        },

        // Run security scan
        runSecurityScan: function(e) {
            e.preventDefault();
            const $button = $(this);
            const originalText = $button.text();
            
            $button.prop('disabled', true).html('<span class="bitek-loading"></span>Scanning...');
            
            $.ajax({
                url: bitekAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'bitek_run_scan',
                    nonce: bitekAjax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        BiTekDashboard.showNotice(`Scan completed: ${response.data.threats_found || 0} threats found`, 'info');
                        BiTekDashboard.refreshDashboardMetrics();
                    } else {
                        BiTekDashboard.showNotice('Security scan failed', 'error');
                    }
                },
                error: function() {
                    BiTekDashboard.showNotice('Security scan failed', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        },

        // Export logs
        exportLogs: function(e) {
            e.preventDefault();
            
            const format = prompt('Export format (json, csv, xml):', 'json');
            if (!format) return;
            
            window.location.href = `admin.php?page=bitek-security-tools&action=export&format=${format}`;
        },

        // Show block IP dialog
        showBlockIPDialog: function(e) {
            e.preventDefault();
            
            const ip = prompt('Enter IP address to block:');
            if (!ip) return;
            
            if (!BiTekDashboard.isValidIP(ip)) {
                BiTekDashboard.showNotice('Invalid IP address format', 'error');
                return;
            }
            
            BiTekDashboard.blockIP(null, ip);
        },

        // Block IP address
        blockIP: function(e, ip) {
            if (e) {
                e.preventDefault();
                ip = $(e.target).data('ip');
            }
            
            if (!ip) return;
            
            const reason = prompt('Reason for blocking (optional):', 'Manual block via dashboard');
            
            $.ajax({
                url: bitekAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'bitek_block_ip',
                    ip: ip,
                    reason: reason,
                    nonce: bitekAjax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        BiTekDashboard.showNotice(`IP ${ip} has been blocked`, 'success');
                        BiTekDashboard.refreshDashboardMetrics();
                    } else {
                        BiTekDashboard.showNotice('Failed to block IP address', 'error');
                    }
                },
                error: function() {
                    BiTekDashboard.showNotice('Failed to block IP address', 'error');
                }
            });
        },

        // Refresh threat intelligence
        refreshThreats: function(e) {
            e.preventDefault();
            const $button = $(this);
            const originalText = $button.text();
            
            $button.prop('disabled', true).html('<span class="bitek-loading"></span>Refreshing...');
            
            $.ajax({
                url: bitekAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'bitek_refresh_threats',
                    nonce: bitekAjax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        BiTekDashboard.showNotice('Threat intelligence updated successfully', 'success');
                        BiTekDashboard.refreshDashboardMetrics();
                    } else {
                        BiTekDashboard.showNotice('Failed to update threat intelligence', 'error');
                    }
                },
                error: function() {
                    BiTekDashboard.showNotice('Failed to update threat intelligence', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        },

        // Filter logs
        filterLogs: function() {
            const type = $('#log-type-filter').val();
            const date = $('#log-date-filter').val();
            
            $('.bitek-logs-table tbody tr').each(function() {
                const $row = $(this);
                const rowType = $row.find('.bitek-log-type').text().toLowerCase();
                const rowDate = $row.find('td:first').text().split(' ')[0];
                
                let showRow = true;
                
                if (type && !rowType.includes(type.toLowerCase())) {
                    showRow = false;
                }
                
                if (date && rowDate !== date) {
                    showRow = false;
                }
                
                $row.toggle(showRow);
            });
        },

        // Apply log filters
        applyLogFilters: function(e) {
            e.preventDefault();
            BiTekDashboard.filterLogs();
        },

        // Clear logs
        clearLogs: function(e) {
            e.preventDefault();
            
            if (!confirm('Are you sure you want to clear all security logs? This action cannot be undone.')) {
                return;
            }
            
            $.ajax({
                url: bitekAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'bitek_clear_logs',
                    nonce: bitekAjax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        BiTekDashboard.showNotice('Security logs cleared successfully', 'success');
                        location.reload();
                    } else {
                        BiTekDashboard.showNotice('Failed to clear logs', 'error');
                    }
                },
                error: function() {
                    BiTekDashboard.showNotice('Failed to clear logs', 'error');
                }
            });
        },

        // Switch settings tabs
        switchSettingsTab: function(e) {
            e.preventDefault();
            const $tab = $(this);
            const target = $tab.attr('href');
            
            // Update active tab
            $('.nav-tab').removeClass('nav-tab-active');
            $tab.addClass('nav-tab-active');
            
            // Show target content
            $('.tab-content').removeClass('active');
            $(target).addClass('active');
        },

        // Enable emergency mode
        enableEmergencyMode: function(e) {
            e.preventDefault();
            
            if (!confirm('Emergency mode will enable maximum security settings and may affect site functionality. Continue?')) {
                return;
            }
            
            const $button = $(this);
            const originalText = $button.text();
            
            $button.prop('disabled', true).html('<span class="bitek-loading"></span>Activating...');
            
            $.ajax({
                url: bitekAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'bitek_emergency_mode',
                    nonce: bitekAjax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        BiTekDashboard.showNotice('Emergency mode activated successfully', 'success');
                        setTimeout(() => location.reload(), 2000);
                    } else {
                        BiTekDashboard.showNotice('Failed to activate emergency mode', 'error');
                    }
                },
                error: function() {
                    BiTekDashboard.showNotice('Failed to activate emergency mode', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        },

        // Run full security scan
        runFullScan: function(e) {
            e.preventDefault();
            const $button = $(this);
            const originalText = $button.text();
            
            $button.prop('disabled', true).html('<span class="bitek-loading"></span>Scanning...');
            
            // Show progress modal
            BiTekDashboard.showScanProgress();
            
            $.ajax({
                url: bitekAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'bitek_run_full_scan',
                    nonce: bitekAjax.nonce
                },
                timeout: 300000, // 5 minutes timeout
                success: function(response) {
                    if (response.success) {
                        const data = response.data;
                        BiTekDashboard.showScanResults(data);
                        BiTekDashboard.showNotice(`Scan completed: ${data.files_scanned} files scanned, ${data.threats_found} threats found`, 'info');
                    } else {
                        BiTekDashboard.showNotice('Security scan failed', 'error');
                    }
                },
                error: function() {
                    BiTekDashboard.showNotice('Security scan failed or timed out', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(originalText);
                    BiTekDashboard.hideScanProgress();
                }
            });
        },

        // Show scan progress modal
        showScanProgress: function() {
            const modal = `
                <div id="bitek-scan-modal" class="bitek-modal">
                    <div class="bitek-modal-content">
                        <h3>Security Scan in Progress</h3>
                        <div class="bitek-progress-bar">
                            <div class="bitek-progress-fill"></div>
                        </div>
                        <p class="bitek-scan-status">Initializing scan...</p>
                        <div class="bitek-scan-stats">
                            <span>Files scanned: <strong id="files-scanned">0</strong></span>
                            <span>Threats found: <strong id="threats-found">0</strong></span>
                        </div>
                    </div>
                </div>
            `;
            
            $('body').append(modal);
            this.animateProgress();
        },

        // Animate scan progress
        animateProgress: function() {
            let progress = 0;
            const interval = setInterval(() => {
                progress += Math.random() * 10;
                if (progress > 95) progress = 95;
                
                $('#bitek-scan-modal .bitek-progress-fill').css('width', progress + '%');
                $('#bitek-scan-modal .bitek-scan-status').text(`Scanning files... ${Math.round(progress)}%`);
                
                if (progress >= 95) {
                    clearInterval(interval);
                }
            }, 500);
        },

        // Hide scan progress modal
        hideScanProgress: function() {
            $('#bitek-scan-modal').remove();
        },

        // Show scan results
        showScanResults: function(data) {
            let threatsHtml = '';
            
            if (data.results && data.results.length > 0) {
                data.results.forEach(result => {
                    if (result.status !== 'clean') {
                        threatsHtml += `
                            <div class="bitek-threat-item">
                                <strong>${result.file}</strong>
                                <ul>
                                    ${result.threats.map(threat => 
                                        `<li class="bitek-threat-${threat.severity}">${threat.name}</li>`
                                    ).join('')}
                                </ul>
                            </div>
                        `;
                    }
                });
            }
            
            const resultsModal = `
                <div id="bitek-results-modal" class="bitek-modal">
                    <div class="bitek-modal-content bitek-modal-large">
                        <div class="bitek-modal-header">
                            <h3>Security Scan Results</h3>
                            <button class="bitek-modal-close">&times;</button>
                        </div>
                        <div class="bitek-modal-body">
                            <div class="bitek-scan-summary">
                                <div class="bitek-summary-item">
                                    <span class="bitek-summary-number">${data.files_scanned}</span>
                                    <span class="bitek-summary-label">Files Scanned</span>
                                </div>
                                <div class="bitek-summary-item">
                                    <span class="bitek-summary-number">${data.threats_found}</span>
                                    <span class="bitek-summary-label">Threats Found</span>
                                </div>
                                <div class="bitek-summary-item">
                                    <span class="bitek-summary-number">${data.scan_time}s</span>
                                    <span class="bitek-summary-label">Scan Time</span>
                                </div>
                            </div>
                            ${data.threats_found > 0 ? 
                                `<div class="bitek-threats-list">
                                    <h4>Detected Threats:</h4>
                                    ${threatsHtml}
                                </div>` : 
                                '<p class="bitek-no-threats">No threats detected. Your site is secure!</p>'
                            }
                        </div>
                    </div>
                </div>
            `;
            
            $('body').append(resultsModal);
            
            // Close modal handler
            $(document).on('click', '.bitek-modal-close, .bitek-modal', function(e) {
                if (e.target === this) {
                    $(this).closest('.bitek-modal').remove();
                }
            });
        },

        // Export security logs
        exportSecurityLogs: function(e) {
            e.preventDefault();
            
            const format = prompt('Export format (json, csv, xml):', 'json');
            if (!format) return;
            
            window.location.href = `admin.php?page=bitek-security-tools&action=export-logs&format=${format}`;
        },

        // Manage IP blacklist
        manageBlacklist: function(e) {
            e.preventDefault();
            
            // This would open a modal or redirect to blacklist management
            BiTekDashboard.showNotice('Blacklist management feature coming soon', 'info');
        },

        // View log details
        viewLogDetails: function(e) {
            e.preventDefault();
            const logId = $(this).data('log-id');
            
            $.ajax({
                url: bitekAjax.ajaxurl,
                type: 'POST',
                data: {
                    action: 'bitek_get_log_details',
                    log_id: logId,
                    nonce: bitekAjax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        BiTekDashboard.showLogDetailsModal(response.data);
                    } else {
                        BiTekDashboard.showNotice('Failed to load log details', 'error');
                    }
                },
                error: function() {
                    BiTekDashboard.showNotice('Failed to load log details', 'error');
                }
            });
        },

        // Show log details modal
        showLogDetailsModal: function(logData) {
            const modal = `
                <div id="bitek-log-details-modal" class="bitek-modal">
                    <div class="bitek-modal-content">
                        <div class="bitek-modal-header">
                            <h3>Security Log Details</h3>
                            <button class="bitek-modal-close">&times;</button>
                        </div>
                        <div class="bitek-modal-body">
                            <table class="bitek-details-table">
                                <tr><th>Time:</th><td>${logData.timestamp}</td></tr>
                                <tr><th>Type:</th><td>${logData.type}</td></tr>
                                <tr><th>Event:</th><td>${logData.event}</td></tr>
                                <tr><th>IP Address:</th><td>${logData.ip}</td></tr>
                                <tr><th>User Agent:</th><td>${logData.user_agent}</td></tr>
                                <tr><th>URL:</th><td>${logData.url}</td></tr>
                                ${logData.data ? `<tr><th>Additional Data:</th><td><pre>${JSON.stringify(JSON.parse(logData.data), null, 2)}</pre></td></tr>` : ''}
                            </table>
                        </div>
                    </div>
                </div>
            `;
            
            $('body').append(modal);
        },

        // Initialize charts and visualizations
        initCharts: function() {
            // Threat trends chart
            if ($('#bitek-threat-trends').length) {
                this.initThreatTrendsChart();
            }
            
            // Activity chart
            if ($('#bitek-activity-chart').length) {
                this.initActivityChart();
            }
        },

        // Initialize threat trends chart
        initThreatTrendsChart: function() {
            const ctx = document.getElementById('bitek-threat-trends');
            if (!ctx) return;
            
            // This would use Chart.js if available
            // For now, we'll create a simple visualization
            this.createSimpleChart(ctx, 'line');
        },

        // Initialize activity chart
        initActivityChart: function() {
            const ctx = document.getElementById('bitek-activity-chart');
            if (!ctx) return;
            
            this.createSimpleChart(ctx, 'bar');
        },

        // Create simple chart visualization
        createSimpleChart: function(canvas, type) {
            // Simple canvas-based chart implementation
            // In a real implementation, you'd use Chart.js or similar
            const ctx = canvas.getContext('2d');
            const width = canvas.width;
            const height = canvas.height;
            
            ctx.fillStyle = '#f0f0f1';
            ctx.fillRect(0, 0, width, height);
            
            ctx.fillStyle = '#667eea';
            ctx.fillText('Chart visualization would appear here', 10, 20);
        },

        // Refresh dashboard metrics
        refreshDashboardMetrics: function() {
            this.loadDashboardData();
        },

        // Show loading state
        showLoading: function() {
            if (!$('.bitek-loading-overlay').length) {
                $('body').append('<div class="bitek-loading-overlay"><div class="bitek-loading-spinner"></div></div>');
            }
        },

        // Hide loading state
        hideLoading: function() {
            $('.bitek-loading-overlay').remove();
        },

        // Show notification
        showNotice: function(message, type = 'info') {
            const notice = `
                <div class="notice notice-${type} is-dismissible bitek-notice">
                    <p>${this.escapeHtml(message)}</p>
                    <button type="button" class="notice-dismiss">
                        <span class="screen-reader-text">Dismiss this notice.</span>
                    </button>
                </div>
            `;
            
            $('.bitek-dashboard, .bitek-logs, .bitek-settings, .bitek-tools').prepend(notice);
            
            // Auto-dismiss after 5 seconds
            setTimeout(() => {
                $('.bitek-notice').fadeOut(function() {
                    $(this).remove();
                });
            }, 5000);
        },

        // Utility: Escape HTML
        escapeHtml: function(unsafe) {
            if (!unsafe) return '';
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        },

        // Utility: Validate IP address
        isValidIP: function(ip) {
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
            
            if (!ipRegex.test(ip)) return false;
            
            return ip.split('.').every(octet => {
                const num = parseInt(octet);
                return num >= 0 && num <= 255;
            });
        },

        // jQuery extend for number animation
        setupNumberAnimation: function() {
            $.fn.animateNumber = function(to) {
                const $this = $(this);
                const from = parseInt($this.text()) || 0;
                
                if (from === to) return this;
                
                $({ counter: from }).animate({
                    counter: to
                }, {
                    duration: 1000,
                    easing: 'swing',
                    step: function() {
                        $this.text(Math.ceil(this.counter));
                    },
                    complete: function() {
                        $this.text(to);
                    }
                });
                
                return this;
            };
        }
    };

    // Initialize when document is ready
    $(document).ready(function() {
        BiTekDashboard.setupNumberAnimation();
        BiTekDashboard.init();
        
        // Handle dismiss notices
        $(document).on('click', '.notice-dismiss', function() {
            $(this).closest('.notice').fadeOut(function() {
                $(this).remove();
            });
        });
        
        // Handle modal closes
        $(document).on('click', '.bitek-modal-close', function() {
            $(this).closest('.bitek-modal').remove();
        });
        
        // Close modal when clicking outside
        $(document).on('click', '.bitek-modal', function(e) {
            if (e.target === this) {
                $(this).remove();
            }
        });
    });

    // Export for external use
    window.BiTekDashboard = BiTekDashboard;

})(jQuery);