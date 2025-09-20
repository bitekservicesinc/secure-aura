/**
 * SecureAura Admin JavaScript
 * 
 * @package SecureAura
 * @since 3.0.0
 */

(function($) {
    'use strict';

    /**
     * SecureAura Admin Object
     */
    window.SecureAuraAdmin = {
        
        // Configuration
        config: {
            ajaxUrl: ajaxurl,
            nonce: secureAuraNonce || '',
            currentPage: '',
            intervals: {},
            modals: {}
        },

        // Initialize admin functionality
        init: function() {
            this.bindEvents();
            this.initModals();
            this.initTooltips();
            this.initCharts();
            this.startRealTimeUpdates();
            this.initEmergencyMode();
            this.initIPManagement();
            this.initScanner();
        },

        /**
         * Bind all event handlers
         */
        bindEvents: function() {
            var self = this;

            // Emergency Lockdown Toggle
            $(document).on('click', '.emergency-lockdown-toggle', function(e) {
                e.preventDefault();
                self.toggleEmergencyMode($(this));
            });

            // IP Management
            $(document).on('click', '.manage-ips-btn', function(e) {
                e.preventDefault();
                self.openIPManagementModal();
            });

            $(document).on('click', '.block-ip-btn', function(e) {
                e.preventDefault();
                self.blockIP();
            });

            $(document).on('click', '.unblock-ip-btn', function(e) {
                e.preventDefault();
                var ip = $(this).data('ip');
                self.unblockIP(ip);
            });

            // Security Scanner
            $(document).on('click', '.start-scan-btn', function(e) {
                e.preventDefault();
                self.startSecurityScan();
            });

            $(document).on('click', '.stop-scan-btn', function(e) {
                e.preventDefault();
                self.stopSecurityScan();
            });

            // Modal controls
            $(document).on('click', '.secure-aura-modal-close, .secure-aura-modal-overlay', function(e) {
                if (e.target === this) {
                    self.closeModal($(this).closest('.secure-aura-modal'));
                }
            });

            // System Info
            $(document).on('click', '.system-info-btn', function(e) {
                e.preventDefault();
                self.openSystemInfoModal();
            });

            // Refresh buttons
            $(document).on('click', '.refresh-dashboard', function(e) {
                e.preventDefault();
                self.refreshDashboard();
            });
        },

        /**
         * Initialize Emergency Mode functionality
         */
        initEmergencyMode: function() {
            var $toggle = $('.emergency-lockdown-toggle');
            var isActive = $toggle.hasClass('active');
            
            if (isActive) {
                this.showEmergencyModeStatus();
            }
        },

        /**
         * Toggle Emergency Mode
         */
        toggleEmergencyMode: function($button) {
            var self = this;
            var isActive = $button.hasClass('active');
            var action = isActive ? 'disable' : 'enable';

            // Show confirmation dialog
            if (!isActive) {
                var confirmMsg = secureAuraL10n.confirmEmergencyMode || 'Emergency mode will enable maximum security settings and may affect site functionality. Continue?';
                if (!confirm(confirmMsg)) {
                    return;
                }
            }

            // Show loading state
            $button.addClass('loading').prop('disabled', true);
            this.showNotification('info', 'Processing emergency mode request...');

            // AJAX request
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_emergency_mode',
                    emergency_action: action,
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success) {
                        // Update button state
                        if (action === 'enable') {
                            $button.addClass('active').removeClass('loading');
                            $button.find('.button-text').text(secureAuraL10n.disableEmergencyMode || 'Disable Emergency Mode');
                            self.showNotification('success', response.data.message || 'Emergency mode activated successfully!');
                            self.showEmergencyModeStatus();
                        } else {
                            $button.removeClass('active').removeClass('loading');
                            $button.find('.button-text').text(secureAuraL10n.enableEmergencyMode || 'Enable Emergency Mode');
                            self.showNotification('success', response.data.message || 'Emergency mode deactivated successfully!');
                            self.hideEmergencyModeStatus();
                        }
                        
                        // Refresh dashboard after 2 seconds
                        setTimeout(function() {
                            self.refreshDashboard();
                        }, 2000);
                    } else {
                        self.showNotification('error', response.data.message || 'Failed to toggle emergency mode.');
                    }
                },
                error: function(xhr, status, error) {
                    self.showNotification('error', 'Network error occurred. Please try again.');
                    console.error('Emergency mode error:', error);
                },
                complete: function() {
                    $button.removeClass('loading').prop('disabled', false);
                }
            });
        },

        /**
         * Show Emergency Mode Status
         */
        showEmergencyModeStatus: function() {
            var $statusBar = $('.emergency-mode-status');
            if ($statusBar.length === 0) {
                $statusBar = $('<div class="emergency-mode-status notice notice-warning">' +
                    '<p><strong>Emergency Mode Active:</strong> Maximum security protection is enabled. Some site functionality may be limited.</p>' +
                    '</div>');
                $('.secure-aura-dashboard').prepend($statusBar);
            }
            $statusBar.slideDown();
        },

        /**
         * Hide Emergency Mode Status
         */
        hideEmergencyModeStatus: function() {
            $('.emergency-mode-status').slideUp(function() {
                $(this).remove();
            });
        },

        /**
         * Initialize IP Management
         */
        initIPManagement: function() {
            this.loadBlockedIPs();
        },

        /**
         * Open IP Management Modal
         */
        openIPManagementModal: function() {
            var self = this;
            
            // Create modal if it doesn't exist
            if (!this.config.modals.ipManagement) {
                this.createIPManagementModal();
            }
            
            this.openModal('ip-management-modal');
            this.loadBlockedIPs();
        },

        /**
         * Create IP Management Modal
         */
        createIPManagementModal: function() {
            var modalHTML = `
                <div id="ip-management-modal" class="secure-aura-modal">
                    <div class="secure-aura-modal-overlay"></div>
                    <div class="secure-aura-modal-container">
                        <div class="secure-aura-modal-header">
                            <h3>${secureAuraL10n.manageIPs || 'Manage IP Addresses'}</h3>
                            <button class="secure-aura-modal-close">&times;</button>
                        </div>
                        <div class="secure-aura-modal-body">
                            <div class="secure-aura-ip-management">
                                <div class="secure-aura-ip-form">
                                    <h4>${secureAuraL10n.blockNewIP || 'Block New IP Address'}</h4>
                                    <div class="secure-aura-form-group">
                                        <label for="ip-address">${secureAuraL10n.ipAddress || 'IP Address'}:</label>
                                        <input type="text" id="ip-address" placeholder="192.168.1.1" class="regular-text">
                                    </div>
                                    <div class="secure-aura-form-group">
                                        <label for="block-reason">${secureAuraL10n.reason || 'Reason'}:</label>
                                        <input type="text" id="block-reason" placeholder="Suspicious activity" class="regular-text">
                                    </div>
                                    <button class="button button-primary block-ip-btn">${secureAuraL10n.blockIP || 'Block IP'}</button>
                                </div>
                                
                                <div class="secure-aura-blocked-ips">
                                    <h4>${secureAuraL10n.blockedIPs || 'Currently Blocked IPs'}</h4>
                                    <div class="blocked-ips-list">
                                        <div class="loading-spinner">Loading...</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            $('body').append(modalHTML);
            this.config.modals.ipManagement = true;
        },

        /**
         * Load Blocked IPs
         */
        loadBlockedIPs: function() {
            var self = this;
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_get_blocked_ips',
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success) {
                        self.displayBlockedIPs(response.data.ips);
                    } else {
                        self.showNotification('error', 'Failed to load blocked IPs.');
                    }
                },
                error: function() {
                    self.showNotification('error', 'Network error occurred while loading blocked IPs.');
                }
            });
        },

        /**
         * Display Blocked IPs
         */
        displayBlockedIPs: function(ips) {
            var $container = $('.blocked-ips-list');
            
            if (!ips || ips.length === 0) {
                $container.html('<p>No blocked IPs found.</p>');
                return;
            }
            
            var html = '<div class="blocked-ips-table">';
            html += '<div class="blocked-ip-header">';
            html += '<span>IP Address</span>';
            html += '<span>Reason</span>';
            html += '<span>Blocked Date</span>';
            html += '<span>Actions</span>';
            html += '</div>';
            
            ips.forEach(function(ip) {
                html += '<div class="blocked-ip-row">';
                html += '<span class="ip-address">' + ip.ip_address + '</span>';
                html += '<span class="block-reason">' + (ip.reason || 'No reason provided') + '</span>';
                html += '<span class="blocked-date">' + ip.blocked_at + '</span>';
                html += '<span class="ip-actions">';
                html += '<button class="button button-small unblock-ip-btn" data-ip="' + ip.ip_address + '">Unblock</button>';
                html += '</span>';
                html += '</div>';
            });
            
            html += '</div>';
            $container.html(html);
        },

        /**
         * Block IP Address
         */
        blockIP: function() {
            var self = this;
            var ipAddress = $('#ip-address').val().trim();
            var reason = $('#block-reason').val().trim();
            
            if (!ipAddress) {
                this.showNotification('error', 'Please enter an IP address.');
                return;
            }
            
            // Basic IP validation
            var ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            if (!ipRegex.test(ipAddress)) {
                this.showNotification('error', 'Please enter a valid IP address.');
                return;
            }
            
            $('.block-ip-btn').addClass('loading').prop('disabled', true);
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_block_ip',
                    ip_address: ipAddress,
                    reason: reason,
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success) {
                        self.showNotification('success', response.data.message || 'IP address blocked successfully!');
                        $('#ip-address, #block-reason').val('');
                        self.loadBlockedIPs();
                    } else {
                        self.showNotification('error', response.data.message || 'Failed to block IP address.');
                    }
                },
                error: function() {
                    self.showNotification('error', 'Network error occurred while blocking IP.');
                },
                complete: function() {
                    $('.block-ip-btn').removeClass('loading').prop('disabled', false);
                }
            });
        },

        /**
         * Unblock IP Address
         */
        unblockIP: function(ipAddress) {
            var self = this;
            
            if (!confirm('Are you sure you want to unblock this IP address?')) {
                return;
            }
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_unblock_ip',
                    ip_address: ipAddress,
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success) {
                        self.showNotification('success', response.data.message || 'IP address unblocked successfully!');
                        self.loadBlockedIPs();
                    } else {
                        self.showNotification('error', response.data.message || 'Failed to unblock IP address.');
                    }
                },
                error: function() {
                    self.showNotification('error', 'Network error occurred while unblocking IP.');
                }
            });
        },

        /**
         * Initialize Scanner
         */
        initScanner: function() {
            this.checkScanStatus();
        },

        /**
         * Start Security Scan
         */
        startSecurityScan: function() {
            var self = this;
            
            // Check if scan is already running
            if ($('.start-scan-btn').hasClass('scanning')) {
                this.showNotification('warning', 'A scan is already in progress.');
                return;
            }
            
            // Show scan modal
            this.openScanProgressModal();
            
            // Start scan
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_start_scan',
                    scan_type: 'full',
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success) {
                        self.showNotification('success', 'Security scan started successfully!');
                        self.startScanProgressMonitoring();
                    } else {
                        self.showNotification('error', response.data.message || 'Failed to start security scan.');
                        self.closeModal('scan-progress-modal');
                    }
                },
                error: function() {
                    self.showNotification('error', 'Network error occurred while starting scan.');
                    self.closeModal('scan-progress-modal');
                }
            });
        },

        /**
         * Open Scan Progress Modal
         */
        openScanProgressModal: function() {
            var modalHTML = `
                <div id="scan-progress-modal" class="secure-aura-modal">
                    <div class="secure-aura-modal-overlay"></div>
                    <div class="secure-aura-modal-container">
                        <div class="secure-aura-modal-header">
                            <h3>${secureAuraL10n.securityScanInProgress || 'Security Scan in Progress'}</h3>
                        </div>
                        <div class="secure-aura-modal-body">
                            <div class="secure-aura-scan-progress">
                                <div class="secure-aura-progress-bar">
                                    <div class="secure-aura-progress-fill" style="width: 0%;"></div>
                                </div>
                                <div class="secure-aura-progress-info">
                                    <span id="scan-progress-text">${secureAuraL10n.initializingScan || 'Initializing scan...'}</span>
                                    <span id="scan-progress-percent">0%</span>
                                </div>
                                <div class="secure-aura-scan-details">
                                    <div class="secure-aura-scan-stat">
                                        <span class="secure-aura-stat-label">${secureAuraL10n.filesScanned || 'Files Scanned'}:</span>
                                        <span id="files-scanned-count">0</span>
                                    </div>
                                    <div class="secure-aura-scan-stat">
                                        <span class="secure-aura-stat-label">${secureAuraL10n.threatsFound || 'Threats Found'}:</span>
                                        <span id="threats-found-count">0</span>
                                    </div>
                                </div>
                                <div class="secure-aura-scan-actions">
                                    <button class="button button-secondary stop-scan-btn">${secureAuraL10n.stopScan || 'Stop Scan'}</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            $('body').append(modalHTML);
            this.openModal('scan-progress-modal');
        },

        /**
         * Start Scan Progress Monitoring
         */
        startScanProgressMonitoring: function() {
            var self = this;
            
            this.config.intervals.scanProgress = setInterval(function() {
                self.updateScanProgress();
            }, 2000);
        },

        /**
         * Update Scan Progress
         */
        updateScanProgress: function() {
            var self = this;
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_get_scan_progress',
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success) {
                        var progress = response.data.progress;
                        
                        // Update progress bar
                        $('.secure-aura-progress-fill').css('width', progress.percentage + '%');
                        $('#scan-progress-percent').text(progress.percentage + '%');
                        $('#scan-progress-text').text(progress.status);
                        $('#files-scanned-count').text(progress.files_scanned || 0);
                        $('#threats-found-count').text(progress.threats_found || 0);
                        
                        // Check if scan is complete
                        if (progress.status === 'completed' || progress.status === 'failed') {
                            self.stopScanProgressMonitoring();
                            setTimeout(function() {
                                self.closeModal('scan-progress-modal');
                                self.showScanResults(progress);
                            }, 2000);
                        }
                    }
                },
                error: function() {
                    // Continue monitoring on error
                }
            });
        },

        /**
         * Stop Scan Progress Monitoring
         */
        stopScanProgressMonitoring: function() {
            if (this.config.intervals.scanProgress) {
                clearInterval(this.config.intervals.scanProgress);
                delete this.config.intervals.scanProgress;
            }
        },

        /**
         * Check Scan Status
         */
        checkScanStatus: function() {
            var self = this;
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_get_scan_status',
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success && response.data.status === 'running') {
                        // Scan is already running, show progress
                        self.openScanProgressModal();
                        self.startScanProgressMonitoring();
                    }
                }
            });
        },

        /**
         * Show Scan Results
         */
        showScanResults: function(results) {
            var message = 'Scan completed! ';
            if (results.threats_found > 0) {
                message += results.threats_found + ' threats found.';
                this.showNotification('warning', message);
            } else {
                message += 'No threats found. Your site is secure!';
                this.showNotification('success', message);
            }
            
            // Refresh dashboard
            this.refreshDashboard();
        },

        /**
         * Initialize Modals
         */
        initModals: function() {
            // Modal can be closed by clicking overlay or close button
            $(document).on('click', '.secure-aura-modal-overlay, .secure-aura-modal-close', function(e) {
                var $modal = $(this).closest('.secure-aura-modal');
                SecureAuraAdmin.closeModal($modal);
            });
            
            // Prevent modal content clicks from closing modal
            $(document).on('click', '.secure-aura-modal-container', function(e) {
                e.stopPropagation();
            });
        },

        /**
         * Open Modal
         */
        openModal: function(modalId) {
            var $modal = $('#' + modalId);
            if ($modal.length) {
                $modal.addClass('active');
                $('body').addClass('secure-aura-modal-open');
            }
        },

        /**
         * Close Modal
         */
        closeModal: function($modal) {
            if (typeof $modal === 'string') {
                $modal = $('#' + $modal);
            }
            
            $modal.removeClass('active');
            
            // Remove modal-open class if no modals are active
            if ($('.secure-aura-modal.active').length === 0) {
                $('body').removeClass('secure-aura-modal-open');
            }
            
            // Clean up scan progress monitoring if closing scan modal
            if ($modal.attr('id') === 'scan-progress-modal') {
                this.stopScanProgressMonitoring();
            }
        },

        /**
         * Open System Info Modal
         */
        openSystemInfoModal: function() {
            var self = this;
            
            // Create modal HTML
            var modalHTML = `
                <div id="system-info-modal" class="secure-aura-modal">
                    <div class="secure-aura-modal-overlay"></div>
                    <div class="secure-aura-modal-container large">
                        <div class="secure-aura-modal-header">
                            <h3>${secureAuraL10n.systemInformation || 'System Information'}</h3>
                            <button class="secure-aura-modal-close">&times;</button>
                        </div>
                        <div class="secure-aura-modal-body">
                            <div class="system-info-loading">
                                <div class="loading-spinner"></div>
                                <p>Loading system information...</p>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // Remove existing modal
            $('#system-info-modal').remove();
            
            // Add new modal
            $('body').append(modalHTML);
            this.openModal('system-info-modal');
            
            // Load system info
            this.loadSystemInfo();
        },

        /**
         * Load System Information
         */
        loadSystemInfo: function() {
            var self = this;
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_get_system_info',
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success) {
                        self.displaySystemInfo(response.data.system_info);
                    } else {
                        $('.system-info-loading').html('<p>Failed to load system information.</p>');
                    }
                },
                error: function() {
                    $('.system-info-loading').html('<p>Network error occurred while loading system information.</p>');
                }
            });
        },

        /**
         * Display System Information
         */
        displaySystemInfo: function(systemInfo) {
            var html = '<div class="system-info-sections">';
            
            // WordPress Information
            html += '<div class="system-info-section">';
            html += '<h4>WordPress Information</h4>';
            html += '<div class="system-info-grid">';
            html += '<div class="info-item"><span>Version:</span> ' + systemInfo.wordpress.version + '</div>';
            html += '<div class="info-item"><span>Multisite:</span> ' + (systemInfo.wordpress.multisite ? 'Yes' : 'No') + '</div>';
            html += '<div class="info-item"><span>Language:</span> ' + systemInfo.wordpress.language + '</div>';
            html += '<div class="info-item"><span>Timezone:</span> ' + systemInfo.wordpress.timezone + '</div>';
            html += '<div class="info-item"><span>Debug Mode:</span> ' + (systemInfo.wordpress.debug_mode ? 'Enabled' : 'Disabled') + '</div>';
            html += '<div class="info-item"><span>Memory Limit:</span> ' + systemInfo.wordpress.memory_limit + '</div>';
            html += '</div>';
            html += '</div>';
            
            // Server Information
            html += '<div class="system-info-section">';
            html += '<h4>Server Information</h4>';
            html += '<div class="system-info-grid">';
            html += '<div class="info-item"><span>Software:</span> ' + systemInfo.server.software + '</div>';
            html += '<div class="info-item"><span>PHP Version:</span> ' + systemInfo.server.php_version + '</div>';
            html += '<div class="info-item"><span>MySQL Version:</span> ' + systemInfo.server.mysql_version + '</div>';
            html += '<div class="info-item"><span>Max Execution Time:</span> ' + systemInfo.server.max_execution_time + 's</div>';
            html += '<div class="info-item"><span>Memory Limit:</span> ' + systemInfo.server.memory_limit + '</div>';
            html += '<div class="info-item"><span>Post Max Size:</span> ' + systemInfo.server.post_max_size + '</div>';
            html += '</div>';
            html += '</div>';
            
            // SecureAura Information
            html += '<div class="system-info-section">';
            html += '<h4>SecureAura Information</h4>';
            html += '<div class="system-info-grid">';
            html += '<div class="info-item"><span>Version:</span> ' + systemInfo.secure_aura.version + '</div>';
            html += '<div class="info-item"><span>Database Version:</span> ' + systemInfo.secure_aura.database_version + '</div>';
            html += '<div class="info-item"><span>License Type:</span> ' + systemInfo.secure_aura.license_type + '</div>';
            html += '<div class="info-item"><span>Emergency Mode:</span> ' + (systemInfo.secure_aura.emergency_mode ? 'Active' : 'Inactive') + '</div>';
            html += '<div class="info-item"><span>Last Scan:</span> ' + systemInfo.secure_aura.last_scan + '</div>';
            html += '<div class="info-item"><span>Threats Blocked:</span> ' + systemInfo.secure_aura.threats_blocked + '</div>';
            html += '</div>';
            html += '</div>';
            
            // Security Status
            html += '<div class="system-info-section">';
            html += '<h4>Security Status</h4>';
            html += '<div class="system-info-grid">';
            html += '<div class="info-item"><span>SSL Enabled:</span> ' + (systemInfo.security.ssl_enabled ? 'Yes' : 'No') + '</div>';
            html += '<div class="info-item"><span>File Editor Disabled:</span> ' + (systemInfo.security.file_editor_disabled ? 'Yes' : 'No') + '</div>';
            html += '<div class="info-item"><span>WP Config Secure:</span> ' + (systemInfo.security.wp_config_secure ? 'Yes' : 'No') + '</div>';
            html += '<div class="info-item"><span>Directory Indexes:</span> ' + (systemInfo.security.directory_indexes_disabled ? 'Disabled' : 'Enabled') + '</div>';
            html += '<div class="info-item"><span>XML-RPC:</span> ' + (systemInfo.security.xmlrpc_enabled ? 'Enabled' : 'Disabled') + '</div>';
            html += '</div>';
            html += '</div>';
            
            html += '</div>';
            
            $('#system-info-modal .secure-aura-modal-body').html(html);
        },

        /**
         * Initialize Tooltips
         */
        initTooltips: function() {
            $('[data-tooltip]').hover(
                function() {
                    var tooltipText = $(this).data('tooltip');
                    var $tooltip = $('<div class="secure-aura-tooltip">' + tooltipText + '</div>');
                    $('body').append($tooltip);
                    
                    var offset = $(this).offset();
                    $tooltip.css({
                        top: offset.top - $tooltip.outerHeight() - 10,
                        left: offset.left + ($(this).outerWidth() / 2) - ($tooltip.outerWidth() / 2)
                    });
                },
                function() {
                    $('.secure-aura-tooltip').remove();
                }
            );
        },

        /**
         * Initialize Charts (placeholder for dashboard charts)
         */
        initCharts: function() {
            // Chart initialization will be handled by dashboard.js
        },

        /**
         * Start Real-time Updates
         */
        startRealTimeUpdates: function() {
            var self = this;
            
            // Update every 30 seconds
            this.config.intervals.realTime = setInterval(function() {
                self.updateRealTimeData();
            }, 30000);
        },

        /**
         * Update Real-time Data
         */
        updateRealTimeData: function() {
            var self = this;
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_get_realtime_data',
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success) {
                        self.updateDashboardCounters(response.data);
                    }
                },
                error: function() {
                    // Silently fail for real-time updates
                }
            });
        },

        /**
         * Update Dashboard Counters
         */
        updateDashboardCounters: function(data) {
            // Update threat counter
            if (data.threats_blocked !== undefined) {
                $('.threats-blocked-count').text(data.threats_blocked);
            }
            
            // Update scan status
            if (data.last_scan) {
                $('.last-scan-time').text(data.last_scan);
            }
            
            // Update security score
            if (data.security_score !== undefined) {
                $('.security-score-value').text(data.security_score + '%');
                this.updateSecurityScoreBar(data.security_score);
            }
            
            // Update recent activities
            if (data.recent_activities) {
                this.updateRecentActivities(data.recent_activities);
            }
        },

        /**
         * Update Security Score Bar
         */
        updateSecurityScoreBar: function(score) {
            var $scoreBar = $('.security-score-bar .score-fill');
            var color = score >= 80 ? '#00a32a' : score >= 60 ? '#dba617' : '#d63638';
            
            $scoreBar.css({
                'width': score + '%',
                'background-color': color
            });
        },

        /**
         * Update Recent Activities
         */
        updateRecentActivities: function(activities) {
            var $container = $('.recent-activities-list');
            if (!$container.length) return;
            
            var html = '';
            activities.forEach(function(activity) {
                html += '<div class="activity-item">';
                html += '<span class="activity-time">' + activity.time + '</span>';
                html += '<span class="activity-message">' + activity.message + '</span>';
                html += '</div>';
            });
            
            $container.html(html);
        },

        /**
         * Refresh Dashboard
         */
        refreshDashboard: function() {
            var self = this;
            
            $('.refresh-dashboard').addClass('loading');
            this.showNotification('info', 'Refreshing dashboard...');
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_refresh_dashboard',
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success) {
                        // Reload the page to get fresh data
                        window.location.reload();
                    } else {
                        self.showNotification('error', 'Failed to refresh dashboard.');
                    }
                },
                error: function() {
                    self.showNotification('error', 'Network error occurred while refreshing dashboard.');
                },
                complete: function() {
                    $('.refresh-dashboard').removeClass('loading');
                }
            });
        },

        /**
         * Show Notification
         */
        showNotification: function(type, message, duration) {
            duration = duration || 5000;
            
            var $notification = $('<div class="secure-aura-notification ' + type + '">' + message + '</div>');
            
            // Remove existing notifications of same type
            $('.secure-aura-notification.' + type).remove();
            
            // Add to page
            $('body').append($notification);
            
            // Position notification
            this.positionNotification($notification);
            
            // Show notification
            setTimeout(function() {
                $notification.addClass('show');
            }, 100);
            
            // Auto hide
            setTimeout(function() {
                $notification.removeClass('show');
                setTimeout(function() {
                    $notification.remove();
                }, 300);
            }, duration);
        },

        /**
         * Position Notification
         */
        positionNotification: function($notification) {
            var notifications = $('.secure-aura-notification').length;
            var topOffset = 20 + (notifications * 70);
            
            $notification.css({
                position: 'fixed',
                top: topOffset + 'px',
                right: '20px',
                zIndex: 999999
            });
        },

        /**
         * Stop Security Scan
         */
        stopSecurityScan: function() {
            var self = this;
            
            if (!confirm('Are you sure you want to stop the security scan?')) {
                return;
            }
            
            $.ajax({
                url: this.config.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'secure_aura_stop_scan',
                    nonce: this.config.nonce
                },
                success: function(response) {
                    if (response.success) {
                        self.showNotification('info', 'Security scan stopped.');
                        self.stopScanProgressMonitoring();
                        self.closeModal('scan-progress-modal');
                    } else {
                        self.showNotification('error', 'Failed to stop security scan.');
                    }
                },
                error: function() {
                    self.showNotification('error', 'Network error occurred while stopping scan.');
                }
            });
        },

        /**
         * Validate IP Address
         */
        validateIP: function(ip) {
            var ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            return ipRegex.test(ip);
        },

        /**
         * Format File Size
         */
        formatFileSize: function(bytes) {
            if (bytes === 0) return '0 Bytes';
            
            var k = 1024;
            var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            var i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },

        /**
         * Format Date
         */
        formatDate: function(dateString) {
            var date = new Date(dateString);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        },

        /**
         * Cleanup on page unload
         */
        cleanup: function() {
            // Clear all intervals
            Object.keys(this.config.intervals).forEach(function(key) {
                clearInterval(this.config.intervals[key]);
            }.bind(this));
            
            // Remove event listeners
            $(document).off('.secureAura');
        }
    };

    /**
     * Initialize when document is ready
     */
    $(document).ready(function() {
        SecureAuraAdmin.init();
    });

    /**
     * Cleanup when page unloads
     */
    $(window).on('beforeunload', function() {
        SecureAuraAdmin.cleanup();
    });

})(jQuery);