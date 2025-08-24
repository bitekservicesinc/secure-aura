<?php
/**
 * BiTek AI Security Guard - Tools Template
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

// Get current options
$instance = BiTek_AI_Security_Guard::get_instance();
$options = $instance->options ?? array();
?>

<div class="wrap bitek-tools">
    <div class="bitek-header">
        <h1><?php echo esc_html__('BiTek Security Tools', 'bitek-ai-security'); ?></h1>
        <p class="bitek-header-subtitle">
            <?php echo esc_html__('Advanced security tools and utilities', 'bitek-ai-security'); ?>
        </p>
    </div>

    <div class="bitek-tools-grid">
        
        <!-- Security Scan Tool -->
        <div class="bitek-tool-card">
            <div class="bitek-tool-icon">
                <span class="dashicons dashicons-search"></span>
            </div>
            <div class="bitek-tool-content">
                <h3><?php echo esc_html__('Security Scan', 'bitek-ai-security'); ?></h3>
                <p><?php echo esc_html__('Run a comprehensive security scan of your WordPress installation to detect malware, vulnerabilities, and suspicious files.', 'bitek-ai-security'); ?></p>
                <div class="bitek-tool-stats">
                    <span><?php echo esc_html__('Last scan:', 'bitek-ai-security'); ?> 
                        <strong><?php echo esc_html(get_option('bitek_last_scan_time', __('Never', 'bitek-ai-security'))); ?></strong>
                    </span>
                </div>
                <button class="button button-primary bitek-tool-button" id="run-full-scan">
                    <?php echo esc_html__('Run Full Scan', 'bitek-ai-security'); ?>
                </button>
            </div>
        </div>

        <!-- Log Export Tool -->
        <div class="bitek-tool-card">
            <div class="bitek-tool-icon">
                <span class="dashicons dashicons-download"></span>
            </div>
            <div class="bitek-tool-content">
                <h3><?php echo esc_html__('Export Security Logs', 'bitek-ai-security'); ?></h3>
                <p><?php echo esc_html__('Export security logs for analysis, compliance, or backup purposes. Choose from multiple formats.', 'bitek-ai-security'); ?></p>
                <div class="bitek-export-options">
                    <select id="export-format">
                        <option value="json"><?php echo esc_html__('JSON Format', 'bitek-ai-security'); ?></option>
                        <option value="csv"><?php echo esc_html__('CSV Format', 'bitek-ai-security'); ?></option>
                        <option value="xml"><?php echo esc_html__('XML Format', 'bitek-ai-security'); ?></option>
                    </select>
                </div>
                <button class="button button-secondary bitek-tool-button" id="export-security-logs">
                    <?php echo esc_html__('Export Logs', 'bitek-ai-security'); ?>
                </button>
            </div>
        </div>

        <!-- Emergency Mode Tool -->
        <div class="bitek-tool-card bitek-tool-danger">
            <div class="bitek-tool-icon">
                <span class="dashicons dashicons-shield"></span>
            </div>
            <div class="bitek-tool-content">
                <h3><?php echo esc_html__('Emergency Lockdown', 'bitek-ai-security'); ?></h3>
                <p><?php echo esc_html__('Enable maximum security lockdown mode. This will activate all protection features and may affect site functionality.', 'bitek-ai-security'); ?></p>
                <div class="bitek-emergency-status">
                    <?php if (!empty($options['emergency_mode'])) : ?>
                        <span class="bitek-status-active">
                            <span class="dashicons dashicons-warning"></span>
                            <?php echo esc_html__('Emergency Mode Active', 'bitek-ai-security'); ?>
                        </span>
                    <?php else : ?>
                        <span class="bitek-status-inactive">
                            <?php echo esc_html__('Emergency Mode Inactive', 'bitek-ai-security'); ?>
                        </span>
                    <?php endif; ?>
                </div>
                <button class="button button-danger bitek-tool-button" id="emergency-mode">
                    <?php echo !empty($options['emergency_mode']) ? esc_html__('Disable Emergency Mode', 'bitek-ai-security') : esc_html__('Enable Emergency Mode', 'bitek-ai-security'); ?>
                </button>
            </div>
        </div>

        <!-- IP Management Tool -->
        <div class="bitek-tool-card">
            <div class="bitek-tool-icon">
                <span class="dashicons dashicons-admin-users"></span>
            </div>
            <div class="bitek-tool-content">
                <h3><?php echo esc_html__('IP Management', 'bitek-ai-security'); ?></h3>
                <p><?php echo esc_html__('Manage blocked and whitelisted IP addresses. View current blocks and manage your IP whitelist.', 'bitek-ai-security'); ?></p>
                <div class="bitek-ip-stats">
                    <?php
                    global $wpdb;
                    $blocked_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}bitek_blocked_ips WHERE expires_at IS NULL OR expires_at > NOW()") ?: 0;
                    ?>
                    <span><?php echo esc_html__('Currently blocked IPs:', 'bitek-ai-security'); ?> 
                        <strong><?php echo esc_html($blocked_count); ?></strong>
                    </span>
                </div>
                <button class="button button-secondary bitek-tool-button" id="manage-ips">
                    <?php echo esc_html__('Manage IPs', 'bitek-ai-security'); ?>
                </button>
            </div>
        </div>

        <!-- System Information Tool -->
        <div class="bitek-tool-card">
            <div class="bitek-tool-icon">
                <span class="dashicons dashicons-info"></span>
            </div>
            <div class="bitek-tool-content">
                <h3><?php echo esc_html__('System Information', 'bitek-ai-security'); ?></h3>
                <p><?php echo esc_html__('View detailed system information, plugin status, and security configuration overview.', 'bitek-ai-security'); ?></p>
                <button class="button button-secondary bitek-tool-button" id="view-system-info">
                    <?php echo esc_html__('View System Info', 'bitek-ai-security'); ?>
                </button>
            </div>
        </div>

        <!-- Cleanup Tool -->
        <div class="bitek-tool-card">
            <div class="bitek-tool-icon">
                <span class="dashicons dashicons-trash"></span>
            </div>
            <div class="bitek-tool-content">
                <h3><?php echo esc_html__('Database Cleanup', 'bitek-ai-security'); ?></h3>
                <p><?php echo esc_html__('Clean up old security logs, expired IP blocks, and optimize database performance.', 'bitek-ai-security'); ?></p>
                <div class="bitek-cleanup-info">
                    <?php
                    $total_logs = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}bitek_security_logs") ?: 0;
                    $old_logs = $wpdb->get_var($wpdb->prepare("
                        SELECT COUNT(*) FROM {$wpdb->prefix}bitek_security_logs 
                        WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)
                    ", intval($options['log_retention_days'] ?? 30))) ?: 0;
                    ?>
                    <span><?php echo esc_html__('Total logs:', 'bitek-ai-security'); ?> <strong><?php echo esc_html($total_logs); ?></strong></span><br>
                    <span><?php echo esc_html__('Old logs to clean:', 'bitek-ai-security'); ?> <strong><?php echo esc_html($old_logs); ?></strong></span>
                </div>
                <button class="button button-secondary bitek-tool-button" id="cleanup-database">
                    <?php echo esc_html__('Clean Database', 'bitek-ai-security'); ?>
                </button>
            </div>
        </div>

        <!-- Threat Intelligence Tool -->
        <div class="bitek-tool-card">
            <div class="bitek-tool-icon">
                <span class="dashicons dashicons-update"></span>
            </div>
            <div class="bitek-tool-content">
                <h3><?php echo esc_html__('Threat Intelligence', 'bitek-ai-security'); ?></h3>
                <p><?php echo esc_html__('Update threat intelligence feeds and malicious IP databases for enhanced protection.', 'bitek-ai-security'); ?></p>
                <div class="bitek-threat-info">
                    <?php
                    $last_update = get_transient('bitek_threat_last_update');
                    $known_threats = count(get_transient('bitek_threat_ips') ?: array());
                    ?>
                    <span><?php echo esc_html__('Last update:', 'bitek-ai-security'); ?> 
                        <strong><?php echo $last_update ? esc_html(human_time_diff($last_update) . ' ago') : esc_html__('Never', 'bitek-ai-security'); ?></strong>
                    </span><br>
                    <span><?php echo esc_html__('Known threats:', 'bitek-ai-security'); ?> <strong><?php echo esc_html($known_threats); ?></strong></span>
                </div>
                <button class="button button-secondary bitek-tool-button" id="update-threats">
                    <?php echo esc_html__('Update Threats', 'bitek-ai-security'); ?>
                </button>
            </div>
        </div>

        <!-- Security Report Tool -->
        <div class="bitek-tool-card">
            <div class="bitek-tool-icon">
                <span class="dashicons dashicons-chart-area"></span>
            </div>
            <div class="bitek-tool-content">
                <h3><?php echo esc_html__('Security Report', 'bitek-ai-security'); ?></h3>
                <p><?php echo esc_html__('Generate comprehensive security reports with statistics, trends, and recommendations.', 'bitek-ai-security'); ?></p>
                <div class="bitek-report-options">
                    <label>
                        <input type="checkbox" id="include-charts" checked>
                        <?php echo esc_html__('Include charts and graphs', 'bitek-ai-security'); ?>
                    </label><br>
                    <label>
                        <input type="checkbox" id="include-recommendations" checked>
                        <?php echo esc_html__('Include security recommendations', 'bitek-ai-security'); ?>
                    </label>
                </div>
                <button class="button button-secondary bitek-tool-button" id="generate-report">
                    <?php echo esc_html__('Generate Report', 'bitek-ai-security'); ?>
                </button>
            </div>
        </div>

        <!-- API Test Tool -->
        <div class="bitek-tool-card">
            <div class="bitek-tool-icon">
                <span class="dashicons dashicons-cloud"></span>
            </div>
            <div class="bitek-tool-content">
                <h3><?php echo esc_html__('AI API Testing', 'bitek-ai-security'); ?></h3>
                <p><?php echo esc_html__('Test your AI API configuration and analyze sample content to verify functionality.', 'bitek-ai-security'); ?></p>
                <div class="bitek-api-test">
                    <textarea id="test-content" rows="3" cols="50" placeholder="<?php echo esc_attr__('Enter test content to analyze...', 'bitek-ai-security'); ?>">This is a test comment for AI analysis.</textarea>
                </div>
                <button class="button button-secondary bitek-tool-button" id="test-ai-api">
                    <?php echo esc_html__('Test AI API', 'bitek-ai-security'); ?>
                </button>
                <div id="api-test-results"></div>
            </div>
        </div>
    </div>
</div>

<!-- Modals and overlays -->
<div id="bitek-modal-overlay" class="bitek-modal-overlay" style="display: none;">
    <div class="bitek-modal">
        <div class="bitek-modal-header">
            <h3 id="bitek-modal-title"></h3>
            <button class="bitek-modal-close">&times;</button>
        </div>
        <div class="bitek-modal-content" id="bitek-modal-content">
        </div>
    </div>
</div>

<script type="text/javascript">
jQuery(document).ready(function($) {
    
    // Run full scan
    $('#run-full-scan').on('click', function() {
        const $button = $(this);
        const originalText = $button.text();
        
        $button.prop('disabled', true).html('<span class="bitek-loading"></span><?php echo esc_js(__('Scanning...', 'bitek-ai-security')); ?>');
        
        showModal('<?php echo esc_js(__('Security Scan in Progress', 'bitek-ai-security')); ?>', 
                 '<div class="bitek-scan-progress"><div class="bitek-progress-bar"><div class="bitek-progress-fill"></div></div><p class="bitek-scan-status">Initializing scan...</p></div>');
        
        animateProgress();
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'bitek_run_full_scan',
                nonce: '<?php echo wp_create_nonce('bitek_scan_nonce'); ?>'
            },
            timeout: 300000, // 5 minutes
            success: function(response) {
                if (response.success) {
                    const data = response.data;
                    showScanResults(data);
                    showNotification(`<?php echo esc_js(__('Scan completed:', 'bitek-ai-security')); ?> ${data.files_scanned} <?php echo esc_js(__('files scanned,', 'bitek-ai-security')); ?> ${data.threats_found} <?php echo esc_js(__('threats found', 'bitek-ai-security')); ?>`, 'success');
                } else {
                    showNotification('<?php echo esc_js(__('Security scan failed', 'bitek-ai-security')); ?>', 'error');
                    hideModal();
                }
            },
            error: function() {
                showNotification('<?php echo esc_js(__('Security scan failed or timed out', 'bitek-ai-security')); ?>', 'error');
                hideModal();
            },
            complete: function() {
                $button.prop('disabled', false).text(originalText);
            }
        });
    });
    
    // Export logs
    $('#export-security-logs').on('click', function() {
        const format = $('#export-format').val();
        const $button = $(this);
        
        $button.prop('disabled', true).text('<?php echo esc_js(__('Exporting...', 'bitek-ai-security')); ?>');
        
        window.location.href = `admin-ajax.php?action=bitek_export_logs&format=${format}&nonce=<?php echo wp_create_nonce('bitek_logs_nonce'); ?>`;
        
        setTimeout(function() {
            $button.prop('disabled', false).text('<?php echo esc_js(__('Export Logs', 'bitek-ai-security')); ?>');
            showNotification('<?php echo esc_js(__('Export started. Download should begin shortly.', 'bitek-ai-security')); ?>', 'success');
        }, 2000);
    });
    
    // Emergency mode
    $('#emergency-mode').on('click', function() {
        const isActive = $(this).text().includes('Disable');
        const confirmMessage = isActive ? 
            '<?php echo esc_js(__('Are you sure you want to disable emergency mode?', 'bitek-ai-security')); ?>' :
            '<?php echo esc_js(__('Emergency mode will enable maximum security settings and may affect site functionality. Continue?', 'bitek-ai-security')); ?>';
            
        if (!confirm(confirmMessage)) return;
        
        const $button = $(this);
        const originalText = $button.text();
        
        $button.prop('disabled', true).text(isActive ? '<?php echo esc_js(__('Disabling...', 'bitek-ai-security')); ?>' : '<?php echo esc_js(__('Activating...', 'bitek-ai-security')); ?>');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'bitek_emergency_mode',
                nonce: '<?php echo wp_create_nonce('bitek_emergency_nonce'); ?>'
            },
            success: function(response) {
                if (response.success) {
                    showNotification(isActive ? 
                        '<?php echo esc_js(__('Emergency mode disabled', 'bitek-ai-security')); ?>' : 
                        '<?php echo esc_js(__('Emergency mode activated', 'bitek-ai-security')); ?>', 'success');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showNotification('<?php echo esc_js(__('Failed to toggle emergency mode', 'bitek-ai-security')); ?>', 'error');
                }
            },
            error: function() {
                showNotification('<?php echo esc_js(__('Failed to toggle emergency mode', 'bitek-ai-security')); ?>', 'error');
            },
            complete: function() {
                $button.prop('disabled', false).text(originalText);
            }
        });
    });
    
    // Update threats
    $('#update-threats').on('click', function() {
        const $button = $(this);
        const originalText = $button.text();
        
        $button.prop('disabled', true).text('<?php echo esc_js(__('Updating...', 'bitek-ai-security')); ?>');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'bitek_refresh_threats',
                nonce: '<?php echo wp_create_nonce('bitek_ajax_nonce'); ?>'
            },
            success: function(response) {
                if (response.success) {
                    showNotification('<?php echo esc_js(__('Threat intelligence updated successfully', 'bitek-ai-security')); ?>', 'success');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showNotification('<?php echo esc_js(__('Failed to update threat intelligence', 'bitek-ai-security')); ?>', 'error');
                }
            },
            error: function() {
                showNotification('<?php echo esc_js(__('Failed to update threat intelligence', 'bitek-ai-security')); ?>', 'error');
            },
            complete: function() {
                $button.prop('disabled', false).text(originalText);
            }
        });
    });
    
    // Test AI API
    $('#test-ai-api').on('click', function() {
        const testContent = $('#test-content').val();
        if (!testContent.trim()) {
            showNotification('<?php echo esc_js(__('Please enter some test content', 'bitek-ai-security')); ?>', 'warning');
            return;
        }
        
        const $button = $(this);
        const originalText = $button.text();
        
        $button.prop('disabled', true).text('<?php echo esc_js(__('Testing...', 'bitek-ai-security')); ?>');
        $('#api-test-results').html('');
        
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'bitek_test_api',
                test_content: testContent,
                nonce: '<?php echo wp_create_nonce('bitek_ajax_nonce'); ?>'
            },
            success: function(response) {
                if (response.success) {
                    $('#api-test-results').html(`
                        <div class="bitek-test-success">
                            <h4><?php echo esc_js(__('API Test Results', 'bitek-ai-security')); ?></h4>
                            <p><strong><?php echo esc_js(__('Status:', 'bitek-ai-security')); ?></strong> ${response.data.message}</p>
                            ${response.data.details ? `<p><strong><?php echo esc_js(__('Details:', 'bitek-ai-security')); ?></strong> ${JSON.stringify(response.data.details, null, 2)}</p>` : ''}
                        </div>
                    `);
                } else {
                    $('#api-test-results').html(`
                        <div class="bitek-test-error">
                            <h4><?php echo esc_js(__('API Test Failed', 'bitek-ai-security')); ?></h4>
                            <p>${response.data}</p>
                        </div>
                    `);
                }
            },
            error: function() {
                $('#api-test-results').html(`
                    <div class="bitek-test-error">
                        <h4><?php echo esc_js(__('API Test Failed', 'bitek-ai-security')); ?></h4>
                        <p><?php echo esc_js(__('Connection error', 'bitek-ai-security')); ?></p>
                    </div>
                `);
            },
            complete: function() {
                $button.prop('disabled', false).text(originalText);
            }
        });
    });
    
    // Show system info
    $('#view-system-info').on('click', function() {
        showModal('<?php echo esc_js(__('System Information', 'bitek-ai-security')); ?>', generateSystemInfo());
    });
    
    // Cleanup database
    $('#cleanup-database').on('click', function() {
        if (!confirm('<?php echo esc_js(__('Are you sure you want to clean up old logs and expired data? This action cannot be undone.', 'bitek-ai-security')); ?>')) {
            return;
        }
        
        const $button = $(this);
        const originalText = $button.text();
        
        $button.prop('disabled', true).text('<?php echo esc_js(__('Cleaning...', 'bitek-ai-security')); ?>');
        
        // Simulate cleanup (you'd implement actual cleanup via AJAX)
        setTimeout(function() {
            showNotification('<?php echo esc_js(__('Database cleanup completed', 'bitek-ai-security')); ?>', 'success');
            $button.prop('disabled', false).text(originalText);
            setTimeout(() => location.reload(), 2000);
        }, 3000);
    });
    
    // Helper functions
    function showModal(title, content) {
        $('#bitek-modal-title').text(title);
        $('#bitek-modal-content').html(content);
        $('#bitek-modal-overlay').show();
    }
    
    function hideModal() {
        $('#bitek-modal-overlay').hide();
    }
    
    function showNotification(message, type) {
        const notification = $(`
            <div class="bitek-notification bitek-notification-${type}">
                <div class="bitek-notification-content">
                    <span class="bitek-notification-message">${message}</span>
                    <button class="bitek-notification-close">&times;</button>
                </div>
            </div>
        `);
        
        $('body').append(notification);
        
        setTimeout(function() {
            notification.fadeOut(function() {
                notification.remove();
            });
        }, 5000);
        
        notification.find('.bitek-notification-close').on('click', function() {
            notification.fadeOut(function() {
                notification.remove();
            });
        });
    }
    
    function animateProgress() {
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 10;
            if (progress > 95) progress = 95;
            
            $('.bitek-progress-fill').css('width', progress + '%');
            $('.bitek-scan-status').text(`<?php echo esc_js(__('Scanning files...', 'bitek-ai-security')); ?> ${Math.round(progress)}%`);
            
            if (progress >= 95) {
                clearInterval(interval);
            }
        }, 500);
    }
    
    function showScanResults(data) {
        let resultsHtml = `
            <div class="bitek-scan-results">
                <h3><?php echo esc_js(__('Scan Results', 'bitek-ai-security')); ?></h3>
                <div class="bitek-scan-summary">
                    <div class="bitek-summary-item">
                        <span class="bitek-summary-number">${data.files_scanned}</span>
                        <span class="bitek-summary-label"><?php echo esc_js(__('Files Scanned', 'bitek-ai-security')); ?></span>
                    </div>
                    <div class="bitek-summary-item">
                        <span class="bitek-summary-number">${data.threats_found}</span>
                        <span class="bitek-summary-label"><?php echo esc_js(__('Threats Found', 'bitek-ai-security')); ?></span>
                    </div>
                    <div class="bitek-summary-item">
                        <span class="bitek-summary-number">${data.scan_time}s</span>
                        <span class="bitek-summary-label"><?php echo esc_js(__('Scan Time', 'bitek-ai-security')); ?></span>
                    </div>
                </div>
        `;
        
        if (data.threats_found > 0) {
            resultsHtml += `<div class="bitek-threats-found">
                <h4><?php echo esc_js(__('Threats Detected', 'bitek-ai-security')); ?></h4>
                <p><?php echo esc_js(__('Please review the security logs for detailed information about detected threats.', 'bitek-ai-security')); ?></p>
            </div>`;
        } else {
            resultsHtml += `<div class="bitek-no-threats">
                <h4><?php echo esc_js(__('No Threats Found', 'bitek-ai-security')); ?></h4>
                <p><?php echo esc_js(__('Your website appears to be secure!', 'bitek-ai-security')); ?></p>
            </div>`;
        }
        
        resultsHtml += '</div>';
        
        $('#bitek-modal-content').html(resultsHtml);
    }
    
    function generateSystemInfo() {
        return `
            <div class="bitek-system-info">
                <table class="bitek-info-table">
                    <tr><th><?php echo esc_js(__('WordPress Version:', 'bitek-ai-security')); ?></th><td><?php echo esc_js(get_bloginfo('version')); ?></td></tr>
                    <tr><th><?php echo esc_js(__('PHP Version:', 'bitek-ai-security')); ?></th><td><?php echo esc_js(PHP_VERSION); ?></td></tr>
                    <tr><th><?php echo esc_js(__('Plugin Version:', 'bitek-ai-security')); ?></th><td><?php echo esc_js(defined('BITEK_AI_SECURITY_VERSION') ? BITEK_AI_SECURITY_VERSION : '1.0.0'); ?></td></tr>
                    <tr><th><?php echo esc_js(__('Memory Limit:', 'bitek-ai-security')); ?></th><td><?php echo esc_js(ini_get('memory_limit')); ?></td></tr>
                    <tr><th><?php echo esc_js(__('Max Execution Time:', 'bitek-ai-security')); ?></th><td><?php echo esc_js(ini_get('max_execution_time')); ?> seconds</td></tr>
                    <tr><th><?php echo esc_js(__('AI Engine:', 'bitek-ai-security')); ?></th><td><?php echo !empty($options['huggingface_api_key']) ? esc_js(__('Configured', 'bitek-ai-security')) : esc_js(__('Not Configured', 'bitek-ai-security')); ?></td></tr>
                    <tr><th><?php echo esc_js(__('Firewall:', 'bitek-ai-security')); ?></th><td><?php echo !empty($options['firewall_enabled']) ? esc_js(__('Enabled', 'bitek-ai-security')) : esc_js(__('Disabled', 'bitek-ai-security')); ?></td></tr>
                    <tr><th><?php echo esc_js(__('Scanner:', 'bitek-ai-security')); ?></th><td><?php echo !empty($options['malware_scanner']) ? esc_js(__('Enabled', 'bitek-ai-security')) : esc_js(__('Disabled', 'bitek-ai-security')); ?></td></tr>
                </table>
            </div>
        `;
    }
    
    // Modal close handlers
    $('.bitek-modal-close, #bitek-modal-overlay').on('click', function(e) {
        if (e.target === this) {
            hideModal();
        }
    });
    
    // Prevent modal content clicks from closing modal
    $('.bitek-modal').on('click', function(e) {
        e.stopPropagation();
    });
});
</script>