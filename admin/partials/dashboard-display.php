<?php
/**
 * Provide a admin area view for the plugin dashboard
 *
 * @link       https://secureaura.pro
 * @since      3.0.0
 *
 * @package    SecureAura
 * @subpackage SecureAura/admin/partials
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

// Get current security status
$security_status = $this->get_security_status();
$scan_status = $this->get_scan_status();
$threat_stats = $this->get_threat_statistics();
$license_type = get_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE);
$emergency_mode = get_option('secure_aura_emergency_mode', false);
?>

<div class="wrap secure-aura-dashboard">
    
    <!-- Header Section -->
    <div class="secure-aura-header">
        <div class="secure-aura-header-content">
            <div class="secure-aura-logo">
                <img src="<?php echo SECURE_AURA_ASSETS_URL; ?>images/logo.svg" alt="SecureAura" width="40" height="40">
                <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
                <span class="secure-aura-version">v<?php echo SECURE_AURA_VERSION; ?></span>
            </div>
            
            <div class="secure-aura-header-actions">
                <?php if ($emergency_mode): ?>
                    <div class="secure-aura-emergency-indicator">
                        <span class="dashicons dashicons-warning"></span>
                        <?php _e('Emergency Mode Active', 'secure-aura'); ?>
                    </div>
                <?php endif; ?>
                
                <button type="button" class="button button-primary" id="run-quick-scan">
                    <span class="dashicons dashicons-search"></span>
                    <?php _e('Quick Scan', 'secure-aura'); ?>
                </button>
                
                <button type="button" class="button button-secondary" id="emergency-mode-toggle">
                    <span class="dashicons dashicons-shield-alt"></span>
                    <?php echo $emergency_mode ? __('Disable Emergency', 'secure-aura') : __('Emergency Mode', 'secure-aura'); ?>
                </button>
            </div>
        </div>
    </div>

    <!-- Security Status Cards -->
    <div class="secure-aura-status-grid">
        
        <!-- Overall Security Score Card -->
        <div class="secure-aura-card secure-aura-security-score">
            <div class="secure-aura-card-header">
                <h3><?php _e('Security Score', 'secure-aura'); ?></h3>
                <span class="secure-aura-card-icon">
                    <span class="dashicons dashicons-shield-alt"></span>
                </span>
            </div>
            <div class="secure-aura-card-body">
                <div class="secure-aura-score-display">
                    <div class="secure-aura-score-circle" data-score="<?php echo $security_status['score']; ?>">
                        <span class="secure-aura-score-number"><?php echo $security_status['score']; ?></span>
                        <span class="secure-aura-score-percent">%</span>
                    </div>
                    <div class="secure-aura-score-details">
                        <p class="secure-aura-score-status <?php echo $security_status['status_class']; ?>">
                            <?php echo $security_status['status_text']; ?>
                        </p>
                        <p class="secure-aura-score-description">
                            <?php echo $security_status['description']; ?>
                        </p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Threats Blocked Card -->
        <div class="secure-aura-card secure-aura-threats-blocked">
            <div class="secure-aura-card-header">
                <h3><?php _e('Threats Blocked', 'secure-aura'); ?></h3>
                <span class="secure-aura-card-icon">
                    <span class="dashicons dashicons-warning"></span>
                </span>
            </div>
            <div class="secure-aura-card-body">
                <div class="secure-aura-stat-large">
                    <?php echo number_format($threat_stats['blocked_today']); ?>
                </div>
                <div class="secure-aura-stat-details">
                    <span class="secure-aura-stat-label"><?php _e('Today', 'secure-aura'); ?></span>
                    <span class="secure-aura-stat-change <?php echo $threat_stats['change_class']; ?>">
                        <span class="dashicons <?php echo $threat_stats['change_icon']; ?>"></span>
                        <?php echo $threat_stats['change_percent']; ?>%
                    </span>
                </div>
                <div class="secure-aura-stat-total">
                    <?php printf(__('Total: %s', 'secure-aura'), number_format($threat_stats['total_blocked'])); ?>
                </div>
            </div>
        </div>

        <!-- Last Scan Card -->
        <div class="secure-aura-card secure-aura-last-scan">
            <div class="secure-aura-card-header">
                <h3><?php _e('Last Security Scan', 'secure-aura'); ?></h3>
                <span class="secure-aura-card-icon">
                    <span class="dashicons dashicons-search"></span>
                </span>
            </div>
            <div class="secure-aura-card-body">
                <?php if ($scan_status['last_scan']): ?>
                    <div class="secure-aura-scan-info">
                        <div class="secure-aura-scan-date">
                            <?php echo human_time_diff(strtotime($scan_status['last_scan']), current_time('timestamp')); ?>
                            <?php _e('ago', 'secure-aura'); ?>
                        </div>
                        <div class="secure-aura-scan-results">
                            <span class="secure-aura-scan-files">
                                <?php printf(__('%s files scanned', 'secure-aura'), number_format($scan_status['files_scanned'])); ?>
                            </span>
                            <?php if ($scan_status['threats_found'] > 0): ?>
                                <span class="secure-aura-scan-threats threat-found">
                                    <?php printf(__('%d threats found', 'secure-aura'), $scan_status['threats_found']); ?>
                                </span>
                            <?php else: ?>
                                <span class="secure-aura-scan-threats no-threats">
                                    <?php _e('No threats found', 'secure-aura'); ?>
                                </span>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php else: ?>
                    <div class="secure-aura-no-scan">
                        <p><?php _e('No scans performed yet', 'secure-aura'); ?></p>
                        <button type="button" class="button button-primary" id="run-first-scan">
                            <?php _e('Run First Scan', 'secure-aura'); ?>
                        </button>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Active Protection Card -->
        <div class="secure-aura-card secure-aura-active-protection">
            <div class="secure-aura-card-header">
                <h3><?php _e('Active Protection', 'secure-aura'); ?></h3>
                <span class="secure-aura-card-icon">
                    <span class="dashicons dashicons-admin-generic"></span>
                </span>
            </div>
            <div class="secure-aura-card-body">
                <div class="secure-aura-protection-modules">
                    <?php
                    $modules = [
                        'firewall' => [
                            'name' => __('Quantum Firewall', 'secure-aura'),
                            'enabled' => get_option('secure_aura_quantum_firewall_enabled', true),
                            'pro' => false
                        ],
                        'scanner' => [
                            'name' => __('Real-time Scanner', 'secure-aura'),
                            'enabled' => get_option('secure_aura_real_time_scanning_enabled', true),
                            'pro' => false
                        ],
                        'ai_detection' => [
                            'name' => __('AI Threat Detection', 'secure-aura'),
                            'enabled' => get_option('secure_aura_ai_threat_detection_enabled', false),
                            'pro' => true
                        ],
                        'behavioral' => [
                            'name' => __('Behavioral Monitor', 'secure-aura'),
                            'enabled' => get_option('secure_aura_behavioral_monitoring_enabled', false),
                            'pro' => true
                        ]
                    ];

                    foreach ($modules as $key => $module):
                        $is_pro = $module['pro'] && $license_type === SECURE_AURA_LICENSE_FREE;
                    ?>
                        <div class="secure-aura-module <?php echo $module['enabled'] && !$is_pro ? 'enabled' : 'disabled'; ?>">
                            <span class="secure-aura-module-status">
                                <?php if ($is_pro): ?>
                                    <span class="dashicons dashicons-lock"></span>
                                <?php elseif ($module['enabled']): ?>
                                    <span class="dashicons dashicons-yes-alt"></span>
                                <?php else: ?>
                                    <span class="dashicons dashicons-dismiss"></span>
                                <?php endif; ?>
                            </span>
                            <span class="secure-aura-module-name">
                                <?php echo $module['name']; ?>
                                <?php if ($is_pro): ?>
                                    <span class="secure-aura-pro-badge">PRO</span>
                                <?php endif; ?>
                            </span>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Main Dashboard Content -->
    <div class="secure-aura-dashboard-main">
        
        <!-- Left Column -->
        <div class="secure-aura-dashboard-left">
            
            <!-- Real-time Activity Feed -->
            <div class="secure-aura-card secure-aura-activity-feed">
                <div class="secure-aura-card-header">
                    <h3><?php _e('Real-time Security Activity', 'secure-aura'); ?></h3>
                    <div class="secure-aura-card-actions">
                        <button type="button" class="button button-small" id="refresh-activity">
                            <span class="dashicons dashicons-update"></span>
                        </button>
                        <div class="secure-aura-live-indicator">
                            <span class="secure-aura-pulse"></span>
                            <?php _e('Live', 'secure-aura'); ?>
                        </div>
                    </div>
                </div>
                <div class="secure-aura-card-body">
                    <div class="secure-aura-activity-list" id="security-activity-feed">
                        <?php $this->render_activity_feed(); ?>
                    </div>
                </div>
            </div>

            <!-- Threat Intelligence -->
            <div class="secure-aura-card secure-aura-threat-intel">
                <div class="secure-aura-card-header">
                    <h3><?php _e('Threat Intelligence', 'secure-aura'); ?></h3>
                    <div class="secure-aura-card-actions">
                        <button type="button" class="button button-small" id="update-threat-intel">
                            <span class="dashicons dashicons-cloud"></span>
                            <?php _e('Update', 'secure-aura'); ?>
                        </button>
                    </div>
                </div>
                <div class="secure-aura-card-body">
                    <?php $this->render_threat_intelligence_summary(); ?>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="secure-aura-card secure-aura-quick-actions">
                <div class="secure-aura-card-header">
                    <h3><?php _e('Quick Actions', 'secure-aura'); ?></h3>
                </div>
                <div class="secure-aura-card-body">
                    <div class="secure-aura-actions-grid">
                        <button type="button" class="secure-aura-action-button" id="run-full-scan">
                            <span class="dashicons dashicons-search"></span>
                            <span class="secure-aura-action-label"><?php _e('Full Scan', 'secure-aura'); ?></span>
                        </button>
                        
                        <button type="button" class="secure-aura-action-button" id="check-file-integrity">
                            <span class="dashicons dashicons-admin-tools"></span>
                            <span class="secure-aura-action-label"><?php _e('File Integrity', 'secure-aura'); ?></span>
                        </button>
                        
                        <button type="button" class="secure-aura-action-button" id="update-firewall-rules">
                            <span class="dashicons dashicons-shield-alt"></span>
                            <span class="secure-aura-action-label"><?php _e('Update Rules', 'secure-aura'); ?></span>
                        </button>
                        
                        <button type="button" class="secure-aura-action-button" id="export-security-logs">
                            <span class="dashicons dashicons-download"></span>
                            <span class="secure-aura-action-label"><?php _e('Export Logs', 'secure-aura'); ?></span>
                        </button>
                        
                        <button type="button" class="secure-aura-action-button" id="cleanup-quarantine">
                            <span class="dashicons dashicons-trash"></span>
                            <span class="secure-aura-action-label"><?php _e('Clean Quarantine', 'secure-aura'); ?></span>
                        </button>
                        
                        <button type="button" class="secure-aura-action-button" id="test-email-notifications">
                            <span class="dashicons dashicons-email"></span>
                            <span class="secure-aura-action-label"><?php _e('Test Alerts', 'secure-aura'); ?></span>
                        </button>
                    </div>
                </div>
            </div>

        </div>

        <!-- Right Column -->
        <div class="secure-aura-dashboard-right">
            
            <!-- Security Analytics Chart -->
            <div class="secure-aura-card secure-aura-analytics">
                <div class="secure-aura-card-header">
                    <h3><?php _e('Security Analytics', 'secure-aura'); ?></h3>
                    <div class="secure-aura-card-actions">
                        <select id="analytics-timeframe" class="secure-aura-timeframe-select">
                            <option value="24h"><?php _e('Last 24 Hours', 'secure-aura'); ?></option>
                            <option value="7d" selected><?php _e('Last 7 Days', 'secure-aura'); ?></option>
                            <option value="30d"><?php _e('Last 30 Days', 'secure-aura'); ?></option>
                            <option value="90d"><?php _e('Last 90 Days', 'secure-aura'); ?></option>
                        </select>
                    </div>
                </div>
                <div class="secure-aura-card-body">
                    <canvas id="security-analytics-chart" width="400" height="200"></canvas>
                </div>
            </div>

            <!-- Geographic Threats Map -->
            <?php if ($license_type !== SECURE_AURA_LICENSE_FREE): ?>
            <div class="secure-aura-card secure-aura-geo-threats">
                <div class="secure-aura-card-header">
                    <h3><?php _e('Geographic Threats', 'secure-aura'); ?></h3>
                    <span class="secure-aura-pro-badge">PRO</span>
                </div>
                <div class="secure-aura-card-body">
                    <div id="threats-world-map" class="secure-aura-world-map"></div>
                    <div class="secure-aura-geo-stats">
                        <?php $this->render_geographic_threat_stats(); ?>
                    </div>
                </div>
            </div>
            <?php else: ?>
            <div class="secure-aura-card secure-aura-upgrade-prompt">
                <div class="secure-aura-card-header">
                    <h3><?php _e('Geographic Threats', 'secure-aura'); ?></h3>
                    <span class="secure-aura-pro-badge">PRO</span>
                </div>
                <div class="secure-aura-card-body">
                    <div class="secure-aura-upgrade-content">
                        <div class="secure-aura-upgrade-icon">
                            <span class="dashicons dashicons-location-alt"></span>
                        </div>
                        <h4><?php _e('Track Global Threats', 'secure-aura'); ?></h4>
                        <p><?php _e('Monitor threats by country, analyze attack patterns, and strengthen your defenses with geographic intelligence.', 'secure-aura'); ?></p>
                        <a href="https://secureaura.pro/upgrade/" target="_blank" class="button button-primary">
                            <?php _e('Upgrade to Pro', 'secure-aura'); ?>
                        </a>
                    </div>
                </div>
            </div>
            <?php endif; ?>

            <!-- System Health Monitor -->
            <div class="secure-aura-card secure-aura-system-health">
                <div class="secure-aura-card-header">
                    <h3><?php _e('System Health', 'secure-aura'); ?></h3>
                    <div class="secure-aura-health-indicator <?php echo $this->get_system_health_status(); ?>">
                        <span class="secure-aura-health-dot"></span>
                    </div>
                </div>
                <div class="secure-aura-card-body">
                    <div class="secure-aura-health-metrics">
                        <?php $this->render_system_health_metrics(); ?>
                    </div>
                </div>
            </div>

            <!-- Recent Security Events -->
            <div class="secure-aura-card secure-aura-recent-events">
                <div class="secure-aura-card-header">
                    <h3><?php _e('Recent Security Events', 'secure-aura'); ?></h3>
                    <div class="secure-aura-card-actions">
                        <a href="<?php echo admin_url('admin.php?page=secure-aura-logs'); ?>" class="button button-small">
                            <?php _e('View All', 'secure-aura'); ?>
                        </a>
                    </div>
                </div>
                <div class="secure-aura-card-body">
                    <div class="secure-aura-events-list">
                        <?php $this->render_recent_security_events(); ?>
                    </div>
                </div>
            </div>

        </div>

    </div>

    <!-- License Information Footer (for free users) -->
    <?php if ($license_type === SECURE_AURA_LICENSE_FREE): ?>
    <div class="secure-aura-license-footer">
        <div class="secure-aura-license-info">
            <div class="secure-aura-license-content">
                <h4><?php _e('You\'re using SecureAura Free', 'secure-aura'); ?></h4>
                <p><?php _e('Upgrade to Pro for AI-powered threat detection, behavioral analysis, advanced reporting, and priority support.', 'secure-aura'); ?></p>
                <div class="secure-aura-license-features">
                    <span class="secure-aura-feature">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <?php _e('AI Threat Detection', 'secure-aura'); ?>
                    </span>
                    <span class="secure-aura-feature">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <?php _e('Behavioral Analysis', 'secure-aura'); ?>
                    </span>
                    <span class="secure-aura-feature">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <?php _e('Advanced Reporting', 'secure-aura'); ?>
                    </span>
                    <span class="secure-aura-feature">
                        <span class="dashicons dashicons-yes-alt"></span>
                        <?php _e('Priority Support', 'secure-aura'); ?>
                    </span>
                </div>
            </div>
            <div class="secure-aura-license-actions">
                <a href="https://secureaura.pro/upgrade/" target="_blank" class="button button-primary button-hero">
                    <?php _e('Upgrade to Pro', 'secure-aura'); ?>
                </a>
                <a href="https://secureaura.pro/features/" target="_blank" class="button button-secondary">
                    <?php _e('Compare Features', 'secure-aura'); ?>
                </a>
            </div>
        </div>
    </div>
    <?php endif; ?>

</div>

<!-- Scan Progress Modal -->
<div id="scan-progress-modal" class="secure-aura-modal" style="display: none;">
    <div class="secure-aura-modal-overlay"></div>
    <div class="secure-aura-modal-container">
        <div class="secure-aura-modal-header">
            <h3><?php _e('Security Scan in Progress', 'secure-aura'); ?></h3>
        </div>
        <div class="secure-aura-modal-body">
            <div class="secure-aura-scan-progress">
                <div class="secure-aura-progress-bar">
                    <div class="secure-aura-progress-fill" style="width: 0%;"></div>
                </div>
                <div class="secure-aura-progress-info">
                    <span id="scan-progress-text"><?php _e('Initializing scan...', 'secure-aura'); ?></span>
                    <span id="scan-progress-percent">0%</span>
                </div>
                <div class="secure-aura-scan-details">
                    <div class="secure-aura-scan-stat">
                        <span class="secure-aura-stat-label"><?php _e('Files Scanned:', 'secure-aura'); ?></span>
                        <span id="files-scanned-count">0</span>
                    </div>
                    <div class="secure-aura-scan-stat">
                        <span class="secure-aura-stat-label"><?php _e('Threats Found:', 'secure-aura'); ?></span>
                        <span id="threats-found-count">0</span>
                    </div>
                    <div class="secure-aura-scan-stat">
                        <span class="secure-aura-stat-label"><?php _e('Current File:', 'secure-aura'); ?></span>
                        <span id="current-file-name">-</span>
                    </div>
                </div>
            </div>
            <div class="secure-aura-modal-actions">
                <button type="button" class="button button-secondary" id="cancel-scan">
                    <?php _e('Cancel Scan', 'secure-aura'); ?>
                </button>
            </div>
        </div>
    </div>
</div>

<?php
// Add inline JavaScript for dashboard initialization
?>
<script type="text/javascript">
jQuery(document).ready(function($) {
    // Initialize dashboard
    if (typeof SecureAuraDashboard !== 'undefined') {
        SecureAuraDashboard.init();
    }
    
    // Initialize real-time updates
    if (typeof SecureAuraRealTime !== 'undefined') {
        SecureAuraRealTime.init();
    }
    
    // Initialize security score circle
    $('.secure-aura-score-circle').each(function() {
        var score = $(this).data('score');
        // Add animation logic here
    });
    
    // Auto-refresh activity feed every 30 seconds
    setInterval(function() {
        $('#refresh-activity').trigger('click');
    }, 30000);
});
</script>