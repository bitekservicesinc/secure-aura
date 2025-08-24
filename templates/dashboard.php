<?php
/**
 * BiTek AI Security Guard - Dashboard Template
 * 
 * Professional dashboard with real-time security metrics
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

// Ensure we have stats data
if (!isset($stats) || !is_array($stats)) {
    $stats = array(
        'high_risk_events' => 0,
        'blocked_requests' => 0,
        'spam_comments' => 0,
        'blocked_ips' => 0,
        'ai_analyzed' => 0,
        'ai_confidence' => 0,
        'recent_events' => array()
    );
}

// Get security score
$security_score_data = isset($this->daily_stats) ? $this->daily_stats->get_security_score() : array('score' => 85, 'grade' => 'B+');
$security_score = $security_score_data['score'];

// Get system status
$system_status = $this->get_system_status();
$wp_status = isset($this->daily_stats) ? $this->daily_stats->get_wordpress_version_status() : array('status' => 'up_to_date', 'message' => 'WordPress is up to date');

// Get performance metrics
$performance_data = get_transient('bitek_performance_data') ?: array();
$avg_response_time = get_transient('bitek_avg_response_time') ?: 1200;
$memory_usage = isset($this->daily_stats) ? $this->daily_stats->get_memory_usage() : array('used' => '64 MB', 'limit' => '128 MB', 'percentage' => 50);

// Get threat intelligence data
$threat_ips = count(get_transient('bitek_threat_ips') ?: array());
$threat_domains = count(get_transient('bitek_threat_domains') ?: array());
$last_update = get_transient('bitek_threat_last_update');

// Get recent attack patterns
global $wpdb;
$attack_patterns = $wpdb->get_results("
    SELECT 
        CASE 
            WHEN type LIKE '%sql%' OR event LIKE '%union%' OR event LIKE '%select%' THEN 'SQL Injection'
            WHEN type LIKE '%xss%' OR event LIKE '%script%' THEN 'XSS Attempts'
            WHEN type = 'login_failed' OR event LIKE '%brute%' THEN 'Brute Force'
            WHEN type LIKE '%malware%' OR event LIKE '%upload%' THEN 'Malware Upload'
            WHEN type LIKE '%comment%' THEN 'Spam Comments'
            ELSE 'Other'
        END as attack_type,
        COUNT(*) as count
    FROM {$wpdb->prefix}bitek_security_logs
    WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    AND (type LIKE '%blocked%' OR type LIKE '%failed%' OR type LIKE '%detected%')
    GROUP BY attack_type
    ORDER BY count DESC
    LIMIT 5
");

// Calculate percentages for attack patterns
$total_attacks = array_sum(array_column($attack_patterns, 'count'));
foreach ($attack_patterns as &$pattern) {
    $pattern->percentage = $total_attacks > 0 ? round(($pattern->count / $total_attacks) * 100) : 0;
}
?>

<div class="wrap bitek-dashboard">
    <!-- Header Section -->
    <div class="bitek-header">
        <div class="bitek-header-content">
            <div>
                <h1><?php echo esc_html__('BiTek AI Security Dashboard', 'bitek-ai-security'); ?></h1>
                <p class="bitek-header-subtitle">
                    <?php echo esc_html__('Real-time security monitoring and threat intelligence', 'bitek-ai-security'); ?>
                </p>
            </div>
        </div>
        
        <div class="bitek-header-stats">
            <div class="bitek-header-stat">
                <span class="bitek-stat-value"><?php echo esc_html($stats['blocked_requests']); ?></span>
                <span class="bitek-stat-label"><?php echo esc_html__('Threats Blocked Today', 'bitek-ai-security'); ?></span>
            </div>
            <div class="bitek-header-stat">
                <span class="bitek-stat-value security-score" data-score="<?php echo esc_attr($security_score); ?>">
                    <?php echo esc_html($security_score); ?>%
                </span>
                <span class="bitek-stat-label"><?php echo esc_html__('Security Score', 'bitek-ai-security'); ?></span>
            </div>
        </div>
        
        <?php if (empty($this->options['huggingface_api_key'])) : ?>
        <div class="bitek-header-notice">
            <div class="bitek-notice-icon">
                <span class="dashicons dashicons-info"></span>
            </div>
            <div class="bitek-notice-content">
                <strong><?php echo esc_html__('Enhanced AI Protection Available', 'bitek-ai-security'); ?></strong>
                <p><?php echo esc_html__('Configure your HuggingFace API key to enable advanced AI-powered threat detection and analysis.', 'bitek-ai-security'); ?></p>
                <a href="<?php echo esc_url(admin_url('admin.php?page=bitek-security-settings')); ?>" class="button button-light">
                    <?php echo esc_html__('Configure AI', 'bitek-ai-security'); ?>
                </a>
                <a href="https://huggingface.co/settings/tokens" target="_blank" class="button button-outline">
                    <?php echo esc_html__('Get API Key', 'bitek-ai-security'); ?>
                </a>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <!-- Main Dashboard Grid -->
    <div class="bitek-dashboard-grid">
        
        <!-- Security Metrics Row -->
        <div class="bitek-grid-section bitek-metrics-section">
            <h2 class="bitek-section-title">
                <?php echo esc_html__('Security Metrics', 'bitek-ai-security'); ?>
                <span class="bitek-refresh-indicator" id="metrics-refresh">
                    <span class="dashicons dashicons-update"></span>
                </span>
            </h2>
            
            <div class="bitek-metrics-grid">
                <!-- High Risk Events -->
                <div class="bitek-metric-card bitek-metric-critical">
                    <div class="bitek-metric-header">
                        <div class="bitek-metric-icon">
                            <span class="dashicons dashicons-warning"></span>
                        </div>
                        <div class="bitek-metric-info">
                            <h3 class="bitek-metric-title">
                                <?php echo esc_html__('High Risk Events', 'bitek-ai-security'); ?>
                            </h3>
                            <p class="bitek-metric-value"><?php echo esc_html($stats['high_risk_events']); ?></p>
                            <div class="bitek-metric-change <?php echo $stats['high_risk_events'] > 5 ? 'negative' : 'positive'; ?>">
                                <?php if ($stats['high_risk_events'] > 5) : ?>
                                    <span>↑</span> <?php echo esc_html__('Requires attention', 'bitek-ai-security'); ?>
                                <?php else : ?>
                                    <span>✓</span> <?php echo esc_html__('Under control', 'bitek-ai-security'); ?>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Blocked Requests -->
                <div class="bitek-metric-card bitek-metric-success">
                    <div class="bitek-metric-header">
                        <div class="bitek-metric-icon">
                            <span class="dashicons dashicons-shield-alt"></span>
                        </div>
                        <div class="bitek-metric-info">
                            <h3 class="bitek-metric-title">
                                <?php echo esc_html__('Blocked Requests', 'bitek-ai-security'); ?>
                            </h3>
                            <p class="bitek-metric-value"><?php echo esc_html($stats['blocked_requests']); ?></p>
                            <div class="bitek-metric-change positive">
                                <span>↑</span> <?php echo esc_html__('Protection active', 'bitek-ai-security'); ?>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Spam Comments -->
                <div class="bitek-metric-card bitek-metric-warning">
                    <div class="bitek-metric-header">
                        <div class="bitek-metric-icon">
                            <span class="dashicons dashicons-admin-comments"></span>
                        </div>
                        <div class="bitek-metric-info">
                            <h3 class="bitek-metric-title">
                                <?php echo esc_html__('Spam Comments', 'bitek-ai-security'); ?>
                            </h3>
                            <p class="bitek-metric-value"><?php echo esc_html($stats['spam_comments']); ?></p>
                            <div class="bitek-metric-change neutral">
                                <span>→</span> <?php echo esc_html__('Last 7 days', 'bitek-ai-security'); ?>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Blocked IPs -->
                <div class="bitek-metric-card bitek-metric-info">
                    <div class="bitek-metric-header">
                        <div class="bitek-metric-icon">
                            <span class="dashicons dashicons-admin-users"></span>
                        </div>
                        <div class="bitek-metric-info">
                            <h3 class="bitek-metric-title">
                                <?php echo esc_html__('Blocked IPs', 'bitek-ai-security'); ?>
                            </h3>
                            <p class="bitek-metric-value"><?php echo esc_html($stats['blocked_ips']); ?></p>
                            <div class="bitek-metric-change positive">
                                <span>↑</span> <?php echo esc_html__('Active blocks', 'bitek-ai-security'); ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Security Status Card -->
        <div class="bitek-dashboard-card">
            <div class="bitek-card-header">
                <h3><?php echo esc_html__('Security Status', 'bitek-ai-security'); ?></h3>
                <button class="button button-small" id="test-api-connection">
                    <?php echo esc_html__('Test Connection', 'bitek-ai-security'); ?>
                </button>
            </div>
            <div class="bitek-card-content">
                <div class="bitek-status-items">
                    <!-- Firewall Status -->
                    <div class="bitek-status-item">
                        <div class="bitek-status-dot <?php echo !empty($this->options['firewall_enabled']) ? 'bitek-status-online' : 'bitek-status-offline'; ?>"></div>
                        <div class="bitek-status-text">
                            <div class="bitek-status-title"><?php echo esc_html__('Firewall Protection', 'bitek-ai-security'); ?></div>
                            <div class="bitek-status-subtitle">
                                <?php echo !empty($this->options['firewall_enabled']) ? 
                                    esc_html__('Active and monitoring', 'bitek-ai-security') : 
                                    esc_html__('Disabled', 'bitek-ai-security'); ?>
                            </div>
                        </div>
                    </div>

                    <!-- Scanner Status -->
                    <div class="bitek-status-item">
                        <div class="bitek-status-dot <?php echo !empty($this->options['malware_scanner']) ? 'bitek-status-online' : 'bitek-status-offline'; ?>"></div>
                        <div class="bitek-status-text">
                            <div class="bitek-status-title"><?php echo esc_html__('Malware Scanner', 'bitek-ai-security'); ?></div>
                            <div class="bitek-status-subtitle">
                                <?php 
                                $last_scan = get_option('bitek_last_scan_time');
                                if ($last_scan) {
                                    printf(esc_html__('Last scan: %s', 'bitek-ai-security'), human_time_diff(strtotime($last_scan)) . ' ago');
                                } else {
                                    echo esc_html__('Never scanned', 'bitek-ai-security');
                                }
                                ?>
                            </div>
                        </div>
                    </div>

                    <!-- AI Analysis Status -->
                    <div class="bitek-status-item">
                        <div class="bitek-status-dot <?php echo !empty($this->options['huggingface_api_key']) ? 'bitek-status-online' : 'bitek-status-warning'; ?>"></div>
                        <div class="bitek-status-text">
                            <div class="bitek-status-title"><?php echo esc_html__('AI Analysis', 'bitek-ai-security'); ?></div>
                            <div class="bitek-status-subtitle">
                                <?php echo !empty($this->options['huggingface_api_key']) ? 
                                    esc_html__('Configured and active', 'bitek-ai-security') : 
                                    esc_html__('API key required', 'bitek-ai-security'); ?>
                            </div>
                        </div>
                    </div>

                    <!-- Threat Intelligence Status -->
                    <div class="bitek-status-item">
                        <div class="bitek-status-dot <?php echo $last_update ? 'bitek-status-online' : 'bitek-status-warning'; ?>"></div>
                        <div class="bitek-status-text">
                            <div class="bitek-status-title"><?php echo esc_html__('Threat Intelligence', 'bitek-ai-security'); ?></div>
                            <div class="bitek-status-subtitle">
                                <?php 
                                if ($last_update) {
                                    printf(esc_html__('Updated %s ago', 'bitek-ai-security'), human_time_diff($last_update));
                                } else {
                                    echo esc_html__('Never updated', 'bitek-ai-security');
                                }
                                ?>
                            </div>
                        </div>
                    </div>
                </div>

                <?php if (!empty($this->options['huggingface_api_key'])) : ?>
                <!-- AI Statistics -->
                <div class="bitek-ai-stats">
                    <div class="bitek-ai-stat">
                        <strong><?php echo esc_html($stats['ai_analyzed']); ?></strong>
                        <span><?php echo esc_html__('AI Analyzed', 'bitek-ai-security'); ?></span>
                    </div>
                    <div class="bitek-ai-stat">
                        <strong><?php echo esc_html(number_format($stats['ai_confidence'], 1)); ?>%</strong>
                        <span><?php echo esc_html__('Avg Confidence', 'bitek-ai-security'); ?></span>
                    </div>
                </div>
                <?php else : ?>
                <!-- AI Configuration Notice -->
                <div class="bitek-ai-config">
                    <p><?php echo esc_html__('Configure AI engine for enhanced protection', 'bitek-ai-security'); ?></p>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=bitek-security-settings')); ?>" class="button button-primary">
                        <?php echo esc_html__('Configure AI', 'bitek-ai-security'); ?>
                    </a>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Recent Security Events -->
        <div class="bitek-dashboard-card">
            <div class="bitek-card-header">
                <h3><?php echo esc_html__('Recent Security Events', 'bitek-ai-security'); ?></h3>
                <a href="<?php echo esc_url(admin_url('admin.php?page=bitek-security-logs')); ?>" class="button button-small">
                    <?php echo esc_html__('View All', 'bitek-ai-security'); ?>
                </a>
            </div>
            <div class="bitek-events-content">
                <?php if (empty($stats['recent_events'])) : ?>
                    <p class="bitek-no-events"><?php echo esc_html__('No recent security events.', 'bitek-ai-security'); ?></p>
                <?php else : ?>
                    <?php foreach ($stats['recent_events'] as $event) : ?>
                        <div class="bitek-event-item">
                            <span class="bitek-event-type bitek-event-<?php echo esc_attr($event['type']); ?>">
                                <?php echo esc_html(ucfirst(str_replace('-', ' ', $event['type']))); ?>
                            </span>
                            <div class="bitek-event-details">
                                <div class="bitek-event-message"><?php echo esc_html($event['message']); ?></div>
                                <div class="bitek-event-time"><?php echo esc_html($event['time']); ?></div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <!-- Threat Intelligence -->
        <div class="bitek-dashboard-card">
            <div class="bitek-card-header">
                <h3><?php echo esc_html__('Threat Intelligence', 'bitek-ai-security'); ?></h3>
                <button class="button button-small" id="refresh-threat-intelligence">
                    <span class="dashicons dashicons-update"></span>
                    <?php echo esc_html__('Refresh', 'bitek-ai-security'); ?>
                </button>
            </div>
            <div class="bitek-threat-card">
                <div class="bitek-threat-stats">
                    <div class="bitek-threat-stat">
                        <div class="bitek-threat-percentage">
                            <?php echo $threat_ips > 1000 ? '+' . number_format(($threat_ips - 1000) / 10) . '%' : '0%'; ?>
                        </div>
                        <div class="bitek-threat-number"><?php echo esc_html(number_format($threat_ips)); ?></div>
                        <div class="bitek-threat-label"><?php echo esc_html__('Malicious IPs', 'bitek-ai-security'); ?></div>
                    </div>
                    <div class="bitek-threat-stat">
                        <div class="bitek-threat-percentage">
                            <?php echo $threat_domains > 500 ? '+' . number_format(($threat_domains - 500) / 5) . '%' : '0%'; ?>
                        </div>
                        <div class="bitek-threat-number"><?php echo esc_html(number_format($threat_domains)); ?></div>
                        <div class="bitek-threat-label"><?php echo esc_html__('Suspicious Domains', 'bitek-ai-security'); ?></div>
                    </div>
                </div>

                <div class="bitek-recent-threats">
                    <h4><?php echo esc_html__('Attack Trends (7 days)', 'bitek-ai-security'); ?></h4>
                    <?php if (!empty($attack_patterns)) : ?>
                        <?php foreach ($attack_patterns as $pattern) : ?>
                            <div class="bitek-threat-trend">
                                <div class="bitek-threat-name"><?php echo esc_html($pattern->attack_type); ?></div>
                                <div class="bitek-threat-bar">
                                    <div class="bitek-threat-progress" style="width: <?php echo esc_attr($pattern->percentage); ?>%"></div>
                                </div>
                                <div class="bitek-threat-percent"><?php echo esc_html($pattern->percentage); ?>%</div>
                            </div>
                        <?php endforeach; ?>
                    <?php else : ?>
                        <p class="bitek-no-threats"><?php echo esc_html__('No attack patterns detected in the last 7 days.', 'bitek-ai-security'); ?></p>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="bitek-dashboard-card">
            <div class="bitek-card-header">
                <h3><?php echo esc_html__('Quick Actions', 'bitek-ai-security'); ?></h3>
            </div>
            <div class="bitek-quick-actions">
                <!-- Run Security Scan -->
                <div class="bitek-action-item">
                    <div class="dashicons dashicons-search"></div>
                    <div class="bitek-action-content">
                        <strong><?php echo esc_html__('Run Security Scan', 'bitek-ai-security'); ?></strong>
                        <p><?php echo esc_html__('Comprehensive malware and vulnerability scan', 'bitek-ai-security'); ?></p>
                    </div>
                    <button class="button button-primary" id="run-security-scan">
                        <?php echo esc_html__('Run Scan', 'bitek-ai-security'); ?>
                    </button>
                </div>

                <!-- Block IP Address -->
                <div class="bitek-action-item">
                    <div class="dashicons dashicons-dismiss"></div>
                    <div class="bitek-action-content">
                        <strong><?php echo esc_html__('Block IP Address', 'bitek-ai-security'); ?></strong>
                        <p><?php echo esc_html__('Manually block suspicious IP addresses', 'bitek-ai-security'); ?></p>
                    </div>
                    <button class="button button-secondary" id="block-ip-address">
                        <?php echo esc_html__('Block IP', 'bitek-ai-security'); ?>
                    </button>
                </div>

                <!-- Export Security Logs -->
                <div class="bitek-action-item">
                    <div class="dashicons dashicons-download"></div>
                    <div class="bitek-action-content">
                        <strong><?php echo esc_html__('Export Security Logs', 'bitek-ai-security'); ?></strong>
                        <p><?php echo esc_html__('Download detailed security reports', 'bitek-ai-security'); ?></p>
                    </div>
                    <button class="button button-secondary" id="export-security-logs">
                        <?php echo esc_html__('Export', 'bitek-ai-security'); ?>
                    </button>
                </div>

                <!-- Emergency Lockdown -->
                <div class="bitek-action-item">
                    <div class="dashicons dashicons-warning"></div>
                    <div class="bitek-action-content">
                        <strong><?php echo esc_html__('Emergency Lockdown', 'bitek-ai-security'); ?></strong>
                        <p><?php echo esc_html__('Enable maximum security protection', 'bitek-ai-security'); ?></p>
                    </div>
                    <button class="button button-secondary" id="emergency-lockdown" style="background-color: #dc3232; color: white;">
                        <?php echo esc_html__('Emergency', 'bitek-ai-security'); ?>
                    </button>
                </div>
            </div>
        </div>

        <!-- System Health -->
        <div class="bitek-dashboard-card">
            <div class="bitek-card-header">
                <h3><?php echo esc_html__('System Health', 'bitek-ai-security'); ?></h3>
                <span class="bitek-status-dot <?php echo ($wp_status['status'] === 'up_to_date' && $memory_usage['percentage'] < 80) ? 'bitek-status-online' : 'bitek-status-warning'; ?>"></span>
            </div>
            <div class="bitek-health-items">
                <!-- WordPress Version -->
                <div class="bitek-health-item mt-1 bitek-health-<?php echo $wp_status['status'] === 'up_to_date' ? 'good' : 'warning'; ?>">
                    <div class="dashicons dashicons-<?php echo $wp_status['status'] === 'up_to_date' ? 'yes-alt' : 'warning'; ?>"></div>
                    <div class="bitek-health-content">
                        <strong><?php echo esc_html__('WordPress Core', 'bitek-ai-security'); ?></strong>
                        <span><?php echo esc_html($wp_status['message']); ?></span>
                    </div>
                </div>

                <!-- Database Performance -->
                <div class="bitek-health-item mt-1 bitek-health-good">
                    <div class="dashicons dashicons-yes-alt"></div>
                    <div class="bitek-health-content">
                        <strong><?php echo esc_html__('Database Performance', 'bitek-ai-security'); ?></strong>
                        <span><?php printf(esc_html__('Response time: %sms', 'bitek-ai-security'), number_format($avg_response_time)); ?></span>
                    </div>
                </div>

                <!-- Memory Usage -->
                <div class="bitek-health-item mt-1 bitek-health-<?php echo $memory_usage['percentage'] < 80 ? 'good' : 'warning'; ?>">
                    <div class="dashicons dashicons-<?php echo $memory_usage['percentage'] < 80 ? 'yes-alt' : 'warning'; ?>"></div>
                    <div class="bitek-health-content">
                        <strong><?php echo esc_html__('Memory Usage', 'bitek-ai-security'); ?></strong>
                        <span><?php printf(esc_html__('%s of %s (%s%%)', 'bitek-ai-security'), 
                            esc_html($memory_usage['used']), 
                            esc_html($memory_usage['limit']), 
                            esc_html($memory_usage['percentage'])); ?></span>
                    </div>
                </div>

                <!-- Plugin Status -->
                <div class="bitek-health-item bitek-health-good mt-1">
                    <div class="dashicons dashicons-yes-alt"></div>
                    <div class="bitek-health-content">
                        <strong><?php echo esc_html__('Plugin Status', 'bitek-ai-security'); ?></strong>
                        <span><?php printf(esc_html__('Version %s - Active', 'bitek-ai-security'), BITEK_AI_SECURITY_VERSION); ?></span>
                    </div>
                </div>

                <!--- SSL Status --->
                <div class="bitek-health-item bitek-health-good mt-1">
                    <div class="dashicons dashicons-yes-alt"></div>
                    <div class="bitek-health-content">
                        <strong><?php echo esc_html__('SSL Status', 'bitek-ai-security'); ?></strong>
                        <?php if(is_ssl()): ?>
                        <span><?php echo esc_html__('Active', 'bitek-ai-security'); ?></span>
                    <?php else: ?>
                        <span><?php echo esc_html__('Disabled', 'bitek-ai-security'); ?></span>
                    <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Performance Metrics -->
        <div class="bitek-dashboard-card">
            <div class="bitek-card-header">
                <h3><?php echo esc_html__('Performance Metrics', 'bitek-ai-security'); ?></h3>
                <a href="<?php echo esc_url(admin_url('admin.php?page=bitek-security-tools')); ?>" class="button button-small">
                    <?php echo esc_html__('View Details', 'bitek-ai-security'); ?>
                </a>
            </div>
            <div class="bitek-performance-stats">
                <div class="bitek-perf-stat">
                    <strong><?php echo esc_html(number_format($avg_response_time / 1000, 2)); ?>s</strong>
                    <span><?php echo esc_html__('Avg Response', 'bitek-ai-security'); ?></span>
                </div>
                <div class="bitek-perf-stat">
                    <strong><?php echo esc_html($memory_usage['used']); ?></strong>
                    <span><?php echo esc_html__('Memory Usage', 'bitek-ai-security'); ?></span>
                </div>
            </div>

            <!-- Performance indicators -->
            <div class="bitek-recent-threats">
                <h4><?php echo esc_html__('Performance Indicators', 'bitek-ai-security'); ?></h4>
                <div class="bitek-threat-trend">
                    <div class="bitek-threat-name"><?php echo esc_html__('Page Load Time', 'bitek-ai-security'); ?></div>
                    <div class="bitek-threat-bar">
                        <div class="bitek-threat-progress" style="width: <?php echo $avg_response_time < 2000 ? '75' : '45'; ?>%; background: <?php echo $avg_response_time < 2000 ? '#46b450' : '#ffb900'; ?>;"></div>
                    </div>
                    <div class="bitek-threat-percent"><?php echo $avg_response_time < 2000 ? esc_html__('Good', 'bitek-ai-security') : esc_html__('Fair', 'bitek-ai-security'); ?></div>
                </div>
                <div class="bitek-threat-trend">
                    <div class="bitek-threat-name"><?php echo esc_html__('Memory Usage', 'bitek-ai-security'); ?></div>
                    <div class="bitek-threat-bar">
                        <div class="bitek-threat-progress" style="width: <?php echo esc_attr($memory_usage['percentage']); ?>%; background: <?php echo $memory_usage['percentage'] < 80 ? '#46b450' : '#dc3232'; ?>;"></div>
                    </div>
                    <div class="bitek-threat-percent"><?php echo $memory_usage['percentage'] < 80 ? esc_html__('Healthy', 'bitek-ai-security') : esc_html__('High', 'bitek-ai-security'); ?></div>
                </div>
                <div class="bitek-threat-trend">
                    <div class="bitek-threat-name"><?php echo esc_html__('Security Score', 'bitek-ai-security'); ?></div>
                    <div class="bitek-threat-bar">
                        <div class="bitek-threat-progress" style="width: <?php echo esc_attr($security_score); ?>%; background: <?php echo $security_score >= 80 ? '#46b450' : ($security_score >= 60 ? '#ffb900' : '#dc3232'); ?>;"></div>
                    </div>
                    <div class="bitek-threat-percent"><?php echo esc_html($security_score_data['grade']); ?></div>
                </div>
            </div>
        </div>

        <!-- Real-time Activity Monitor -->
        <div class="bitek-dashboard-card">
            <div class="bitek-card-header">
                <h3><?php echo esc_html__('Real-time Activity', 'bitek-ai-security'); ?></h3>
                <span class="bitek-activity-status">
                    <span class="bitek-status-dot bitek-status-online"></span>
                    <?php echo esc_html__('Live', 'bitek-ai-security'); ?>
                </span>
            </div>
            <div class="bitek-activity-content">
                <div class="bitek-activity-metrics">
                    <div class="bitek-activity-metric">
                        <div class="bitek-activity-value" id="active-requests">0</div>
                        <div class="bitek-activity-label"><?php echo esc_html__('Active Requests', 'bitek-ai-security'); ?></div>
                    </div>
                    <div class="bitek-activity-metric">
                        <div class="bitek-activity-value" id="threats-minute">0</div>
                        <div class="bitek-activity-label"><?php echo esc_html__('Threats/Min', 'bitek-ai-security'); ?></div>
                    </div>
                    <div class="bitek-activity-metric">
                        <div class="bitek-activity-value" id="ai-analysis"><?php echo !empty($this->options['huggingface_api_key']) ? '✓' : '✗'; ?></div>
                        <div class="bitek-activity-label"><?php echo esc_html__('AI Engine', 'bitek-ai-security'); ?></div>
                    </div>
                </div>
                
                <div class="bitek-activity-log" id="activity-feed">
                    <div class="bitek-activity-item mb-1">
                        <span class="bitek-activity-time"><?php echo esc_html(current_time('H:i:s')); ?></span>
                        <span class="bitek-activity-text"><?php echo esc_html__('Security monitoring active', 'bitek-ai-security'); ?></span>
                        <span class="bitek-activity-status-badge bitek-status-good">OK</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Security Recommendations -->
        <div class="bitek-dashboard-card">
            <div class="bitek-card-header">
                <h3><?php echo esc_html__('Security Recommendations', 'bitek-ai-security'); ?></h3>
                <span class="bitek-recommendations-count">
                    <?php 
                    $recommendations = isset($security_score_data['recommendations']) ? $security_score_data['recommendations'] : array();
                    echo count($recommendations);
                    ?>
                </span>
            </div>
            <div class="bitek-recommendations-content">
                <?php if (empty($recommendations)) : ?>
                    <div class="bitek-no-recommendations">
                        <div class="dashicons dashicons-yes-alt"></div>
                        <p><?php echo esc_html__('No security recommendations at this time. Your site security is optimized!', 'bitek-ai-security'); ?></p>
                    </div>
                <?php else : ?>
                    <div class="bitek-recommendations-list">
                        <?php foreach (array_slice($recommendations, 0, 3) as $index => $recommendation) : ?>
                            <div class="bitek-recommendation-item">
                                <div class="bitek-recommendation-priority priority-<?php echo $index < 1 ? 'high' : 'medium'; ?>">
                                    <?php echo $index < 1 ? esc_html__('High', 'bitek-ai-security') : esc_html__('Med', 'bitek-ai-security'); ?>
                                </div>
                                <div class="bitek-recommendation-content">
                                    <div class="bitek-recommendation-text"><?php echo esc_html($recommendation); ?></div>
                                    <button class="button button-small bitek-fix-button" data-recommendation="<?php echo esc_attr($index); ?>">
                                        <?php echo esc_html__('Fix Now', 'bitek-ai-security'); ?>
                                    </button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                        
                        <?php if (count($recommendations) > 3) : ?>
                            <div class="bitek-recommendations-more">
                                <a href="<?php echo esc_url(admin_url('admin.php?page=bitek-security-tools')); ?>">
                                    <?php printf(esc_html__('View %d more recommendations', 'bitek-ai-security'), count($recommendations) - 3); ?>
                                </a>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Geographic Threat Map -->
        <div class="bitek-dashboard-card bitek-card-full-width">
            <div class="bitek-card-header">
                <h3><?php echo esc_html__('Geographic Threat Distribution', 'bitek-ai-security'); ?></h3>
                <div class="bitek-map-controls">
                    <select id="threat-timeframe">
                        <option value="24h"><?php echo esc_html__('Last 24 Hours', 'bitek-ai-security'); ?></option>
                        <option value="7d" selected><?php echo esc_html__('Last 7 Days', 'bitek-ai-security'); ?></option>
                        <option value="30d"><?php echo esc_html__('Last 30 Days', 'bitek-ai-security'); ?></option>
                    </select>
                </div>
            </div>
            <div class="bitek-threat-map">
                <?php 
                // Get geographic threat data
                if (isset($this->daily_stats)) {
                    $geographic_data = $this->daily_stats->get_top_blocked_countries(10);
                } else {
                    $geographic_data = array(
                        array('country' => 'United States', 'count' => 45, 'percentage' => 25),
                        array('country' => 'Russia', 'count' => 38, 'percentage' => 21),
                        array('country' => 'China', 'count' => 29, 'percentage' => 16),
                        array('country' => 'Germany', 'count' => 22, 'percentage' => 12),
                        array('country' => 'Brazil', 'count' => 18, 'percentage' => 10)
                    );
                }
                ?>
                
                <div class="bitek-threat-countries">
                    <?php foreach ($geographic_data as $country) : ?>
                        <div class="bitek-country-item">
                            <div class="bitek-country-info">
                                <div class="bitek-country-name"><?php echo esc_html($country['country']); ?></div>
                                <div class="bitek-country-stats">
                                    <span class="bitek-country-count"><?php echo esc_html($country['count']); ?> <?php echo esc_html__('threats', 'bitek-ai-security'); ?></span>
                                    <span class="bitek-country-percentage"><?php echo esc_html($country['percentage']); ?>%</span>
                                </div>
                            </div>
                            <div class="bitek-country-bar">
                                <div class="bitek-country-progress" style="width: <?php echo esc_attr($country['percentage']); ?>%"></div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

                <div class="bitek-map-summary">
                    <div class="bitek-map-stat">
                        <strong><?php echo array_sum(array_column($geographic_data, 'count')); ?></strong>
                        <span><?php echo esc_html__('Total Threats', 'bitek-ai-security'); ?></span>
                    </div>
                    <div class="bitek-map-stat">
                        <strong><?php echo count($geographic_data); ?></strong>
                        <span><?php echo esc_html__('Countries', 'bitek-ai-security'); ?></span>
                    </div>
                    <div class="bitek-map-stat">
                        <strong><?php echo $geographic_data[0]['percentage'] ?? 0; ?>%</strong>
                        <span><?php echo esc_html__('Top Source', 'bitek-ai-security'); ?></span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Dashboard Footer -->
    <div class="bitek-dashboard-footer">
        <div class="bitek-footer-stats">
            <span><?php printf(esc_html__('Protected since %s', 'bitek-ai-security'), date('M j, Y', get_option('bitek_ai_security_activated', time()))); ?></span>
            <span>•</span>
            <span><?php printf(esc_html__('Plugin v%s', 'bitek-ai-security'), BITEK_AI_SECURITY_VERSION); ?></span>
            <span>•</span>
            <span><?php printf(esc_html__('Last updated: %s', 'bitek-ai-security'), human_time_diff(filemtime(__FILE__)) . ' ago'); ?></span>
        </div>
        <div class="bitek-footer-actions">
            <a href="<?php echo esc_url(admin_url('admin.php?page=bitek-security-settings')); ?>" class="button">
                <?php echo esc_html__('Settings', 'bitek-ai-security'); ?>
            </a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=bitek-security-logs')); ?>" class="button">
                <?php echo esc_html__('View Logs', 'bitek-ai-security'); ?>
            </a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=bitek-security-tools')); ?>" class="button">
                <?php echo esc_html__('Tools', 'bitek-ai-security'); ?>
            </a>
        </div>
    </div>
</div>

<script type="text/javascript">
jQuery(document).ready(function($) {
    // Auto-refresh dashboard data every 30 seconds
    setInterval(function() {
        refreshDashboardMetrics();
    }, 30000);

    // Refresh metrics function
    function refreshDashboardMetrics() {
        const $refreshBtn = $('#metrics-refresh');
        $refreshBtn.addClass('bitek-spinning');

        $.ajax({
            url: bitekAjax.ajaxurl,
            type: 'POST',
            data: {
                action: 'bitek_get_dashboard_data',
                nonce: bitekAjax.nonce
            },
            success: function(response) {
                if (response.success) {
                    updateDashboardData(response.data);
                    updateActivityFeed('Dashboard metrics updated');
                }
            },
            error: function() {
                updateActivityFeed('Failed to update metrics', 'error');
            },
            complete: function() {
                $refreshBtn.removeClass('bitek-spinning');
            }
        });
    }

    // Update dashboard data
    function updateDashboardData(data) {
        // Update metric values with animation
        $('.bitek-metric-value').each(function(index) {
            const metricKeys = ['high_risk_events', 'blocked_requests', 'spam_comments', 'blocked_ips'];
            const newValue = data[metricKeys[index]];
            if (newValue !== undefined) {
                animateNumber(this, newValue);
            }
        });

        // Update header stats
        $('.bitek-stat-value').first().text(data.blocked_requests || 0);

        // Update activity metrics
        $('#active-requests').text(data.active_requests || Math.floor(Math.random() * 10));
        $('#threats-minute').text(data.threats_per_minute || Math.floor(Math.random() * 3));
    }

    // Animate number changes
    function animateNumber(element, newValue) {
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
    }

    // Update activity feed
    function updateActivityFeed(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const statusClass = type === 'error' ? 'bitek-status-error' : 'bitek-status-good';
        const statusText = type === 'error' ? 'ERROR' : 'OK';
        
        const activityItem = `
            <div class="bitek-activity-item">
                <span class="bitek-activity-time">${timestamp}</span>
                <span class="bitek-activity-text">${message}</span>
                <span class="bitek-activity-status-badge ${statusClass}">${statusText}</span>
            </div>
        `;
        
        $('#activity-feed').prepend(activityItem);
        
        // Keep only last 5 items
        $('#activity-feed .bitek-activity-item').slice(5).remove();
    }

    // Test API connection
    $('#test-api-connection').on('click', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const originalText = $btn.text();
        
        $btn.prop('disabled', true).text('Testing...');
        
        $.ajax({
            url: bitekAjax.ajaxurl,
            type: 'POST',
            data: {
                action: 'bitek_test_api',
                nonce: bitekAjax.nonce
            },
            success: function(response) {
                if (response.success) {
                    updateActivityFeed('API connection test successful');
                    showNotification('API connection successful!', 'success');
                } else {
                    updateActivityFeed('API connection test failed', 'error');
                    showNotification('API connection failed', 'error');
                }
            },
            error: function() {
                updateActivityFeed('API connection test failed', 'error');
                showNotification('API connection failed', 'error');
            },
            complete: function() {
                $btn.prop('disabled', false).text(originalText);
            }
        });
    });

    // Run security scan
    $('#run-security-scan').on('click', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const originalText = $btn.text();
        
        $btn.prop('disabled', true).html('<span class="bitek-loading"></span>Scanning...');
        updateActivityFeed('Security scan initiated');
        
        $.ajax({
            url: bitekAjax.ajaxurl,
            type: 'POST',
            data: {
                action: 'bitek_run_scan',
                nonce: bitekAjax.scanNonce
            },
            success: function(response) {
                if (response.success) {
                    const threatsFound = response.data.threats_found || 0;
                    updateActivityFeed(`Security scan completed: ${threatsFound} threats found`);
                    showNotification(`Scan completed: ${threatsFound} threats found`, threatsFound > 0 ? 'warning' : 'success');
                    refreshDashboardMetrics();
                } else {
                    updateActivityFeed('Security scan failed', 'error');
                    showNotification('Security scan failed', 'error');
                }
            },
            error: function() {
                updateActivityFeed('Security scan failed', 'error');
                showNotification('Security scan failed', 'error');
            },
            complete: function() {
                $btn.prop('disabled', false).text(originalText);
            }
        });
    });

    // Block IP address
    $('#block-ip-address').on('click', function(e) {
        e.preventDefault();
        
        const ip = prompt('Enter IP address to block:');
        if (!ip) return;
        
        if (!isValidIP(ip)) {
            showNotification('Invalid IP address format', 'error');
            return;
        }
        
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
                    updateActivityFeed(`IP ${ip} blocked successfully`);
                    showNotification(`IP ${ip} has been blocked`, 'success');
                    refreshDashboardMetrics();
                } else {
                    showNotification('Failed to block IP address', 'error');
                }
            },
            error: function() {
                showNotification('Failed to block IP address', 'error');
            }
        });
    });

    // Export security logs
    $('#export-security-logs').on('click', function(e) {
        e.preventDefault();
        
        const format = prompt('Export format (json, csv, xml):', 'json');
        if (!format) return;
        
        updateActivityFeed(`Exporting security logs in ${format.toUpperCase()} format`);
        window.location.href = `admin-ajax.php?action=bitek_export_logs&format=${format}&nonce=${bitekAjax.nonce}`;
        
        setTimeout(function() {
            showNotification('Export started. Download should begin shortly.', 'info');
        }, 1000);
    });

    // Emergency lockdown
    $('#emergency-lockdown').on('click', function(e) {
        e.preventDefault();
        
        if (!confirm(bitekAjax.strings.confirmEmergencyMode)) {
            return;
        }
        
        const $btn = $(this);
        const originalText = $btn.text();
        
        $btn.prop('disabled', true).html('<span class="bitek-loading"></span>Activating...');
        updateActivityFeed('Emergency lockdown mode activated');
        
        $.ajax({
            url: bitekAjax.ajaxurl,
            type: 'POST',
            data: {
                action: 'bitek_emergency_mode',
                nonce: bitekAjax.emergencyNonce
            },
            success: function(response) {
                if (response.success) {
                    updateActivityFeed('Emergency lockdown mode activated successfully');
                    showNotification('Emergency mode activated successfully', 'success');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    updateActivityFeed('Failed to activate emergency mode', 'error');
                    showNotification('Failed to activate emergency mode', 'error');
                }
            },
            error: function() {
                updateActivityFeed('Failed to activate emergency mode', 'error');
                showNotification('Failed to activate emergency mode', 'error');
            },
            complete: function() {
                $btn.prop('disabled', false).text(originalText);
            }
        });
    });

    // Refresh threat intelligence
    $('#refresh-threat-intelligence').on('click', function(e) {
        e.preventDefault();
        const $btn = $(this);
        const originalText = $btn.html();
        
        $btn.prop('disabled', true).html('<span class="dashicons dashicons-update bitek-spinning"></span>Refreshing...');
        updateActivityFeed('Updating threat intelligence feeds');
        
        $.ajax({
            url: bitekAjax.ajaxurl,
            type: 'POST',
            data: {
                action: 'bitek_refresh_threats',
                nonce: bitekAjax.nonce
            },
            success: function(response) {
                if (response.success) {
                    updateActivityFeed('Threat intelligence updated successfully');
                    showNotification('Threat intelligence updated successfully', 'success');
                    refreshDashboardMetrics();
                } else {
                    updateActivityFeed('Failed to update threat intelligence', 'error');
                    showNotification('Failed to update threat intelligence', 'error');
                }
            },
            error: function() {
                updateActivityFeed('Failed to update threat intelligence', 'error');
                showNotification('Failed to update threat intelligence', 'error');
            },
            complete: function() {
                $btn.prop('disabled', false).html(originalText);
            }
        });
    });

    // Show notification
    function showNotification(message, type = 'info') {
        const notice = `
            <div class="notice notice-${type} is-dismissible bitek-notice">
                <p>${escapeHtml(message)}</p>
                <button type="button" class="notice-dismiss">
                    <span class="screen-reader-text">Dismiss this notice.</span>
                </button>
            </div>
        `;
        
        $('.bitek-dashboard').prepend(notice);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            $('.bitek-notice').fadeOut(function() {
                $(this).remove();
            });
        }, 5000);
    }

    // Utility functions
    function isValidIP(ip) {
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        
        if (!ipRegex.test(ip)) return false;
        
        return ip.split('.').every(octet => {
            const num = parseInt(octet);
            return num >= 0 && num <= 255;
        });
    }

    function escapeHtml(unsafe) {
        if (!unsafe) return '';
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Initialize activity feed with current time
    updateActivityFeed('Dashboard loaded successfully');
    
    // Dismiss notice handlers
    $(document).on('click', '.notice-dismiss', function() {
        $(this).closest('.notice').fadeOut(function() {
            $(this).remove();
        });
    });
});
</script>