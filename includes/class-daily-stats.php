<?php
/**
 * BiTek Production Daily Stats Class
 * 
 * Real-time dashboard statistics and metrics collection with actual data
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class BiTek_Daily_Stats {
    
    private $cache_duration = 300; // 5 minutes cache
    private $options;
    
    public function __construct() {
        $this->options = get_option('bitek_ai_security_options', array());
        add_action('init', array($this, 'init_stats_tracking'));
    }
    
    public function init_stats_tracking() {
        // Track page views for analytics
        if (!is_admin() && !wp_doing_cron()) {
            $this->track_page_view();
        }
    }
    
    private function track_page_view() {
        $ip = $this->get_client_ip();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // Don't track bots and known crawlers
        if ($this->is_bot($user_agent)) {
            return;
        }
        
        // Increment daily page views
        $today = date('Y-m-d');
        $daily_views = get_transient("bitek_daily_views_{$today}") ?: 0;
        set_transient("bitek_daily_views_{$today}", $daily_views + 1, DAY_IN_SECONDS);
        
        // Track unique visitors
        $visitors_today = get_transient("bitek_visitors_{$today}") ?: array();
        if (!in_array($ip, $visitors_today)) {
            $visitors_today[] = $ip;
            set_transient("bitek_visitors_{$today}", $visitors_today, DAY_IN_SECONDS);
        }
    }
    
    private function is_bot($user_agent) {
        $bot_patterns = array(
            'bot', 'crawl', 'spider', 'scraper', 'curl', 'wget', 'python', 'java'
        );
        
        $user_agent_lower = strtolower($user_agent);
        foreach ($bot_patterns as $pattern) {
            if (strpos($user_agent_lower, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    public function get_dashboard_stats() {
        $cached_stats = get_transient('bitek_dashboard_stats');
        if ($cached_stats !== false) {
            return $cached_stats;
        }
        
        global $wpdb;
        
        $stats = array();
        
        // Security tables
        $logs_table = $wpdb->prefix . 'bitek_security_logs';
        $blocked_ips_table = $wpdb->prefix . 'bitek_blocked_ips';
        $file_integrity_table = $wpdb->prefix . 'bitek_file_integrity';
        
        // High Risk Events (24h) - Real critical security events
        $stats['high_risk_events'] = $this->get_high_risk_events_count();
        
        // Blocked Requests (24h) - Real blocked requests
        $stats['blocked_requests'] = $this->get_blocked_requests_count();
        
        // Spam Comments Blocked (7d) - Real spam comments
        $stats['spam_comments'] = $this->get_spam_comments_count();
        
        // Currently Blocked IP Addresses
        $stats['blocked_ips'] = $this->get_active_blocked_ips_count();
        
        // AI Analysis Stats - Real AI usage data
        $stats['ai_analyzed'] = $this->get_ai_analyzed_count();
        $stats['ai_confidence'] = $this->get_average_ai_confidence();
        
        // Recent Security Events - Real events from database
        $stats['recent_events'] = $this->get_recent_security_events();
        
        // Performance Metrics - Real system data
        $stats['memory_usage'] = $this->get_memory_usage();
        $stats['database_size'] = $this->get_database_size();
        $stats['response_time'] = $this->get_average_response_time();
        
        // Threat Intelligence Stats - Real threat data
        $stats['threat_feeds_last_update'] = $this->get_threat_feeds_last_update();
        $stats['known_malicious_ips'] = $this->get_known_malicious_ips_count();
        $stats['suspicious_domains'] = $this->get_suspicious_domains_count();
        
        // Site Health Metrics
        $stats['wordpress_version_status'] = $this->get_wordpress_version_status();
        $stats['plugin_vulnerabilities'] = $this->get_plugin_vulnerability_count();
        $stats['file_integrity_violations'] = $this->get_file_integrity_violations();
        
        // Activity Metrics
        $stats['login_attempts_24h'] = $this->get_login_attempts_count();
        $stats['failed_logins_24h'] = $this->get_failed_logins_count();
        $stats['admin_access_attempts'] = $this->get_admin_access_attempts();
        
        // Cache the results
        set_transient('bitek_dashboard_stats', $stats, $this->cache_duration);
        
        return $stats;
    }
    
    private function get_high_risk_events_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        // Define what constitutes high-risk events
        $high_risk_types = array(
            'malware_detected',
            'backdoor_detected',
            'sql_injection_blocked',
            'command_injection_blocked',
            'file_integrity_violation',
            'suspicious_upload_blocked',
            'brute_force_blocked',
            'admin_breach_attempt'
        );
        
        $placeholders = implode(',', array_fill(0, count($high_risk_types), '%s'));
        $query_params = array_merge($high_risk_types);
        
        $count = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type IN ({$placeholders})
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ", $query_params));
        
        return intval($count);
    }
    
    private function get_blocked_requests_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $count = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE (type LIKE '%blocked%' OR event LIKE '%blocked%')
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        return intval($count);
    }
    
    private function get_spam_comments_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $count = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type IN ('comment_blocked', 'ai_comment_blocked', 'spam_comment_blocked')
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");
        
        return intval($count);
    }
    
    private function get_active_blocked_ips_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_blocked_ips';
        
        $count = $wpdb->get_var("
            SELECT COUNT(DISTINCT ip) FROM {$table_name}
            WHERE expires_at IS NULL OR expires_at > NOW()
        ");
        
        return intval($count);
    }
    
    private function get_ai_analyzed_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        // Count actual AI analysis events
        $count = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE (event LIKE '%AI%' OR type LIKE '%ai_%')
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");
        
        return intval($count);
    }
    
    private function get_average_ai_confidence() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        // Extract confidence scores from AI analysis logs
        $results = $wpdb->get_results("
            SELECT data FROM {$table_name}
            WHERE type LIKE '%ai_%'
            AND data IS NOT NULL
            AND data != ''
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");
        
        $confidence_scores = array();
        
        foreach ($results as $result) {
            $data = json_decode($result->data, true);
            if (isset($data['confidence']) || isset($data['score'])) {
                $score = $data['confidence'] ?? $data['score'];
                if (is_numeric($score)) {
                    $confidence_scores[] = floatval($score) * 100; // Convert to percentage
                }
            }
        }
        
        if (empty($confidence_scores)) {
            return 0; // Return 0 if no AI analysis has been performed
        }
        
        return round(array_sum($confidence_scores) / count($confidence_scores), 1);
    }
    
    private function get_recent_security_events($limit = 5) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $events = $wpdb->get_results($wpdb->prepare("
            SELECT type, event, ip, created_at
            FROM {$table_name}
            WHERE type IN (
                'firewall_blocked', 'comment_blocked', 'ai_comment_blocked',
                'login_failed', 'brute_force_blocked', 'malware_detected',
                'file_integrity_violation', 'suspicious_upload_blocked'
            )
            ORDER BY created_at DESC
            LIMIT %d
        ", $limit));
        
        $formatted_events = array();
        
        foreach ($events as $event) {
            $formatted_events[] = array(
                'type' => $this->format_event_type($event->type),
                'message' => $this->format_event_message($event->event, $event->ip),
                'time' => $this->format_time_ago($event->created_at),
                'severity' => $this->get_event_severity($event->type)
            );
        }
        
        return $formatted_events;
    }
    
    private function format_event_type($type) {
        $type_mapping = array(
            'firewall_blocked' => 'firewall',
            'comment_blocked' => 'spam',
            'ai_comment_blocked' => 'ai-spam',
            'login_failed' => 'login',
            'brute_force_blocked' => 'brute-force',
            'malware_detected' => 'malware',
            'file_integrity_violation' => 'integrity',
            'suspicious_upload_blocked' => 'upload'
        );
        
        return $type_mapping[$type] ?? 'security';
    }
    
    private function format_event_message($event, $ip) {
        // Truncate long messages and add IP for context
        $message = strlen($event) > 60 ? substr($event, 0, 57) . '...' : $event;
        
        // Add IP context if available
        if (!empty($ip) && $ip !== 'Unknown' && filter_var($ip, FILTER_VALIDATE_IP)) {
            $message .= " (IP: {$ip})";
        }
        
        return $message;
    }
    
    private function format_time_ago($datetime) {
        $time = strtotime($datetime);
        $time_diff = time() - $time;
        
        if ($time_diff < 60) {
            return 'Just now';
        } elseif ($time_diff < 3600) {
            $minutes = floor($time_diff / 60);
            return $minutes . ' minute' . ($minutes > 1 ? 's' : '') . ' ago';
        } elseif ($time_diff < 86400) {
            $hours = floor($time_diff / 3600);
            return $hours . ' hour' . ($hours > 1 ? 's' : '') . ' ago';
        } else {
            $days = floor($time_diff / 86400);
            return $days . ' day' . ($days > 1 ? 's' : '') . ' ago';
        }
    }
    
    private function get_event_severity($type) {
        $high_severity = array('malware_detected', 'backdoor_detected', 'brute_force_blocked', 'file_integrity_violation');
        $medium_severity = array('firewall_blocked', 'suspicious_upload_blocked', 'admin_breach_attempt');
        
        if (in_array($type, $high_severity)) {
            return 'high';
        } elseif (in_array($type, $medium_severity)) {
            return 'medium';
        }
        
        return 'low';
    }
    
    public function get_memory_usage() {
        $memory_limit = ini_get('memory_limit');
        $memory_usage = memory_get_peak_usage(true);
        
        return array(
            'used' => $this->format_bytes($memory_usage),
            'limit' => $memory_limit,
            'percentage' => round(($memory_usage / $this->parse_size($memory_limit)) * 100, 1)
        );
    }
    
    private function get_database_size() {
        global $wpdb;
        
        $size = $wpdb->get_var($wpdb->prepare("
            SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) as size_mb
            FROM information_schema.tables 
            WHERE table_schema = %s
        ", DB_NAME));
        
        return $size ? $size . ' MB' : '0 MB';
    }
    
    private function get_average_response_time() {
        // Calculate based on recent response times stored in logs
        $response_times = get_transient('bitek_response_times') ?: array();
        
        if (empty($response_times)) {
            return 'N/A';
        }
        
        $average = array_sum($response_times) / count($response_times);
        return round($average, 2) . 'ms';
    }
    
    private function get_threat_feeds_last_update() {
        $last_update = get_transient('bitek_threat_last_update');
        
        if (!$last_update) {
            return 'Never';
        }
        
        return $this->format_time_ago(date('Y-m-d H:i:s', $last_update));
    }
    
    private function get_known_malicious_ips_count() {
        $threat_ips = get_transient('bitek_threat_ips') ?: array();
        return count($threat_ips);
    }
    
    private function get_suspicious_domains_count() {
        $threat_domains = get_transient('bitek_threat_domains') ?: array();
        return count($threat_domains);
    }
    
    public function get_wordpress_version_status() {
        global $wp_version;
        
        $latest_version = get_transient('bitek_wp_latest_version');
        
        if (!$latest_version) {
            // Check WordPress.org API for latest version
            $response = wp_remote_get('https://api.wordpress.org/core/version-check/1.7/');
            
            if (!is_wp_error($response)) {
                $body = wp_remote_retrieve_body($response);
                $data = json_decode($body, true);
                
                if (isset($data['offers'][0]['version'])) {
                    $latest_version = $data['offers'][0]['version'];
                    set_transient('bitek_wp_latest_version', $latest_version, DAY_IN_SECONDS);
                }
            }
        }
        
        if (!$latest_version) {
            return array('status' => 'unknown', 'message' => 'Unable to check version');
        }
        
        if (version_compare($wp_version, $latest_version, '>=')) {
            return array('status' => 'up_to_date', 'message' => 'WordPress is up to date');
        } else {
            return array('status' => 'outdated', 'message' => "Update available: {$latest_version}");
        }
    }
    
    private function get_plugin_vulnerability_count() {
        // Check for known vulnerable plugins
        $vulnerable_plugins = 0;
        $active_plugins = get_option('active_plugins', array());
        
        foreach ($active_plugins as $plugin) {
            $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin);
            
            // This would integrate with vulnerability databases
            // For now, check for very old plugins (simplified approach)
            if (isset($plugin_data['Version'])) {
                $version_age = $this->get_plugin_version_age($plugin_data['Version']);
                if ($version_age > 365) { // Older than 1 year
                    $vulnerable_plugins++;
                }
            }
        }
        
        return $vulnerable_plugins;
    }
    
    private function get_plugin_version_age($version) {
        // Simplified version age calculation
        // In production, this would check against plugin repository data
        
        // Look for date patterns in version number
        if (preg_match('/(\d{4})/', $version, $matches)) {
            $year = intval($matches[1]);
            $current_year = date('Y');
            
            if ($year >= 2020 && $year <= $current_year) {
                return ($current_year - $year) * 365;
            }
        }
        
        return 0; // Unknown age
    }
    
    private function get_file_integrity_violations() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $count = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type = 'file_integrity_violation'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");
        
        return intval($count);
    }
    
    private function get_login_attempts_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $count = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type IN ('login_success', 'login_failed')
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        return intval($count);
    }
    
    private function get_failed_logins_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $count = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type = 'login_failed'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        return intval($count);
    }
    
    private function get_admin_access_attempts() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $count = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE (type = 'admin_access_denied' OR event LIKE '%admin%')
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        return intval($count);
    }
    
    public function get_weekly_trends() {
        global $wpdb;
        
        $cached_trends = get_transient('bitek_weekly_trends');
        if ($cached_trends !== false) {
            return $cached_trends;
        }
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $trends = $wpdb->get_results("
            SELECT 
                DATE(created_at) as date,
                COUNT(CASE WHEN type LIKE '%blocked%' THEN 1 END) as blocked_count,
                COUNT(CASE WHEN type LIKE '%comment%' THEN 1 END) as spam_count,
                COUNT(CASE WHEN type = 'malware_detected' THEN 1 END) as malware_count,
                COUNT(CASE WHEN type = 'login_failed' THEN 1 END) as failed_login_count
            FROM {$table_name}
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        ");
        
        set_transient('bitek_weekly_trends', $trends, 3600); // Cache for 1 hour
        
        return $trends;
    }
    
    public function get_hourly_activity() {
        global $wpdb;
        
        $cached_activity = get_transient('bitek_hourly_activity');
        if ($cached_activity !== false) {
            return $cached_activity;
        }
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $activity = $wpdb->get_results("
            SELECT 
                HOUR(created_at) as hour,
                COUNT(*) as activity_count,
                COUNT(CASE WHEN type LIKE '%blocked%' THEN 1 END) as blocked_count
            FROM {$table_name}
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY HOUR(created_at)
            ORDER BY hour ASC
        ");
        
        // Fill missing hours with 0
        $hourly_data = array();
        for ($i = 0; $i < 24; $i++) {
            $hourly_data[$i] = array(
                'hour' => $i,
                'activity_count' => 0,
                'blocked_count' => 0
            );
        }
        
        foreach ($activity as $hour_data) {
            $hourly_data[$hour_data->hour] = array(
                'hour' => $hour_data->hour,
                'activity_count' => $hour_data->activity_count,
                'blocked_count' => $hour_data->blocked_count
            );
        }
        
        set_transient('bitek_hourly_activity', array_values($hourly_data), 1800); // Cache for 30 minutes
        
        return array_values($hourly_data);
    }
    
    public function get_top_blocked_countries($limit = 10) {
        global $wpdb;
        
        $cached_countries = get_transient('bitek_blocked_countries');
        if ($cached_countries !== false) {
            return $cached_countries;
        }
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        // Get IPs that have been blocked
        $blocked_ips = $wpdb->get_results("
            SELECT ip, COUNT(*) as block_count
            FROM {$table_name}
            WHERE type LIKE '%blocked%'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            AND ip IS NOT NULL
            AND ip != 'Unknown'
            GROUP BY ip
            ORDER BY block_count DESC
            LIMIT 50
        ");
        
        // Group by country (simplified IP-to-country mapping)
        $countries = array();
        $total_blocks = 0;
        
        foreach ($blocked_ips as $ip_data) {
            $country = $this->ip_to_country($ip_data->ip);
            
            if (!isset($countries[$country])) {
                $countries[$country] = 0;
            }
            
            $countries[$country] += $ip_data->block_count;
            $total_blocks += $ip_data->block_count;
        }
        
        arsort($countries);
        $countries = array_slice($countries, 0, $limit, true);
        
        // Calculate percentages
        $result = array();
        foreach ($countries as $country => $count) {
            $percentage = $total_blocks > 0 ? round(($count / $total_blocks) * 100, 1) : 0;
            $result[] = array(
                'country' => $country,
                'count' => $count,
                'percentage' => $percentage
            );
        }
        
        set_transient('bitek_blocked_countries', $result, 3600); // Cache for 1 hour
        
        return $result;
    }
    
    private function ip_to_country($ip) {
        // Simplified IP to country mapping
        // In production, this would use a GeoIP service or database
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return 'Unknown';
        }
        
        // Basic IP range to country mapping (very simplified)
        $ip_long = ip2long($ip);
        
        if ($ip_long === false) {
            return 'Unknown';
        }
        
        // This is a very basic example - use a proper GeoIP service in production
        $ranges = array(
            array('start' => ip2long('5.0.0.0'), 'end' => ip2long('5.255.255.255'), 'country' => 'Russia'),
            array('start' => ip2long('14.0.0.0'), 'end' => ip2long('14.255.255.255'), 'country' => 'China'),
            array('start' => ip2long('46.0.0.0'), 'end' => ip2long('46.255.255.255'), 'country' => 'Europe'),
            array('start' => ip2long('91.0.0.0'), 'end' => ip2long('91.255.255.255'), 'country' => 'Middle East'),
            array('start' => ip2long('103.0.0.0'), 'end' => ip2long('103.255.255.255'), 'country' => 'Asia Pacific'),
            array('start' => ip2long('125.0.0.0'), 'end' => ip2long('125.255.255.255'), 'country' => 'Asia'),
        );
        
        foreach ($ranges as $range) {
            if ($ip_long >= $range['start'] && $ip_long <= $range['end']) {
                return $range['country'];
            }
        }
        
        return 'Other';
    }
    
    public function get_attack_vectors_breakdown() {
        global $wpdb;
        
        $cached_vectors = get_transient('bitek_attack_vectors');
        if ($cached_vectors !== false) {
            return $cached_vectors;
        }
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $vectors = $wpdb->get_results("
            SELECT 
                CASE 
                    WHEN type LIKE '%comment%' THEN 'Comment Spam'
                    WHEN type = 'firewall_blocked' AND event LIKE '%SQL%' THEN 'SQL Injection'
                    WHEN type = 'firewall_blocked' AND event LIKE '%XSS%' THEN 'XSS Attempts'
                    WHEN type = 'firewall_blocked' AND event LIKE '%command%' THEN 'Command Injection'
                    WHEN type = 'firewall_blocked' AND event LIKE '%file%' THEN 'File Inclusion'
                    WHEN type LIKE '%login%' THEN 'Brute Force'
                    WHEN type = 'malware_detected' THEN 'Malware'
                    WHEN type = 'firewall_blocked' THEN 'Web Attack'
                    ELSE 'Other'
                END as attack_type,
                COUNT(*) as count
            FROM {$table_name}
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            AND (type LIKE '%blocked%' OR type LIKE '%detected%' OR type LIKE '%failed%')
            GROUP BY attack_type
            ORDER BY count DESC
        ");
        
        set_transient('bitek_attack_vectors', $vectors, 3600); // Cache for 1 hour
        
        return $vectors;
    }
    
    public function get_security_score() {
        $cached_score = get_transient('bitek_security_score');
        if ($cached_score !== false) {
            return $cached_score;
        }
        
        $score = 100;
        $recommendations = array();
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        // Check for recent malware detections
        $malware_count = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type = 'malware_detected'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");
        
        if ($malware_count > 0) {
            $score -= min($malware_count * 15, 40);
            $recommendations[] = 'Clean up detected malware immediately';
        }
        
        // Check for failed login attempts
        $failed_logins = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type = 'login_failed'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        if ($failed_logins > 50) {
            $score -= 25;
            $recommendations[] = 'High number of failed login attempts detected';
        } elseif ($failed_logins > 20) {
            $score -= 15;
            $recommendations[] = 'Consider strengthening login security';
        }
        
        // Check for high-risk blocked requests
        $high_risk_blocks = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type = 'firewall_blocked'
            AND (event LIKE '%SQL%' OR event LIKE '%XSS%' OR event LIKE '%command%')
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        if ($high_risk_blocks > 10) {
            $score -= 20;
            $recommendations[] = 'Multiple high-risk attack attempts blocked';
        }
        
        // Check WordPress version
        $wp_status = $this->get_wordpress_version_status();
        if ($wp_status['status'] === 'outdated') {
            $score -= 15;
            $recommendations[] = 'Update WordPress to latest version';
        }
        
        // Check for file integrity violations
        $integrity_violations = $this->get_file_integrity_violations();
        if ($integrity_violations > 0) {
            $score -= min($integrity_violations * 10, 30);
            $recommendations[] = 'File integrity violations detected';
        }
        
        // Check plugin vulnerabilities
        $vulnerable_plugins = $this->get_plugin_vulnerability_count();
        if ($vulnerable_plugins > 0) {
            $score -= min($vulnerable_plugins * 5, 20);
            $recommendations[] = 'Update or remove vulnerable plugins';
        }
        
        // Check if AI protection is enabled
        if (empty($this->options['huggingface_api_key'])) {
            $score -= 10;
            $recommendations[] = 'Enable AI-powered threat detection';
        }
        
        // Ensure score doesn't go below 0
        $score = max($score, 0);
        
        $result = array(
            'score' => $score,
            'grade' => $this->get_security_grade($score),
            'recommendations' => $recommendations,
            'last_updated' => current_time('mysql')
        );
        
        set_transient('bitek_security_score', $result, 1800); // Cache for 30 minutes
        
        return $result;
    }
    
    private function get_security_grade($score) {
        if ($score >= 95) return 'A+';
        if ($score >= 90) return 'A';
        if ($score >= 85) return 'A-';
        if ($score >= 80) return 'B+';
        if ($score >= 75) return 'B';
        if ($score >= 70) return 'B-';
        if ($score >= 65) return 'C+';
        if ($score >= 60) return 'C';
        if ($score >= 55) return 'C-';
        if ($score >= 50) return 'D';
        return 'F';
    }
    
    public function get_real_time_metrics() {
        return array(
            'current_threats' => $this->get_current_active_threats(),
            'requests_per_minute' => $this->get_current_request_rate(),
            'memory_usage' => $this->get_current_memory_usage(),
            'cpu_load' => $this->get_current_cpu_load(),
            'active_sessions' => $this->get_active_user_sessions()
        );
    }
    
    private function get_current_active_threats() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        return $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type LIKE '%blocked%'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        ") ?: 0;
    }
    
    private function get_current_request_rate() {
        $today = date('Y-m-d');
        $current_hour = date('H');
        $hourly_requests = get_transient("bitek_hourly_requests_{$today}_{$current_hour}") ?: 0;
        
        return round($hourly_requests / 60, 1); // Approximate requests per minute
    }
    
    private function get_current_memory_usage() {
        return round(memory_get_usage(true) / 1024 / 1024, 2); // MB
    }
    
    private function get_current_cpu_load() {
        if (function_exists('sys_getloadavg')) {
            $load = sys_getloadavg();
            return round($load[0], 2);
        }
        
        return 'N/A';
    }
    
    private function get_active_user_sessions() {
        global $wpdb;
        
        // Count active user sessions from the last hour
        $active_sessions = $wpdb->get_var("
            SELECT COUNT(DISTINCT user_id) FROM {$wpdb->usermeta}
            WHERE meta_key = 'session_tokens'
            AND meta_value != ''
        ");
        
        return intval($active_sessions);
    }
    
    public function export_security_report($format = 'json') {
        $report = array(
            'report_info' => array(
                'generated_at' => current_time('mysql'),
                'site_url' => get_site_url(),
                'wordpress_version' => get_bloginfo('version'),
                'plugin_version' => defined('BITEK_AI_SECURITY_VERSION') ? BITEK_AI_SECURITY_VERSION : '1.0.0',
                'report_period' => '30 days'
            ),
            'dashboard_stats' => $this->get_dashboard_stats(),
            'security_score' => $this->get_security_score(),
            'weekly_trends' => $this->get_weekly_trends(),
            'hourly_activity' => $this->get_hourly_activity(),
            'top_blocked_countries' => $this->get_top_blocked_countries(),
            'attack_vectors' => $this->get_attack_vectors_breakdown(),
            'real_time_metrics' => $this->get_real_time_metrics()
        );
        
        switch ($format) {
            case 'csv':
                return $this->export_to_csv($report);
            case 'xml':
                return $this->export_to_xml($report);
            default:
                return wp_json_encode($report, JSON_PRETTY_PRINT);
        }
    }
    
    private function export_to_csv($data) {
        $csv = "BiTek AI Security Report - " . current_time('Y-m-d H:i:s') . "\n\n";
        
        // Dashboard Statistics
        $csv .= "Dashboard Statistics\n";
        $csv .= "Metric,Value\n";
        foreach ($data['dashboard_stats'] as $key => $value) {
            if (!is_array($value) && !is_object($value)) {
                $csv .= "{$key}," . (is_numeric($value) ? $value : '"' . str_replace('"', '""', $value) . '"') . "\n";
            }
        }
        
        $csv .= "\nSecurity Score\n";
        $csv .= "Score," . $data['security_score']['score'] . "\n";
        $csv .= "Grade," . $data['security_score']['grade'] . "\n";
        
        $csv .= "\nAttack Vectors (Last 30 Days)\n";
        $csv .= "Attack Type,Count\n";
        foreach ($data['attack_vectors'] as $vector) {
            $csv .= "{$vector->attack_type},{$vector->count}\n";
        }
        
        $csv .= "\nTop Blocked Countries\n";
        $csv .= "Country,Count,Percentage\n";
        foreach ($data['top_blocked_countries'] as $country) {
            $csv .= "{$country['country']},{$country['count']},{$country['percentage']}%\n";
        }
        
        return $csv;
    }
    
    private function export_to_xml($data) {
        $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><security_report></security_report>');
        
        // Report info
        $report_info = $xml->addChild('report_info');
        foreach ($data['report_info'] as $key => $value) {
            $report_info->addChild($key, htmlspecialchars($value));
        }
        
        // Dashboard stats
        $stats = $xml->addChild('dashboard_stats');
        foreach ($data['dashboard_stats'] as $key => $value) {
            if (!is_array($value) && !is_object($value)) {
                $stats->addChild($key, htmlspecialchars($value));
            }
        }
        
        // Security score
        $score = $xml->addChild('security_score');
        $score->addChild('score', $data['security_score']['score']);
        $score->addChild('grade', $data['security_score']['grade']);
        
        // Attack vectors
        $vectors = $xml->addChild('attack_vectors');
        foreach ($data['attack_vectors'] as $vector) {
            $vector_node = $vectors->addChild('vector');
            $vector_node->addChild('type', htmlspecialchars($vector->attack_type));
            $vector_node->addChild('count', $vector->count);
        }
        
        return $xml->asXML();
    }
    
    // Utility methods
    private function format_bytes($size, $precision = 2) {
        $units = array('B', 'KB', 'MB', 'GB', 'TB');
        
        for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
            $size /= 1024;
        }
        
        return round($size, $precision) . ' ' . $units[$i];
    }
    
    private function parse_size($size) {
        $unit = strtoupper(substr($size, -1));
        $value = intval($size);
        
        switch ($unit) {
            case 'G':
                $value *= 1024;
            case 'M':
                $value *= 1024;
            case 'K':
                $value *= 1024;
        }
        
        return $value;
    }
    
    private function get_client_ip() {
        $ip_headers = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip_list = $_SERVER[$header];
                
                if (strpos($ip_list, ',') !== false) {
                    $ip_array = explode(',', $ip_list);
                    $ip = trim($ip_array[0]);
                } else {
                    $ip = trim($ip_list);
                }
                
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    // Performance tracking methods
    public function track_response_time($start_time = null) {
        if ($start_time === null) {
            return microtime(true);
        }
        
        $response_time = (microtime(true) - $start_time) * 1000; // Convert to milliseconds
        
        // Store in transient for analytics
        $response_times = get_transient('bitek_response_times') ?: array();
        $response_times[] = $response_time;
        
        // Keep only last 100 response times
        if (count($response_times) > 100) {
            $response_times = array_slice($response_times, -100);
        }
        
        set_transient('bitek_response_times', $response_times, 3600);
        
        return $response_time;
    }
    
    public function increment_request_counter() {
        $today = date('Y-m-d');
        $current_hour = date('H');
        
        // Increment hourly counter
        $hourly_key = "bitek_hourly_requests_{$today}_{$current_hour}";
        $hourly_count = get_transient($hourly_key) ?: 0;
        set_transient($hourly_key, $hourly_count + 1, 3600);
        
        // Increment daily counter
        $daily_key = "bitek_daily_requests_{$today}";
        $daily_count = get_transient($daily_key) ?: 0;
        set_transient($daily_key, $daily_count + 1, DAY_IN_SECONDS);
    }
    
    // Cleanup methods
    public function cleanup_old_stats() {
        global $wpdb;
        
        // Clean up old transients
        $wpdb->query("
            DELETE FROM {$wpdb->options}
            WHERE option_name LIKE '_transient_bitek_%'
            AND option_name LIKE '%_2%'
            AND option_name < CONCAT('_transient_bitek_', DATE_FORMAT(DATE_SUB(NOW(), INTERVAL 7 DAY), '%Y-%m-%d'))
        ");
        
        // Clean up old daily view counters
        $wpdb->query("
            DELETE FROM {$wpdb->options}
            WHERE option_name LIKE '_transient_bitek_daily_views_%'
            AND option_name < CONCAT('_transient_bitek_daily_views_', DATE_FORMAT(DATE_SUB(NOW(), INTERVAL 30 DAY), '%Y-%m-%d'))
        ");
        
        // Clean up old visitor data
        $wpdb->query("
            DELETE FROM {$wpdb->options}
            WHERE option_name LIKE '_transient_bitek_visitors_%'
            AND option_name < CONCAT('_transient_bitek_visitors_', DATE_FORMAT(DATE_SUB(NOW(), INTERVAL 7 DAY), '%Y-%m-%d'))
        ");
    }
    
    // Health check methods
    public function perform_health_check() {
        $health_status = array(
            'overall_status' => 'good',
            'checks' => array(),
            'timestamp' => current_time('mysql')
        );
        
        // Database connectivity
        global $wpdb;
        try {
            $wpdb->get_var("SELECT 1");
            $health_status['checks']['database'] = array('status' => 'pass', 'message' => 'Database connection successful');
        } catch (Exception $e) {
            $health_status['checks']['database'] = array('status' => 'fail', 'message' => 'Database connection failed');
            $health_status['overall_status'] = 'critical';
        }
        
        // Memory usage check
        $memory_usage = $this->get_memory_usage();
        if ($memory_usage['percentage'] > 90) {
            $health_status['checks']['memory'] = array('status' => 'warn', 'message' => 'High memory usage: ' . $memory_usage['percentage'] . '%');
            if ($health_status['overall_status'] === 'good') {
                $health_status['overall_status'] = 'warning';
            }
        } else {
            $health_status['checks']['memory'] = array('status' => 'pass', 'message' => 'Memory usage normal: ' . $memory_usage['percentage'] . '%');
        }
        
        // Disk space check (if available)
        if (function_exists('disk_free_space')) {
            $free_space = disk_free_space(ABSPATH);
            $total_space = disk_total_space(ABSPATH);
            
            if ($free_space && $total_space) {
                $free_percentage = ($free_space / $total_space) * 100;
                
                if ($free_percentage < 10) {
                    $health_status['checks']['disk_space'] = array('status' => 'warn', 'message' => 'Low disk space: ' . round($free_percentage, 1) . '% free');
                    if ($health_status['overall_status'] === 'good') {
                        $health_status['overall_status'] = 'warning';
                    }
                } else {
                    $health_status['checks']['disk_space'] = array('status' => 'pass', 'message' => 'Disk space sufficient: ' . round($free_percentage, 1) . '% free');
                }
            }
        }
        
        // Plugin conflicts check
        if (function_exists('wp_get_active_and_valid_plugins')) {
            $active_plugins = count(wp_get_active_and_valid_plugins());
            if ($active_plugins > 50) {
                $health_status['checks']['plugins'] = array('status' => 'warn', 'message' => "Many active plugins ({$active_plugins}) - may affect performance");
                if ($health_status['overall_status'] === 'good') {
                    $health_status['overall_status'] = 'warning';
                }
            } else {
                $health_status['checks']['plugins'] = array('status' => 'pass', 'message' => "Plugin count normal ({$active_plugins})");
            }
        }
        
        // WordPress update check
        $wp_status = $this->get_wordpress_version_status();
        if ($wp_status['status'] === 'outdated') {
            $health_status['checks']['wordpress_version'] = array('status' => 'warn', 'message' => $wp_status['message']);
            if ($health_status['overall_status'] === 'good') {
                $health_status['overall_status'] = 'warning';
            }
        } else {
            $health_status['checks']['wordpress_version'] = array('status' => 'pass', 'message' => $wp_status['message']);
        }
        
        return $health_status;
    }
    
    // Cache management
    public function clear_stats_cache() {
        $cache_keys = array(
            'bitek_dashboard_stats',
            'bitek_weekly_trends',
            'bitek_hourly_activity',
            'bitek_blocked_countries',
            'bitek_attack_vectors',
            'bitek_security_score'
        );
        
        foreach ($cache_keys as $key) {
            delete_transient($key);
        }
        
        return true;
    }
    
    public function get_cache_status() {
        $cache_keys = array(
            'dashboard_stats' => 'bitek_dashboard_stats',
            'weekly_trends' => 'bitek_weekly_trends',
            'hourly_activity' => 'bitek_hourly_activity',
            'blocked_countries' => 'bitek_blocked_countries',
            'attack_vectors' => 'bitek_attack_vectors',
            'security_score' => 'bitek_security_score'
        );
        
        $cache_status = array();
        
        foreach ($cache_keys as $name => $key) {
            $cached_data = get_transient($key);
            $cache_status[$name] = array(
                'cached' => ($cached_data !== false),
                'expires' => $cached_data ? get_option("_transient_timeout_{$key}") : null
            );
        }
        
        return $cache_status;
    }
    
    // Debugging and logging
    public function log_stats_error($message, $context = array()) {
        if (class_exists('BiTek_AI_Security_Guard')) {
            $instance = BiTek_AI_Security_Guard::get_instance();
            if (method_exists($instance, 'bitek_log_security_event')) {
                $instance->bitek_log_security_event('stats_error', $message, $context);
            }
        }
        
        // Also log to PHP error log for debugging
        error_log("BiTek Stats Error: {$message} " . wp_json_encode($context));
    }
    
    public function validate_stats_data($stats) {
        $required_fields = array(
            'high_risk_events',
            'blocked_requests',
            'spam_comments',
            'blocked_ips',
            'ai_analyzed',
            'ai_confidence'
        );
        
        $validation_errors = array();
        
        foreach ($required_fields as $field) {
            if (!isset($stats[$field])) {
                $validation_errors[] = "Missing required field: {$field}";
            } elseif (!is_numeric($stats[$field])) {
                $validation_errors[] = "Field {$field} must be numeric";
            }
        }
        
        if (!empty($validation_errors)) {
            $this->log_stats_error('Stats validation failed', array('errors' => $validation_errors));
            return false;
        }
        
        return true;
    }
}
?>