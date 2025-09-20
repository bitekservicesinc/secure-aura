<?php
/**
 * AJAX Request Handler for SecureAura
 *
 * Handles all AJAX requests from the admin interface
 *
 * @link       https://secureaura.pro
 * @since      3.0.0
 *
 * @package    SecureAura
 * @subpackage SecureAura/admin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * AJAX Request Handler Class
 *
 * Manages all AJAX endpoints for the admin interface including:
 * - Emergency lockdown toggle
 * - IP management (block/unblock)
 * - Security scanning
 * - Real-time monitoring
 * - Settings management
 *
 * @since      3.0.0
 * @package    SecureAura
 * @subpackage SecureAura/admin
 * @author     SecureAura Team
 */
class Secure_Aura_Ajax_Handler {

    /**
     * Main plugin instance.
     *
     * @since    3.0.0
     * @access   private
     * @var      object    $plugin    Main plugin instance.
     */
    private $plugin;

    /**
     * Plugin configuration.
     *
     * @since    3.0.0
     * @access   private
     * @var      array    $config    Plugin configuration.
     */
    private $config;

    /**
     * Initialize the AJAX handler.
     *
     * @since    3.0.0
     * @param    object $plugin Main plugin instance.
     */
    public function __construct($plugin) {
        $this->plugin = $plugin;
        $this->config = $plugin->get_config();
        
        $this->init_ajax_hooks();
    }

    /**
     * Initialize AJAX hooks.
     *
     * @since    3.0.0
     */
    private function init_ajax_hooks() {
        // Emergency Mode
        add_action('wp_ajax_secure_aura_toggle_emergency', [$this, 'handle_toggle_emergency']);
        
        // IP Management
        add_action('wp_ajax_secure_aura_block_ip', [$this, 'handle_block_ip']);
        add_action('wp_ajax_secure_aura_unblock_ip', [$this, 'handle_unblock_ip']);
        add_action('wp_ajax_secure_aura_get_blocked_ips', [$this, 'handle_get_blocked_ips']);
        add_action('wp_ajax_secure_aura_get_ip_info', [$this, 'handle_get_ip_info']);
        
        // Scanner Operations
        add_action('wp_ajax_secure_aura_run_scan', [$this, 'handle_run_scan']);
        add_action('wp_ajax_secure_aura_get_scan_status', [$this, 'handle_get_scan_status']);
        add_action('wp_ajax_secure_aura_cancel_scan', [$this, 'handle_cancel_scan']);
        
        // Dashboard Data
        add_action('wp_ajax_secure_aura_get_dashboard_data', [$this, 'handle_get_dashboard_data']);
        add_action('wp_ajax_secure_aura_get_real_time_stats', [$this, 'handle_get_real_time_stats']);
        
        // Threat Management
        add_action('wp_ajax_secure_aura_quarantine_file', [$this, 'handle_quarantine_file']);
        add_action('wp_ajax_secure_aura_restore_file', [$this, 'handle_restore_file']);
        add_action('wp_ajax_secure_aura_delete_quarantined', [$this, 'handle_delete_quarantined']);
        
        // Settings
        add_action('wp_ajax_secure_aura_save_settings', [$this, 'handle_save_settings']);
        add_action('wp_ajax_secure_aura_reset_settings', [$this, 'handle_reset_settings']);
        
        // System Info
        add_action('wp_ajax_secure_aura_get_system_info', [$this, 'handle_get_system_info']);
        add_action('wp_ajax_secure_aura_download_logs', [$this, 'handle_download_logs']);
        
        // Threat Intelligence
        add_action('wp_ajax_secure_aura_update_threat_intel', [$this, 'handle_update_threat_intel']);
    }

    /**
     * Handle emergency mode toggle.
     *
     * @since    3.0.0
     */
    public function handle_toggle_emergency() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_emergency_nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'secure-aura')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions.', 'secure-aura')]);
        }

        $current_mode = get_option('secure_aura_emergency_mode', false);
        $new_mode = !$current_mode;
        
        try {
            // Toggle emergency mode
            update_option('secure_aura_emergency_mode', $new_mode);
            
            if ($new_mode) {
                $this->activate_emergency_mode();
                $message = __('Emergency mode activated! Maximum security protection is now active.', 'secure-aura');
                $status = 'activated';
            } else {
                $this->deactivate_emergency_mode();
                $message = __('Emergency mode deactivated. Normal security level restored.', 'secure-aura');
                $status = 'deactivated';
            }
            
            // Log the action
            $this->log_emergency_action($new_mode);
            
            wp_send_json_success([
                'emergency_mode' => $new_mode,
                'status' => $status,
                'message' => $message,
                'button_text' => $new_mode ? __('Disable Emergency', 'secure-aura') : __('Emergency Mode', 'secure-aura')
            ]);
            
        } catch (Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Handle block IP request.
     *
     * @since    3.0.0
     */
    public function handle_block_ip() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_ip_nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'secure-aura')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions.', 'secure-aura')]);
        }

        $ip_address = sanitize_text_field($_POST['ip_address']);
        $reason = sanitize_text_field($_POST['reason'] ?? 'Manual block');
        $duration = intval($_POST['duration'] ?? 0); // 0 = permanent

        // Validate IP
        if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
            wp_send_json_error(['message' => __('Invalid IP address.', 'secure-aura')]);
        }

        // Don't block current user's IP
        if ($ip_address === $this->get_client_ip()) {
            wp_send_json_error(['message' => __('Cannot block your own IP address.', 'secure-aura')]);
        }

        try {
            $result = $this->block_ip_address($ip_address, $reason, $duration);
            
            if ($result['success']) {
                wp_send_json_success([
                    'message' => sprintf(__('IP %s has been blocked successfully.', 'secure-aura'), $ip_address),
                    'ip_data' => $result['ip_data']
                ]);
            } else {
                wp_send_json_error(['message' => $result['message']]);
            }
            
        } catch (Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Handle unblock IP request.
     *
     * @since    3.0.0
     */
    public function handle_unblock_ip() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_ip_nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'secure-aura')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions.', 'secure-aura')]);
        }

        $ip_address = sanitize_text_field($_POST['ip_address']);

        // Validate IP
        if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
            wp_send_json_error(['message' => __('Invalid IP address.', 'secure-aura')]);
        }

        try {
            $result = $this->unblock_ip_address($ip_address);
            
            if ($result['success']) {
                wp_send_json_success([
                    'message' => sprintf(__('IP %s has been unblocked successfully.', 'secure-aura'), $ip_address)
                ]);
            } else {
                wp_send_json_error(['message' => $result['message']]);
            }
            
        } catch (Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Handle get blocked IPs request.
     *
     * @since    3.0.0
     */
    public function handle_get_blocked_ips() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_ajax_nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'secure-aura')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions.', 'secure-aura')]);
        }

        $page = intval($_POST['page'] ?? 1);
        $per_page = intval($_POST['per_page'] ?? 20);
        $search = sanitize_text_field($_POST['search'] ?? '');

        try {
            $blocked_ips = $this->get_blocked_ips_list($page, $per_page, $search);
            wp_send_json_success($blocked_ips);
            
        } catch (Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Handle get IP info request.
     *
     * @since    3.0.0
     */
    public function handle_get_ip_info() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_ajax_nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'secure-aura')]);
        }

        $ip_address = sanitize_text_field($_POST['ip_address']);

        // Validate IP
        if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
            wp_send_json_error(['message' => __('Invalid IP address.', 'secure-aura')]);
        }

        try {
            $ip_info = $this->get_ip_information($ip_address);
            wp_send_json_success($ip_info);
            
        } catch (Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Handle scan request.
     *
     * @since    3.0.0
     */
    public function handle_run_scan() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_scan_nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'secure-aura')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions.', 'secure-aura')]);
        }

        // Check if scan is already running
        if (get_transient('secure_aura_scan_in_progress')) {
            wp_send_json_error(['message' => __('A scan is already in progress.', 'secure-aura')]);
        }

        $scan_type = sanitize_text_field($_POST['scan_type'] ?? 'quick');
        
        try {
            // Initialize scanner
            if (class_exists('Secure_Aura_Malware_Scanner')) {
                $scanner = new Secure_Aura_Malware_Scanner($this->config);
                
                if ($scan_type === 'quick') {
                    $result = $scanner->run_quick_scan();
                } else {
                    $result = $scanner->run_full_scan();
                }
                
                wp_send_json_success([
                    'scan_id' => $result['scan_id'],
                    'message' => __('Security scan started successfully.', 'secure-aura'),
                    'scan_type' => $scan_type
                ]);
            } else {
                wp_send_json_error(['message' => __('Scanner module not available.', 'secure-aura')]);
            }
            
        } catch (Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Handle get scan status request.
     *
     * @since    3.0.0
     */
    public function handle_get_scan_status() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_ajax_nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'secure-aura')]);
        }

        try {
            $scan_progress = get_transient('secure_aura_scan_progress');
            $scan_in_progress = get_transient('secure_aura_scan_in_progress');
            
            if ($scan_progress && $scan_in_progress) {
                wp_send_json_success([
                    'status' => 'running',
                    'progress' => $scan_progress,
                    'in_progress' => true
                ]);
            } else {
                $last_scan = get_option('secure_aura_last_scan_results', []);
                wp_send_json_success([
                    'status' => 'completed',
                    'last_scan' => $last_scan,
                    'in_progress' => false
                ]);
            }
            
        } catch (Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Handle get dashboard data request.
     *
     * @since    3.0.0
     */
    public function handle_get_dashboard_data() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_ajax_nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'secure-aura')]);
        }

        try {
            $dashboard_data = [
                'security_score' => $this->calculate_security_score(),
                'threats_blocked_today' => $this->get_threats_blocked_today(),
                'recent_activities' => $this->get_recent_activities(10),
                'system_health' => $this->get_system_health_status(),
                'emergency_mode' => get_option('secure_aura_emergency_mode', false),
                'last_scan' => get_option('secure_aura_last_scan_time', ''),
                'scan_status' => $this->get_current_scan_status()
            ];
            
            wp_send_json_success($dashboard_data);
            
        } catch (Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Handle get system info request.
     *
     * @since    3.0.0
     */
    public function handle_get_system_info() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_ajax_nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'secure-aura')]);
        }

        try {
            $system_info = $this->collect_system_information();
            wp_send_json_success($system_info);
            
        } catch (Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Activate emergency mode.
     *
     * @since    3.0.0
     */
    private function activate_emergency_mode() {
        // Update security settings to maximum
        $emergency_settings = [
            'security_level' => SECURE_AURA_LEVEL_FORTRESS,
            'firewall_mode' => 'blocking',
            'auto_block_malicious_ips' => true,
            'brute_force_protection' => true,
            'rate_limiting_enabled' => true,
            'geo_blocking_enabled' => true,
            'tor_blocking_enabled' => true,
            'vpn_blocking_enabled' => true
        ];
        
        foreach ($emergency_settings as $key => $value) {
            update_option('secure_aura_' . $key, $value);
        }
        
        // Clear all caches
        wp_cache_flush();
        
        // Update .htaccess if possible
        $this->update_htaccess_emergency_rules();
    }

    /**
     * Deactivate emergency mode.
     *
     * @since    3.0.0
     */
    private function deactivate_emergency_mode() {
        // Restore normal settings
        $normal_settings = [
            'security_level' => SECURE_AURA_LEVEL_ENHANCED,
            'firewall_mode' => 'learning',
            'geo_blocking_enabled' => false,
            'tor_blocking_enabled' => false,
            'vpn_blocking_enabled' => false
        ];
        
        foreach ($normal_settings as $key => $value) {
            update_option('secure_aura_' . $key, $value);
        }
        
        // Remove emergency .htaccess rules
        $this->remove_htaccess_emergency_rules();
    }

    /**
     * Block IP address.
     *
     * @since    3.0.0
     * @param    string $ip_address IP to block.
     * @param    string $reason     Block reason.
     * @param    int    $duration   Block duration in hours (0 = permanent).
     * @return   array  Operation result.
     */
    private function block_ip_address($ip_address, $reason, $duration = 0) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
        
        // Check if IP is already blocked
        $existing = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table_name} WHERE ip_address = %s",
            $ip_address
        ));
        
        if ($existing) {
            return [
                'success' => false,
                'message' => __('IP address is already blocked.', 'secure-aura')
            ];
        }
        
        // Calculate expiration
        $expires_at = null;
        if ($duration > 0) {
            $expires_at = date('Y-m-d H:i:s', time() + ($duration * 3600));
        }
        
        // Get IP info
        $ip_info = $this->get_ip_geolocation($ip_address);
        
        // Insert blocked IP
        $result = $wpdb->insert($table_name, [
            'ip_address' => $ip_address,
            'block_reason' => $reason,
            'threat_type' => 'manual_block',
            'confidence_score' => 1.0,
            'blocked_at' => current_time('mysql'),
            'expires_at' => $expires_at,
            'is_permanent' => $duration === 0,
            'is_manual' => true,
            'blocked_by_user_id' => get_current_user_id(),
            'geo_country' => $ip_info['country'] ?? '',
            'geo_region' => $ip_info['region'] ?? '',
            'asn' => $ip_info['asn'] ?? '',
            'organization' => $ip_info['organization'] ?? ''
        ]);
        
        if ($result) {
            // Log the action
            $this->log_ip_block_action($ip_address, $reason);
            
            // Update .htaccess
            $this->update_htaccess_blocked_ips();
            
            return [
                'success' => true,
                'ip_data' => [
                    'ip_address' => $ip_address,
                    'blocked_at' => current_time('mysql'),
                    'expires_at' => $expires_at,
                    'reason' => $reason,
                    'country' => $ip_info['country'] ?? 'Unknown'
                ]
            ];
        }
        
        return [
            'success' => false,
            'message' => __('Failed to block IP address.', 'secure-aura')
        ];
    }

    /**
     * Unblock IP address.
     *
     * @since    3.0.0
     * @param    string $ip_address IP to unblock.
     * @return   array  Operation result.
     */
    private function unblock_ip_address($ip_address) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
        
        $result = $wpdb->delete($table_name, [
            'ip_address' => $ip_address
        ]);
        
        if ($result) {
            // Log the action
            $this->log_ip_unblock_action($ip_address);
            
            // Update .htaccess
            $this->update_htaccess_blocked_ips();
            
            return ['success' => true];
        }
        
        return [
            'success' => false,
            'message' => __('Failed to unblock IP address or IP not found.', 'secure-aura')
        ];
    }

    /**
     * Get blocked IPs list.
     *
     * @since    3.0.0
     * @param    int    $page     Page number.
     * @param    int    $per_page Items per page.
     * @param    string $search   Search term.
     * @return   array  Blocked IPs data.
     */
    private function get_blocked_ips_list($page = 1, $per_page = 20, $search = '') {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
        $offset = ($page - 1) * $per_page;
        
        $where_clause = "WHERE 1=1";
        $search_params = [];
        
        if (!empty($search)) {
            $where_clause .= " AND (ip_address LIKE %s OR block_reason LIKE %s OR geo_country LIKE %s)";
            $search_term = '%' . $search . '%';
            $search_params = [$search_term, $search_term, $search_term];
        }
        
        // Get total count
        $total_query = "SELECT COUNT(*) FROM {$table_name} {$where_clause}";
        $total = $wpdb->get_var($wpdb->prepare($total_query, $search_params));
        
        // Get blocked IPs
        $query = "SELECT * FROM {$table_name} {$where_clause} ORDER BY blocked_at DESC LIMIT %d OFFSET %d";
        $params = array_merge($search_params, [$per_page, $offset]);
        $blocked_ips = $wpdb->get_results($wpdb->prepare($query, $params));
        
        // Format data
        $formatted_ips = array_map(function($ip) {
            return [
                'ip_address' => $ip->ip_address,
                'block_reason' => $ip->block_reason,
                'blocked_at' => $ip->blocked_at,
                'expires_at' => $ip->expires_at,
                'is_permanent' => (bool)$ip->is_permanent,
                'geo_country' => $ip->geo_country,
                'geo_region' => $ip->geo_region,
                'organization' => $ip->organization,
                'attempt_count' => $ip->attempt_count ?? 1,
                'time_ago' => human_time_diff(strtotime($ip->blocked_at), current_time('timestamp'))
            ];
        }, $blocked_ips);
        
        return [
            'ips' => $formatted_ips,
            'total' => intval($total),
            'page' => $page,
            'per_page' => $per_page,
            'total_pages' => ceil($total / $per_page)
        ];
    }

    /**
     * Get IP geolocation information.
     *
     * @since    3.0.0
     * @param    string $ip_address IP address.
     * @return   array  IP information.
     */
    private function get_ip_geolocation($ip_address) {
        // Try to get from cache first
        $cache_key = 'secure_aura_ip_info_' . md5($ip_address);
        $cached_info = get_transient($cache_key);
        
        if ($cached_info !== false) {
            return $cached_info;
        }
        
        $ip_info = [
            'country' => 'Unknown',
            'region' => 'Unknown',
            'city' => 'Unknown',
            'asn' => '',
            'organization' => '',
            'is_tor' => false,
            'is_vpn' => false,
            'is_proxy' => false
        ];
        
        // Try multiple IP info services
        $services = [
            'http://ip-api.com/json/' . $ip_address,
            'https://ipapi.co/' . $ip_address . '/json/',
            'https://api.ipgeolocation.io/ipgeo?apiKey=free&ip=' . $ip_address
        ];
        
        foreach ($services as $service_url) {
            $response = wp_remote_get($service_url, [
                'timeout' => 10,
                'user-agent' => 'SecureAura/' . SECURE_AURA_VERSION
            ]);
            
            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                $data = json_decode(wp_remote_retrieve_body($response), true);
                
                if ($data) {
                    // Parse different API formats
                    $ip_info = $this->parse_ip_info_response($data, $service_url);
                    break;
                }
            }
        }
        
        // Cache for 1 hour
        set_transient($cache_key, $ip_info, HOUR_IN_SECONDS);
        
        return $ip_info;
    }

    /**
     * Calculate security score.
     *
     * @since    3.0.0
     * @return   array Security score data.
     */
    private function calculate_security_score() {
        $score = 0;
        $max_score = 100;
        
        // Plugin active (20 points)
        $score += 20;
        
        // Firewall enabled (25 points)
        if (get_option('secure_aura_quantum_firewall_enabled', true)) {
            $score += 25;
        }
        
        // Recent scan (20 points)
        $last_scan = get_option('secure_aura_last_scan_time', '');
        if ($last_scan && strtotime($last_scan) > (time() - 7 * 24 * 60 * 60)) {
            $score += 20;
        }
        
        // Real-time protection (15 points)
        if (get_option('secure_aura_real_time_scanning_enabled', true)) {
            $score += 15;
        }
        
        // File integrity monitoring (10 points)
        if (get_option('secure_aura_file_integrity_monitoring_enabled', true)) {
            $score += 10;
        }
        
        // Emergency mode (10 points)
        if (get_option('secure_aura_emergency_mode', false)) {
            $score += 10;
        }
        
        // Determine status
        $status = 'good';
        if ($score >= 90) {
            $status = 'excellent';
        } elseif ($score >= 70) {
            $status = 'good';
        } elseif ($score >= 50) {
            $status = 'warning';
        } else {
            $status = 'critical';
        }
        
        return [
            'score' => min($score, $max_score),
            'status' => $status,
            'max_score' => $max_score
        ];
    }

    /**
     * Get threats blocked today.
     *
     * @since    3.0.0
     * @return   int Number of threats blocked today.
     */
    private function get_threats_blocked_today() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $count = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE response_action IN ('block', 'quarantine', 'blocked') 
            AND DATE(created_at) = %s
        ", current_time('Y-m-d')));
        
        return intval($count);
    }

    /**
     * Get recent security activities.
     *
     * @since    3.0.0
     * @param    int $limit Number of activities to retrieve.
     * @return   array Recent activities.
     */
    private function get_recent_activities($limit = 10) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $activities = $wpdb->get_results($wpdb->prepare("
            SELECT * FROM {$table_name} 
            ORDER BY created_at DESC 
            LIMIT %d
        ", $limit));
        
        return array_map(function($activity) {
            return [
                'id' => $activity->id,
                'event_type' => $activity->event_type,
                'severity' => $activity->severity,
                'source_ip' => $activity->source_ip,
                'message' => $this->format_activity_message($activity),
                'time_ago' => human_time_diff(strtotime($activity->created_at), current_time('timestamp')),
                'timestamp' => $activity->created_at
            ];
        }, $activities);
    }

    /**
     * Get system health status.
     *
     * @since    3.0.0
     * @return   array System health information.
     */
    private function get_system_health_status() {
        $health = [
            'status' => 'healthy',
            'issues' => [],
            'metrics' => []
        ];
        
        // Check memory usage
        $memory_limit = wp_convert_hr_to_bytes(ini_get('memory_limit'));
        $memory_usage = memory_get_usage(true);
        $memory_percent = ($memory_usage / $memory_limit) * 100;
        
        $health['metrics']['memory'] = [
            'usage' => $memory_usage,
            'limit' => $memory_limit,
            'percentage' => round($memory_percent, 2)
        ];
        
        if ($memory_percent > 80) {
            $health['status'] = 'warning';
            $health['issues'][] = __('High memory usage detected', 'secure-aura');
        }
        
        // Check disk space
        $disk_free = disk_free_space(ABSPATH);
        $disk_total = disk_total_space(ABSPATH);
        $disk_percent = (($disk_total - $disk_free) / $disk_total) * 100;
        
        $health['metrics']['disk'] = [
            'free' => $disk_free,
            'total' => $disk_total,
            'percentage' => round($disk_percent, 2)
        ];
        
        if ($disk_percent > 90) {
            $health['status'] = 'critical';
            $health['issues'][] = __('Low disk space', 'secure-aura');
        } elseif ($disk_percent > 80) {
            $health['status'] = 'warning';
            $health['issues'][] = __('Disk space running low', 'secure-aura');
        }
        
        // Check database connectivity
        if (!$this->test_database_connection()) {
            $health['status'] = 'critical';
            $health['issues'][] = __('Database connection issues', 'secure-aura');
        }
        
        return $health;
    }

    /**
     * Get current scan status.
     *
     * @since    3.0.0
     * @return   array Scan status information.
     */
    private function get_current_scan_status() {
        $scan_progress = get_transient('secure_aura_scan_progress');
        $scan_in_progress = get_transient('secure_aura_scan_in_progress');
        
        if ($scan_progress && $scan_in_progress) {
            return [
                'status' => 'running',
                'progress' => $scan_progress
            ];
        }
        
        return [
            'status' => 'idle',
            'last_scan' => get_option('secure_aura_last_scan_results', [])
        ];
    }

    /**
     * Collect comprehensive system information.
     *
     * @since    3.0.0
     * @return   array System information.
     */
    private function collect_system_information() {
        global $wpdb;
        
        return [
            'wordpress' => [
                'version' => get_bloginfo('version'),
                'multisite' => is_multisite(),
                'language' => get_locale(),
                'timezone' => wp_timezone_string(),
                'debug_mode' => defined('WP_DEBUG') && WP_DEBUG,
                'memory_limit' => WP_MEMORY_LIMIT,
                'max_upload_size' => size_format(wp_max_upload_size())
            ],
            'server' => [
                'software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
                'php_version' => PHP_VERSION,
                'mysql_version' => $wpdb->db_version(),
                'max_execution_time' => ini_get('max_execution_time'),
                'memory_limit' => ini_get('memory_limit'),
                'post_max_size' => ini_get('post_max_size'),
                'upload_max_filesize' => ini_get('upload_max_filesize'),
                'max_input_vars' => ini_get('max_input_vars')
            ],
            'secure_aura' => [
                'version' => SECURE_AURA_VERSION,
                'database_version' => get_option('secure_aura_db_version', '0'),
                'license_type' => get_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE),
                'emergency_mode' => get_option('secure_aura_emergency_mode', false),
                'last_scan' => get_option('secure_aura_last_scan_time', 'Never'),
                'threats_blocked' => $this->get_total_threats_blocked(),
                'active_modules' => $this->get_active_modules()
            ],
            'security' => [
                'ssl_enabled' => is_ssl(),
                'file_editor_disabled' => defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT,
                'wp_config_secure' => $this->check_wp_config_security(),
                'directory_indexes_disabled' => $this->check_directory_indexes(),
                'xmlrpc_enabled' => $this->check_xmlrpc_status()
            ]
        ];
    }

    /**
     * Format activity message for display.
     *
     * @since    3.0.0
     * @param    object $activity Activity data.
     * @return   string Formatted message.
     */
    private function format_activity_message($activity) {
        $messages = [
            'malware_detected' => __('Malware detected and quarantined', 'secure-aura'),
            'login_failed' => sprintf(__('Failed login attempt from %s', 'secure-aura'), $activity->source_ip),
            'brute_force_attempt' => sprintf(__('Brute force attack blocked from %s', 'secure-aura'), $activity->source_ip),
            'file_quarantined' => __('Malicious file quarantined', 'secure-aura'),
            'scan_completed' => __('Security scan completed', 'secure-aura'),
            'emergency_mode_activated' => __('Emergency mode activated', 'secure-aura'),
            'emergency_mode_deactivated' => __('Emergency mode deactivated', 'secure-aura'),
            'ip_blocked' => sprintf(__('IP %s blocked', 'secure-aura'), $activity->source_ip),
            'suspicious_activity' => __('Suspicious activity detected', 'secure-aura')
        ];
        
        return $messages[$activity->event_type] ?? ucwords(str_replace('_', ' ', $activity->event_type));
    }

    /**
     * Log emergency mode action.
     *
     * @since    3.0.0
     * @param    bool $activated Whether emergency mode was activated.
     */
    private function log_emergency_action($activated) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $wpdb->insert($table_name, [
            'event_type' => $activated ? 'emergency_mode_activated' : 'emergency_mode_deactivated',
            'severity' => SECURE_AURA_SEVERITY_HIGH,
            'source_ip' => $this->get_client_ip(),
            'user_id' => get_current_user_id(),
            'event_data' => json_encode([
                'emergency_mode' => $activated,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'timestamp' => current_time('mysql')
            ]),
            'response_action' => 'emergency_mode_toggle'
        ]);
    }

    /**
     * Log IP block action.
     *
     * @since    3.0.0
     * @param    string $ip_address Blocked IP.
     * @param    string $reason     Block reason.
     */
    private function log_ip_block_action($ip_address, $reason) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $wpdb->insert($table_name, [
            'event_type' => 'ip_blocked',
            'severity' => SECURE_AURA_SEVERITY_MEDIUM,
            'source_ip' => $ip_address,
            'user_id' => get_current_user_id(),
            'event_data' => json_encode([
                'blocked_ip' => $ip_address,
                'reason' => $reason,
                'blocked_by' => get_current_user_id(),
                'timestamp' => current_time('mysql')
            ]),
            'response_action' => 'ip_blocked'
        ]);
    }

    /**
     * Log IP unblock action.
     *
     * @since    3.0.0
     * @param    string $ip_address Unblocked IP.
     */
    private function log_ip_unblock_action($ip_address) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $wpdb->insert($table_name, [
            'event_type' => 'ip_unblocked',
            'severity' => SECURE_AURA_SEVERITY_INFO,
            'source_ip' => $ip_address,
            'user_id' => get_current_user_id(),
            'event_data' => json_encode([
                'unblocked_ip' => $ip_address,
                'unblocked_by' => get_current_user_id(),
                'timestamp' => current_time('mysql')
            ]),
            'response_action' => 'ip_unblocked'
        ]);
    }

    /**
     * Update .htaccess with emergency rules.
     *
     * @since    3.0.0
     */
    private function update_htaccess_emergency_rules() {
        $htaccess_file = ABSPATH . '.htaccess';
        
        if (!is_writable($htaccess_file)) {
            return false;
        }
        
        $emergency_rules = "
# SecureAura Emergency Mode Rules - START
<Files \"wp-config.php\">
    Order allow,deny
    Deny from all
</Files>

<Files \"error_log\">
    Order allow,deny
    Deny from all
</Files>

# Block suspicious request methods
<Limit GET POST HEAD>
    deny from all
</Limit>

# Block common attack patterns
RewriteEngine On
RewriteCond %{QUERY_STRING} (eval\() [NC,OR]
RewriteCond %{QUERY_STRING} (127\.0\.0\.1) [NC,OR]
RewriteCond %{QUERY_STRING} (localhost) [NC,OR]
RewriteCond %{QUERY_STRING} (<|%3C).*script.*(>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2}) [OR]
RewriteCond %{QUERY_STRING} proc/self/environ [OR]
RewriteCond %{QUERY_STRING} mosConfig_[a-zA-Z_]{1,21}(=|\%3D) [OR]
RewriteCond %{QUERY_STRING} base64_(en|de)code\(.*\) [OR]
RewriteCond %{QUERY_STRING} (\[|\]|\(|\)|<|>|ê||;|\?|\*|\.|='|'|\$|_SESSION) [NC]
RewriteRule .* - [F]";
        
        $htaccess_content = file_get_contents($htaccess_file);
        
        // Remove existing emergency rules if any
        $htaccess_content = preg_replace('/# SecureAura Emergency Mode Rules - START.*# SecureAura Emergency Mode Rules - END\s*/s', '', $htaccess_content);
        
        // Add new emergency rules at the top
        $new_content = $emergency_rules . $htaccess_content;
        
        return file_put_contents($htaccess_file, $new_content) !== false;
    }

    /**
     * Remove emergency .htaccess rules.
     *
     * @since    3.0.0
     */
    private function remove_htaccess_emergency_rules() {
        $htaccess_file = ABSPATH . '.htaccess';
        
        if (!file_exists($htaccess_file) || !is_writable($htaccess_file)) {
            return false;
        }
        
        $htaccess_content = file_get_contents($htaccess_file);
        
        // Remove emergency rules
        $new_content = preg_replace('/# SecureAura Emergency Mode Rules - START.*# SecureAura Emergency Mode Rules - END\s*/s', '', $htaccess_content);
        
        return file_put_contents($htaccess_file, $new_content) !== false;
    }

    /**
     * Update .htaccess with blocked IPs.
     *
     * @since    3.0.0
     */
    private function update_htaccess_blocked_ips() {
        global $wpdb;
        
        $htaccess_file = ABSPATH . '.htaccess';
        
        if (!is_writable($htaccess_file)) {
            return false;
        }
        
        // Get currently blocked IPs
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
        $blocked_ips = $wpdb->get_col("
            SELECT ip_address FROM {$table_name} 
            WHERE (expires_at IS NULL OR expires_at > NOW())
            AND ip_address IS NOT NULL
            ORDER BY blocked_at DESC
            LIMIT 1000
        ");
        
        $htaccess_content = file_get_contents($htaccess_file);
        
        // Remove existing IP block rules
        $htaccess_content = preg_replace('/# SecureAura IP Blocks - START.*# SecureAura IP Blocks - END\s*/s', '', $htaccess_content);
        
        if (!empty($blocked_ips)) {
            $ip_rules = "# SecureAura IP Blocks - START\n";
            $ip_rules .= "<RequireAll>\n";
            $ip_rules .= "    Require all granted\n";
            
            foreach ($blocked_ips as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    $ip_rules .= "    Require not ip {$ip}\n";
                }
            }
            
            $ip_rules .= "</RequireAll>\n";
            $ip_rules .= "# SecureAura IP Blocks - END\n\n";
            
            // Add IP rules at the top
            $htaccess_content = $ip_rules . $htaccess_content;
        }
        
        return file_put_contents($htaccess_file, $htaccess_content) !== false;
    }

    /**
     * Parse IP information response from different APIs.
     *
     * @since    3.0.0
     * @param    array  $data       API response data.
     * @param    string $service_url Service URL for context.
     * @return   array  Parsed IP information.
     */
    private function parse_ip_info_response($data, $service_url) {
        $ip_info = [
            'country' => 'Unknown',
            'region' => 'Unknown',
            'city' => 'Unknown',
            'asn' => '',
            'organization' => '',
            'is_tor' => false,
            'is_vpn' => false,
            'is_proxy' => false
        ];
        
        // Parse based on service
        if (strpos($service_url, 'ip-api.com') !== false) {
            $ip_info['country'] = $data['country'] ?? 'Unknown';
            $ip_info['region'] = $data['regionName'] ?? 'Unknown';
            $ip_info['city'] = $data['city'] ?? 'Unknown';
            $ip_info['asn'] = $data['as'] ?? '';
            $ip_info['organization'] = $data['org'] ?? '';
            $ip_info['is_proxy'] = isset($data['proxy']) && $data['proxy'];
        } elseif (strpos($service_url, 'ipapi.co') !== false) {
            $ip_info['country'] = $data['country_name'] ?? 'Unknown';
            $ip_info['region'] = $data['region'] ?? 'Unknown';
            $ip_info['city'] = $data['city'] ?? 'Unknown';
            $ip_info['asn'] = $data['asn'] ?? '';
            $ip_info['organization'] = $data['org'] ?? '';
        }
        
        return $ip_info;
    }

    /**
     * Test database connection.
     *
     * @since    3.0.0
     * @return   bool True if database is accessible.
     */
    private function test_database_connection() {
        global $wpdb;
        
        $result = $wpdb->get_var("SELECT 1");
        return $result == 1;
    }

    /**
     * Get total threats blocked.
     *
     * @since    3.0.0
     * @return   int Total threats blocked.
     */
    private function get_total_threats_blocked() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $count = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE response_action IN ('block', 'quarantine', 'blocked')
        ");
        
        return intval($count);
    }

    /**
     * Get active security modules.
     *
     * @since    3.0.0
     * @return   array Active modules list.
     */
    private function get_active_modules() {
        $modules = [];
        
        if (get_option('secure_aura_quantum_firewall_enabled', true)) {
            $modules[] = 'Quantum Firewall';
        }
        
        if (get_option('secure_aura_real_time_scanning_enabled', true)) {
            $modules[] = 'Real-time Scanner';
        }
        
        if (get_option('secure_aura_file_integrity_monitoring_enabled', true)) {
            $modules[] = 'File Integrity Monitor';
        }
        
        if (get_option('secure_aura_ai_threat_detection_enabled', false)) {
            $modules[] = 'AI Threat Detection';
        }
        
        if (get_option('secure_aura_behavioral_monitoring_enabled', false)) {
            $modules[] = 'Behavioral Monitor';
        }
        
        return $modules;
    }

    /**
     * Check WordPress configuration security.
     *
     * @since    3.0.0
     * @return   bool True if wp-config.php is secure.
     */
    private function check_wp_config_security() {
        $wp_config_file = ABSPATH . 'wp-config.php';
        
        if (!file_exists($wp_config_file)) {
            return false;
        }
        
        // Check file permissions
        $perms = fileperms($wp_config_file);
        $perms_octal = substr(sprintf('%o', $perms), -4);
        
        // Should not be world-readable
        return $perms_octal !== '0644' && $perms_octal !== '0755';
    }

    /**
     * Check if directory indexes are disabled.
     *
     * @since    3.0.0
     * @return   bool True if directory indexes are disabled.
     */
    private function check_directory_indexes() {
        $htaccess_file = ABSPATH . '.htaccess';
        
        if (!file_exists($htaccess_file)) {
            return false;
        }
        
        $content = file_get_contents($htaccess_file);
        return strpos($content, 'Options -Indexes') !== false;
    }

    /**
     * Check XML-RPC status.
     *
     * @since    3.0.0
     * @return   bool True if XML-RPC is enabled.
     */
    private function check_xmlrpc_status() {
        return !has_filter('xmlrpc_enabled', '__return_false');
    }

    /**
     * Get client IP address.
     *
     * @since    3.0.0
     * @return   string Client IP address.
     */
    private function get_client_ip() {
        $ip_headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];
        
        foreach ($ip_headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = trim(explode(',', $_SERVER[$header])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Cleanup AJAX handler resources.
     *
     * @since    3.0.0
     */
    public function cleanup() {
        // Remove AJAX hooks
        remove_action('wp_ajax_secure_aura_toggle_emergency', [$this, 'handle_toggle_emergency']);
        remove_action('wp_ajax_secure_aura_block_ip', [$this, 'handle_block_ip']);
        remove_action('wp_ajax_secure_aura_unblock_ip', [$this, 'handle_unblock_ip']);
        // ... remove other hooks
        
        // Clear any temporary data
        delete_transient('secure_aura_ajax_cache');
    }
}

?>