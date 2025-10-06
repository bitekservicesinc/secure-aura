<?php
/**
 * The AJAX functionality of the plugin.
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
 * The AJAX functionality of the plugin.
 *
 * Handles all AJAX requests from the admin interface including:
 * - Emergency mode toggle
 * - IP management
 * - Security scanning
 * - Real-time data updates
 * - System information
 *
 * @package    SecureAura
 * @subpackage SecureAura/admin
 * @author     Bitekservices
 */
class Secure_Aura_Ajax_Handler {

    /**
     * Plugin configuration.
     *
     * @since    3.0.0
     * @access   private
     * @var      array    $config    Plugin configuration array.
     */
    private $config;

    /**
     * Database manager instance.
     *
     * @since    3.0.0
     * @access   private
     * @var      object    $db_manager    Database manager instance.
     */
    private $db_manager;

    /**
     * Initialize the class and set its properties.
     *
     * @since    3.0.0
     * @param    array     $config     Plugin configuration.
     */
    public function __construct($config = []) {
        $this->config = $config;
        
        // Initialize database manager
        if (class_exists('Secure_Aura_Database_Manager')) {
            $this->db_manager = new Secure_Aura_Database_Manager();
        }
    }

    /**
     * Register AJAX hooks.
     *
     * @since    3.0.0
     */
    public function init() {
        // Emergency Mode
        add_action('wp_ajax_secure_aura_emergency_mode', [$this, 'handle_emergency_mode']);
        
        // IP Management
        add_action('wp_ajax_secure_aura_get_blocked_ips', [$this, 'handle_get_blocked_ips']);
        add_action('wp_ajax_secure_aura_block_ip', [$this, 'handle_block_ip']);
        add_action('wp_ajax_secure_aura_unblock_ip', [$this, 'handle_unblock_ip']);
        
        // Security Scanning
        add_action('wp_ajax_secure_aura_start_scan', [$this, 'handle_start_scan']);
        add_action('wp_ajax_secure_aura_stop_scan', [$this, 'handle_stop_scan']);
        add_action('wp_ajax_secure_aura_get_scan_progress', [$this, 'handle_get_scan_progress']);
        add_action('wp_ajax_secure_aura_get_scan_status', [$this, 'handle_get_scan_status']);
        
        // Dashboard & System Info
        add_action('wp_ajax_secure_aura_get_system_info', [$this, 'handle_get_system_info']);
        add_action('wp_ajax_secure_aura_get_realtime_data', [$this, 'handle_get_realtime_data']);
        add_action('wp_ajax_secure_aura_refresh_dashboard', [$this, 'handle_refresh_dashboard']);
        
        // Threat Management
        add_action('wp_ajax_secure_aura_quarantine_threat', [$this, 'handle_quarantine_threat']);
        add_action('wp_ajax_secure_aura_delete_threat', [$this, 'handle_delete_threat']);
        add_action('wp_ajax_secure_aura_whitelist_file', [$this, 'handle_whitelist_file']);
        
        // Settings
        add_action('wp_ajax_secure_aura_save_settings', [$this, 'handle_save_settings']);
        add_action('wp_ajax_secure_aura_reset_settings', [$this, 'handle_reset_settings']);
        
        // Logs
        add_action('wp_ajax_secure_aura_get_logs', [$this, 'handle_get_logs']);
        add_action('wp_ajax_secure_aura_clear_logs', [$this, 'handle_clear_logs']);
    }

    /**
     * Handle Emergency Mode Toggle
     *
     * @since    3.0.0
     */
    public function handle_emergency_mode() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error([
                'message' => __('Insufficient permissions.', 'secure-aura')
            ]);
        }

        $action = sanitize_text_field($_POST['emergency_action']);
        $current_status = get_option('secure_aura_emergency_mode', false);

        try {
            if ($action === 'enable') {
                // Enable emergency mode
                $this->enable_emergency_mode();
                
                wp_send_json_success([
                    'message' => __('Emergency mode activated successfully! Maximum security protection is now enabled.', 'secure-aura'),
                    'status' => 'enabled',
                    'timestamp' => current_time('mysql')
                ]);
                
            } elseif ($action === 'disable') {
                // Disable emergency mode
                $this->disable_emergency_mode();
                
                wp_send_json_success([
                    'message' => __('Emergency mode deactivated successfully.', 'secure-aura'),
                    'status' => 'disabled',
                    'timestamp' => current_time('mysql')
                ]);
                
            } else {
                wp_send_json_error([
                    'message' => __('Invalid action specified.', 'secure-aura')
                ]);
            }

        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to toggle emergency mode: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Enable Emergency Mode
     *
     * @since    3.0.0
     */
    private function enable_emergency_mode() {
        // Store current settings before applying emergency settings
        $current_settings = get_option('secure_aura_settings', []);
        update_option('secure_aura_settings_backup_before_emergency', $current_settings);
        
        // Apply emergency settings
        $emergency_settings = [
            'quantum_firewall_enabled' => true,
            'firewall_strictness' => 'maximum',
            'real_time_scanning_enabled' => true,
            'scan_frequency' => 'continuous',
            'auto_quarantine_threats' => true,
            'block_suspicious_uploads' => true,
            'disable_file_editing' => true,
            'force_strong_passwords' => true,
            'limit_login_attempts' => true,
            'max_login_attempts' => 3,
            'block_admin_access_from_frontend' => true,
            'disable_xmlrpc' => true,
            'hide_wp_version' => true,
            'block_directory_browsing' => true,
            'emergency_contact_notifications' => true,
            'log_all_activities' => true,
        ];
        
        // Merge emergency settings with current settings
        $updated_settings = array_merge($current_settings, $emergency_settings);
        update_option('secure_aura_settings', $updated_settings);
        
        // Set emergency mode flag
        update_option('secure_aura_emergency_mode', true);
        update_option('secure_aura_emergency_mode_activated_at', current_time('mysql'));
        update_option('secure_aura_emergency_mode_activated_by', get_current_user_id());
        
        // Apply immediate security measures
        $this->apply_immediate_security_measures();
        
        // Log emergency mode activation
        if ($this->db_manager) {
            $this->db_manager->log_event(
                'emergency_mode_activated',
                [
                    'user_id' => get_current_user_id(),
                    'ip_address' => $this->get_client_ip(),
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                    'settings_applied' => $emergency_settings,
                ],
                'high'
            );
        }
        
        // Send notification to admin
        $this->send_emergency_mode_notification('activated');
        
        // Clear all caches
        $this->clear_all_caches();
    }

    /**
     * Disable Emergency Mode
     *
     * @since    3.0.0
     */
    private function disable_emergency_mode() {
        // Restore previous settings
        $backup_settings = get_option('secure_aura_settings_backup_before_emergency', []);
        
        if (!empty($backup_settings)) {
            update_option('secure_aura_settings', $backup_settings);
            delete_option('secure_aura_settings_backup_before_emergency');
        }
        
        // Disable emergency mode flag
        update_option('secure_aura_emergency_mode', false);
        update_option('secure_aura_emergency_mode_deactivated_at', current_time('mysql'));
        update_option('secure_aura_emergency_mode_deactivated_by', get_current_user_id());
        
        // Log emergency mode deactivation
        if ($this->db_manager) {
            $this->db_manager->log_event(
                'emergency_mode_deactivated',
                [
                    'user_id' => get_current_user_id(),
                    'ip_address' => $this->get_client_ip(),
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                    'duration' => $this->calculate_emergency_mode_duration(),
                ],
                'medium'
            );
        }
        
        // Send notification
        $this->send_emergency_mode_notification('deactivated');
        
        // Clear caches
        $this->clear_all_caches();
    }

    /**
     * Apply Immediate Security Measures
     *
     * @since    3.0.0
     */
    private function apply_immediate_security_measures() {
        // Flush rewrite rules
        flush_rewrite_rules();
        
        // Clear any existing malicious sessions
        $this->clear_suspicious_sessions();
        
        // Update .htaccess with security rules
        $this->update_htaccess_security_rules();
        
        // Block current suspicious IPs
        $this->block_suspicious_ips();
    }

    /**
     * Handle Get Blocked IPs
     *
     * @since    3.0.0
     */
    public function handle_get_blocked_ips() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error([
                'message' => __('Insufficient permissions.', 'secure-aura')
            ]);
        }

        try {
            global $wpdb;
            $table_name = $wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
            
            $blocked_ips = $wpdb->get_results("
                SELECT ip_address, reason, blocked_at, expires_at, is_permanent
                FROM {$table_name} 
                WHERE is_active = 1 
                ORDER BY blocked_at DESC 
                LIMIT 100
            ");
            
            // Format the data
            $formatted_ips = [];
            foreach ($blocked_ips as $ip) {
                $formatted_ips[] = [
                    'ip_address' => $ip->ip_address,
                    'reason' => $ip->reason ?: __('No reason provided', 'secure-aura'),
                    'blocked_at' => $this->format_date($ip->blocked_at),
                    'expires_at' => $ip->expires_at ? $this->format_date($ip->expires_at) : __('Never', 'secure-aura'),
                    'is_permanent' => (bool) $ip->is_permanent,
                ];
            }
            
            wp_send_json_success([
                'ips' => $formatted_ips,
                'total_count' => count($formatted_ips)
            ]);
            
        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to retrieve blocked IPs: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Handle Block IP
     *
     * @since    3.0.0
     */
    public function handle_block_ip() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error([
                'message' => __('Insufficient permissions.', 'secure-aura')
            ]);
        }

        $ip_address = sanitize_text_field($_POST['ip_address']);
        $reason = sanitize_text_field($_POST['reason']) ?: __('Manually blocked by admin', 'secure-aura');

        // Validate IP address
        if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
            wp_send_json_error([
                'message' => __('Invalid IP address format.', 'secure-aura')
            ]);
        }

        // Check if IP is already blocked
        if ($this->is_ip_blocked($ip_address)) {
            wp_send_json_error([
                'message' => __('This IP address is already blocked.', 'secure-aura')
            ]);
        }

        // Don't allow blocking current user's IP
        if ($ip_address === $this->get_client_ip()) {
            wp_send_json_error([
                'message' => __('You cannot block your own IP address.', 'secure-aura')
            ]);
        }

        try {
            global $wpdb;
            $table_name = $wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
            
            $result = $wpdb->insert(
                $table_name,
                [
                    'ip_address' => $ip_address,
                    'reason' => $reason,
                    'blocked_by_user_id' => get_current_user_id(),
                    'is_active' => 1,
                    'is_permanent' => 1,
                    'blocked_at' => current_time('mysql'),
                    'threat_type' => 'manual_block',
                ],
                ['%s', '%s', '%d', '%d', '%d', '%s', '%s']
            );
            
            if ($result === false) {
                throw new Exception(__('Database error occurred while blocking IP.', 'secure-aura'));
            }
            
            // Apply block immediately via .htaccess
            $this->apply_ip_block_to_htaccess($ip_address);
            
            // Log the action
            if ($this->db_manager) {
                $this->db_manager->log_event(
                    'ip_blocked_manually',
                    [
                        'blocked_ip' => $ip_address,
                        'reason' => $reason,
                        'blocked_by_user_id' => get_current_user_id(),
                        'admin_ip' => $this->get_client_ip(),
                    ],
                    'medium'
                );
            }
            
            wp_send_json_success([
                'message' => sprintf(__('IP address %s has been blocked successfully.', 'secure-aura'), $ip_address),
                'ip_address' => $ip_address,
                'blocked_at' => current_time('mysql')
            ]);
            
        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to block IP address: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Handle Unblock IP
     *
     * @since    3.0.0
     */
    public function handle_unblock_ip() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error([
                'message' => __('Insufficient permissions.', 'secure-aura')
            ]);
        }

        $ip_address = sanitize_text_field($_POST['ip_address']);

        // Validate IP address
        if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
            wp_send_json_error([
                'message' => __('Invalid IP address format.', 'secure-aura')
            ]);
        }

        try {
            global $wpdb;
            $table_name = $wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
            
            $result = $wpdb->update(
                $table_name,
                [
                    'is_active' => 0,
                    'unblocked_at' => current_time('mysql'),
                    'unblocked_by_user_id' => get_current_user_id(),
                ],
                ['ip_address' => $ip_address, 'is_active' => 1],
                ['%d', '%s', '%d'],
                ['%s', '%d']
            );
            
            if ($result === false) {
                throw new Exception(__('Database error occurred while unblocking IP.', 'secure-aura'));
            }
            
            if ($result === 0) {
                wp_send_json_error([
                    'message' => __('IP address not found in blocked list.', 'secure-aura')
                ]);
            }
            
            // Remove block from .htaccess
            $this->remove_ip_block_from_htaccess($ip_address);
            
            // Log the action
            if ($this->db_manager) {
                $this->db_manager->log_event(
                    'ip_unblocked_manually',
                    [
                        'unblocked_ip' => $ip_address,
                        'unblocked_by_user_id' => get_current_user_id(),
                        'admin_ip' => $this->get_client_ip(),
                    ],
                    'low'
                );
            }
            
            wp_send_json_success([
                'message' => sprintf(__('IP address %s has been unblocked successfully.', 'secure-aura'), $ip_address),
                'ip_address' => $ip_address,
                'unblocked_at' => current_time('mysql')
            ]);
            
        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to unblock IP address: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Handle Start Security Scan
     *
     * @since    3.0.0
     */
    public function handle_start_scan() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error([
                'message' => __('Insufficient permissions.', 'secure-aura')
            ]);
        }

        // Check if scan is already running
        if (get_transient('secure_aura_scan_in_progress')) {
            wp_send_json_error([
                'message' => __('A security scan is already in progress.', 'secure-aura')
            ]);
        }

        $scan_type = sanitize_text_field($_POST['scan_type']) ?: 'full';

        try {
            // Initialize scanner if available
            if (class_exists('Secure_Aura_Malware_Scanner')) {
                $scanner = new Secure_Aura_Malware_Scanner($this->config);
                
                // Start scan in background
                wp_schedule_single_event(time(), 'secure_aura_run_background_scan', [$scan_type]);
                
                // Set scan in progress flag
                set_transient('secure_aura_scan_in_progress', [
                    'scan_type' => $scan_type,
                    'started_at' => current_time('mysql'),
                    'started_by' => get_current_user_id(),
                ], 3600); // 1 hour timeout
                
                // Initialize progress
                set_transient('secure_aura_scan_progress', [
                    'percentage' => 0,
                    'status' => __('Initializing scan...', 'secure-aura'),
                    'files_scanned' => 0,
                    'threats_found' => 0,
                ], 3600);
                
                wp_send_json_success([
                    'message' => __('Security scan started successfully.', 'secure-aura'),
                    'scan_type' => $scan_type,
                    'started_at' => current_time('mysql')
                ]);
                
            } else {
                wp_send_json_error([
                    'message' => __('Scanner module is not available.', 'secure-aura')
                ]);
            }
            
        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to start security scan: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Handle Get Scan Progress
     *
     * @since    3.0.0
     */
    public function handle_get_scan_progress() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        $progress = get_transient('secure_aura_scan_progress');
        $in_progress = get_transient('secure_aura_scan_in_progress');
        
        if ($progress && $in_progress) {
            wp_send_json_success([
                'progress' => $progress,
                'scan_info' => $in_progress
            ]);
        } else {
            // Check for completed scan results
            $last_scan = get_option('secure_aura_last_scan_results');
            if ($last_scan) {
                wp_send_json_success([
                    'progress' => [
                        'percentage' => 100,
                        'status' => 'completed',
                        'files_scanned' => $last_scan['files_scanned'] ?? 0,
                        'threats_found' => count($last_scan['threats_found'] ?? []),
                    ]
                ]);
            } else {
                wp_send_json_error([
                    'message' => __('No scan progress found.', 'secure-aura')
                ]);
            }
        }
    }

    /**
     * Handle Get Scan Status
     *
     * @since    3.0.0
     */
    public function handle_get_scan_status() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        $status = $this->get_current_scan_status();
        
        wp_send_json_success([
            'status' => $status['status'],
            'data' => $status
        ]);
    }

    /**
     * Handle Stop Security Scan
     *
     * @since    3.0.0
     */
    public function handle_stop_scan() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error([
                'message' => __('Insufficient permissions.', 'secure-aura')
            ]);
        }

        try {
            // Clear scan progress
            delete_transient('secure_aura_scan_in_progress');
            delete_transient('secure_aura_scan_progress');
            
            // Cancel scheduled scan
            wp_clear_scheduled_hook('secure_aura_run_background_scan');
            
            // Log scan cancellation
            if ($this->db_manager) {
                $this->db_manager->log_event(
                    'scan_cancelled',
                    [
                        'cancelled_by_user_id' => get_current_user_id(),
                        'cancelled_at' => current_time('mysql'),
                    ],
                    'low'
                );
            }
            
            wp_send_json_success([
                'message' => __('Security scan stopped successfully.', 'secure-aura')
            ]);
            
        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to stop security scan: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Handle Get System Information
     *
     * @since    3.0.0
     */
    public function handle_get_system_info() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error([
                'message' => __('Insufficient permissions.', 'secure-aura')
            ]);
        }

        try {
            $system_info = $this->collect_system_information();
            
            wp_send_json_success([
                'system_info' => $system_info
            ]);
            
        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to collect system information: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Handle Get Real-time Data
     *
     * @since    3.0.0
     */
    public function handle_get_realtime_data() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        try {
            $data = [
                'threats_blocked' => $this->get_total_threats_blocked(),
                'last_scan' => get_option('secure_aura_last_scan_time', __('Never', 'secure-aura')),
                'security_score' => $this->calculate_security_score(),
                'recent_activities' => $this->get_recent_activities(5),
                'active_threats' => $this->get_active_threats_count(),
                'emergency_mode' => get_option('secure_aura_emergency_mode', false),
            ];
            
            wp_send_json_success($data);
            
        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to get real-time data: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Handle Refresh Dashboard
     *
     * @since    3.0.0
     */
    public function handle_refresh_dashboard() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        try {
            // Clear dashboard cache
            delete_transient('secure_aura_dashboard_cache');
            delete_transient('secure_aura_dashboard_stats');
            
            // Refresh security score
            delete_transient('secure_aura_security_score');
            
            wp_send_json_success([
                'message' => __('Dashboard refreshed successfully.', 'secure-aura'),
                'refreshed_at' => current_time('mysql')
            ]);
            
        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to refresh dashboard: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Handle Quarantine Threat
     *
     * @since    3.0.0
     */
    public function handle_quarantine_threat() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error([
                'message' => __('Insufficient permissions.', 'secure-aura')
            ]);
        }

        $threat_id = intval($_POST['threat_id']);
        
        try {
            // Get threat details
            global $wpdb;
            $threats_table = $wpdb->prefix . SECURE_AURA_TABLE_THREATS;
            
            $threat = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM {$threats_table} WHERE id = %d",
                $threat_id
            ));
            
            if (!$threat) {
                wp_send_json_error([
                    'message' => __('Threat not found.', 'secure-aura')
                ]);
            }
            
            // Move file to quarantine
            $quarantine_result = $this->quarantine_file($threat->file_path, $threat_id);
            
            if ($quarantine_result) {
                // Update threat status
                $wpdb->update(
                    $threats_table,
                    [
                        'status' => 'quarantined',
                        'quarantined_at' => current_time('mysql'),
                        'quarantined_by_user_id' => get_current_user_id(),
                    ],
                    ['id' => $threat_id],
                    ['%s', '%s', '%d'],
                    ['%d']
                );
                
                wp_send_json_success([
                    'message' => __('Threat quarantined successfully.', 'secure-aura'),
                    'threat_id' => $threat_id
                ]);
            } else {
                wp_send_json_error([
                    'message' => __('Failed to quarantine threat.', 'secure-aura')
                ]);
            }
            
        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to quarantine threat: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Handle Save Settings
     *
     * @since    3.0.0
     */
    public function handle_save_settings() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_nonce')) {
            wp_send_json_error([
                'message' => __('Security verification failed.', 'secure-aura')
            ]);
        }

        // Check user permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error([
                'message' => __('Insufficient permissions.', 'secure-aura')
            ]);
        }

        try {
            $settings = $_POST['settings'] ?? [];
            
            // Sanitize settings
            $sanitized_settings = $this->sanitize_settings($settings);
            
            // Validate settings
            $validation_result = $this->validate_settings($sanitized_settings);
            
            if (!$validation_result['valid']) {
                wp_send_json_error([
                    'message' => __('Settings validation failed: ', 'secure-aura') . $validation_result['message']
                ]);
            }
            
            // Save settings
            update_option('secure_aura_settings', $sanitized_settings);
            
            // Log settings change
            if ($this->db_manager) {
                $this->db_manager->log_event(
                    'settings_updated',
                    [
                        'updated_by_user_id' => get_current_user_id(),
                        'settings_changed' => array_keys($sanitized_settings),
                    ],
                    'low'
                );
            }
            
            wp_send_json_success([
                'message' => __('Settings saved successfully.', 'secure-aura'),
                'saved_at' => current_time('mysql')
            ]);
            
        } catch (Exception $e) {
            wp_send_json_error([
                'message' => __('Failed to save settings: ', 'secure-aura') . $e->getMessage()
            ]);
        }
    }

    /**
     * Helper Methods
     */

    /**
     * Get current scan status.
     *
     * @since    3.0.0
     * @return   array Current scan status.
     */
    private function get_current_scan_status() {
        $progress = get_transient('secure_aura_scan_progress');
        $in_progress = get_transient('secure_aura_scan_in_progress');
        
        if ($progress && $in_progress) {
            return [
                'status' => 'running',
                'progress' => $progress,
            ];
        }
        
        $last_scan = get_option('secure_aura_last_scan_results');
        if ($last_scan) {
            return [
                'status' => 'completed',
                'last_scan' => $last_scan,
            ];
        }
        
        return [
            'status' => 'idle',
            'last_scan' => null,
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
     * Calculate security score.
     *
     * @since    3.0.0
     * @return   int Security score (0-100).
     */
    private function calculate_security_score() {
        $score = get_transient('secure_aura_security_score');
        
        if ($score === false) {
            $score = 0;
            $checks = [
                'ssl_enabled' => is_ssl() ? 15 : 0,
                'file_editor_disabled' => (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT) ? 10 : 0,
                'strong_passwords' => get_option('secure_aura_force_strong_passwords', false) ? 10 : 0,
                'firewall_enabled' => get_option('secure_aura_quantum_firewall_enabled', true) ? 20 : 0,
                'scanner_enabled' => get_option('secure_aura_real_time_scanning_enabled', true) ? 15 : 0,
                'updates_available' => $this->check_updates_available() ? 0 : 10,
                'wp_version_hidden' => get_option('secure_aura_hide_wp_version', false) ? 5 : 0,
                'login_attempts_limited' => get_option('secure_aura_limit_login_attempts', false) ? 10 : 0,
                'xmlrpc_disabled' => !$this->check_xmlrpc_status() ? 5 : 0,
            ];
            
            $score = array_sum($checks);
            set_transient('secure_aura_security_score', $score, HOUR_IN_SECONDS);
        }
        
        return min(100, max(0, $score));
    }

    /**
     * Get recent activities.
     *
     * @since    3.0.0
     * @param    int $limit Number of activities to return.
     * @return   array Recent activities.
     */
    private function get_recent_activities($limit = 10) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $activities = $wpdb->get_results($wpdb->prepare("
            SELECT event_type, ip_address, created_at, event_data
            FROM {$table_name} 
            ORDER BY created_at DESC 
            LIMIT %d
        ", $limit));
        
        $formatted_activities = [];
        foreach ($activities as $activity) {
            $formatted_activities[] = [
                'time' => $this->time_ago($activity->created_at),
                'message' => $this->format_activity_message($activity),
            ];
        }
        
        return $formatted_activities;
    }

    /**
     * Get active threats count.
     *
     * @since    3.0.0
     * @return   int Active threats count.
     */
    private function get_active_threats_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_THREATS;
        
        $count = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE status = 'active'
        ");
        
        return intval($count);
    }

    /**
     * Check if IP is already blocked.
     *
     * @since    3.0.0
     * @param    string $ip_address IP address to check.
     * @return   bool True if blocked, false otherwise.
     */
    private function is_ip_blocked($ip_address) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
        
        $count = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE ip_address = %s AND is_active = 1
        ", $ip_address));
        
        return intval($count) > 0;
    }

    /**
     * Get client IP address.
     *
     * @since    3.0.0
     * @return   string Client IP address.
     */
    private function get_client_ip() {
        $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    /**
     * Format date for display.
     *
     * @since    3.0.0
     * @param    string $date_string Date string.
     * @return   string Formatted date.
     */
    private function format_date($date_string) {
        $date = new DateTime($date_string);
        return $date->format('M j, Y g:i A');
    }

    /**
     * Time ago format.
     *
     * @since    3.0.0
     * @param    string $date_string Date string.
     * @return   string Time ago format.
     */
    private function time_ago($date_string) {
        $time_ago = strtotime($date_string);
        $current_time = current_time('timestamp');
        $time_difference = $current_time - $time_ago;
        
        if ($time_difference < 60) {
            return __('Just now', 'secure-aura');
        } elseif ($time_difference < 3600) {
            $minutes = floor($time_difference / 60);
            return sprintf(_n('%d minute ago', '%d minutes ago', $minutes, 'secure-aura'), $minutes);
        } elseif ($time_difference < 86400) {
            $hours = floor($time_difference / 3600);
            return sprintf(_n('%d hour ago', '%d hours ago', $hours, 'secure-aura'), $hours);
        } else {
            $days = floor($time_difference / 86400);
            return sprintf(_n('%d day ago', '%d days ago', $days, 'secure-aura'), $days);
        }
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
            'threat_blocked' => __('Threat blocked from IP: %s', 'secure-aura'),
            'login_failed' => __('Failed login attempt from IP: %s', 'secure-aura'),
            'scan_completed' => __('Security scan completed', 'secure-aura'),
            'emergency_mode_activated' => __('Emergency mode activated', 'secure-aura'),
            'ip_blocked_manually' => __('IP address manually blocked: %s', 'secure-aura'),
            'file_quarantined' => __('Malicious file quarantined', 'secure-aura'),
        ];
        
        $message_template = $messages[$activity->event_type] ?? __('Security event: %s', 'secure-aura');
        
        return sprintf($message_template, $activity->ip_address);
    }

    /**
     * Send emergency mode notification.
     *
     * @since    3.0.0
     * @param    string $action 'activated' or 'deactivated'.
     */
    private function send_emergency_mode_notification($action) {
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        
        if ($action === 'activated') {
            $subject = sprintf(__('[%s] Emergency Mode Activated', 'secure-aura'), $site_name);
            $message = sprintf(
                __('Emergency mode has been activated on your website %s at %s.

This means maximum security protection is now enabled. Some site functionality may be temporarily limited.

If this was not done by you, please check your site immediately.

You can deactivate emergency mode from the SecureAura dashboard.', 'secure-aura'),
                home_url(),
                current_time('mysql')
            );
        } else {
            $subject = sprintf(__('[%s] Emergency Mode Deactivated', 'secure-aura'), $site_name);
            $message = sprintf(
                __('Emergency mode has been deactivated on your website %s at %s.

Normal security settings have been restored.', 'secure-aura'),
                home_url(),
                current_time('mysql')
            );
        }
        
        wp_mail($admin_email, $subject, $message);
    }

    /**
     * Apply IP block to .htaccess.
     *
     * @since    3.0.0
     * @param    string $ip_address IP address to block.
     */
    private function apply_ip_block_to_htaccess($ip_address) {
        $htaccess_file = ABSPATH . '.htaccess';
        
        if (!is_writable($htaccess_file)) {
            return false;
        }
        
        $htaccess_content = file_get_contents($htaccess_file);
        $block_rule = "Deny from {$ip_address}\n";
        
        // Check if rule already exists
        if (strpos($htaccess_content, $block_rule) === false) {
            // Add rule at the beginning
            $new_content = "# SecureAura IP Block\n" . $block_rule . "\n" . $htaccess_content;
            file_put_contents($htaccess_file, $new_content);
        }
        
        return true;
    }

    /**
     * Remove IP block from .htaccess.
     *
     * @since    3.0.0
     * @param    string $ip_address IP address to unblock.
     */
    private function remove_ip_block_from_htaccess($ip_address) {
        $htaccess_file = ABSPATH . '.htaccess';
        
        if (!is_writable($htaccess_file)) {
            return false;
        }
        
        $htaccess_content = file_get_contents($htaccess_file);
        $block_rule = "Deny from {$ip_address}";
        
        // Remove the rule
        $new_content = str_replace($block_rule, '', $htaccess_content);
        $new_content = preg_replace('/\n\s*\n/', "\n", $new_content); // Remove empty lines
        
        file_put_contents($htaccess_file, $new_content);
        
        return true;
    }

    /**
     * Quarantine file.
     *
     * @since    3.0.0
     * @param    string $file_path File path to quarantine.
     * @param    int    $threat_id Threat ID.
     * @return   bool   True on success, false on failure.
     */
    private function quarantine_file($file_path, $threat_id) {
        if (!file_exists($file_path)) {
            return false;
        }
        
        $quarantine_dir = SECURE_AURA_QUARANTINE_DIR;
        if (!file_exists($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
        }
        
        $quarantine_filename = 'threat_' . $threat_id . '_' . basename($file_path) . '.quarantine';
        $quarantine_path = $quarantine_dir . $quarantine_filename;
        
        // Move file to quarantine
        $result = rename($file_path, $quarantine_path);
        
        if ($result) {
            // Log quarantine action
            global $wpdb;
            $quarantine_table = $wpdb->prefix . SECURE_AURA_TABLE_QUARANTINE;
            
            $wpdb->insert(
                $quarantine_table,
                [
                    'threat_id' => $threat_id,
                    'original_path' => $file_path,
                    'quarantine_path' => $quarantine_path,
                    'quarantined_by_user_id' => get_current_user_id(),
                    'quarantined_at' => current_time('mysql'),
                ],
                ['%d', '%s', '%s', '%d', '%s']
            );
        }
        
        return $result;
    }

    /**
     * Sanitize settings array.
     *
     * @since    3.0.0
     * @param    array $settings Settings to sanitize.
     * @return   array Sanitized settings.
     */
    private function sanitize_settings($settings) {
        $sanitized = [];
        
        foreach ($settings as $key => $value) {
            switch ($key) {
                case 'max_login_attempts':
                case 'scan_frequency_hours':
                case 'log_retention_days':
                    $sanitized[$key] = intval($value);
                    break;
                    
                case 'admin_email':
                    $sanitized[$key] = sanitize_email($value);
                    break;
                    
                case 'quantum_firewall_enabled':
                case 'real_time_scanning_enabled':
                case 'emergency_mode':
                    $sanitized[$key] = (bool) $value;
                    break;
                    
                default:
                    $sanitized[$key] = sanitize_text_field($value);
                    break;
            }
        }
        
        return $sanitized;
    }

    /**
     * Validate settings.
     *
     * @since    3.0.0
     * @param    array $settings Settings to validate.
     * @return   array Validation result.
     */
    private function validate_settings($settings) {
        $errors = [];
        
        // Validate email if provided
        if (!empty($settings['admin_email']) && !is_email($settings['admin_email'])) {
            $errors[] = __('Invalid admin email address.', 'secure-aura');
        }
        
        // Validate numeric values
        if (isset($settings['max_login_attempts']) && ($settings['max_login_attempts'] < 1 || $settings['max_login_attempts'] > 20)) {
            $errors[] = __('Max login attempts must be between 1 and 20.', 'secure-aura');
        }
        
        if (isset($settings['scan_frequency_hours']) && ($settings['scan_frequency_hours'] < 1 || $settings['scan_frequency_hours'] > 168)) {
            $errors[] = __('Scan frequency must be between 1 and 168 hours.', 'secure-aura');
        }
        
        if (isset($settings['log_retention_days']) && ($settings['log_retention_days'] < 1 || $settings['log_retention_days'] > 365)) {
            $errors[] = __('Log retention must be between 1 and 365 days.', 'secure-aura');
        }
        
        return [
            'valid' => empty($errors),
            'message' => implode(' ', $errors)
        ];
    }

    /**
     * Clear all caches.
     *
     * @since    3.0.0
     */
    private function clear_all_caches() {
        // WordPress caches
        wp_cache_flush();
        
        // Plugin caches
        delete_transient('secure_aura_dashboard_cache');
        delete_transient('secure_aura_security_score');
        delete_transient('secure_aura_threat_intel_cache');
        delete_transient('secure_aura_malware_signatures');
        
        // Clear any object cache
        if (function_exists('wp_cache_clear_cache')) {
            wp_cache_clear_cache();
        }
    }

    /**
     * Clear suspicious sessions.
     *
     * @since    3.0.0
     */
    private function clear_suspicious_sessions() {
        global $wpdb;
        
        // Get current time minus 24 hours
        $time_limit = date('Y-m-d H:i:s', strtotime('-24 hours'));
        
        // Clear sessions from suspicious IPs
        $suspicious_ips = $wpdb->get_col($wpdb->prepare("
            SELECT DISTINCT ip_address 
            FROM {$wpdb->prefix}" . SECURE_AURA_TABLE_LOGS . " 
            WHERE event_type IN ('failed_login', 'brute_force_attempt', 'suspicious_activity')
            AND created_at > %s
            GROUP BY ip_address
            HAVING COUNT(*) > 5
        ", $time_limit));
        
        foreach ($suspicious_ips as $ip) {
            // Destroy sessions for this IP
            $this->destroy_sessions_by_ip($ip);
        }
    }

    /**
     * Destroy sessions by IP.
     *
     * @since    3.0.0
     * @param    string $ip_address IP address.
     */
    private function destroy_sessions_by_ip($ip_address) {
        // This is a placeholder for session destruction logic
        // In a real implementation, you'd need to track sessions by IP
        // and destroy them accordingly
        
        // Log the action
        if ($this->db_manager) {
            $this->db_manager->log_event(
                'suspicious_sessions_cleared',
                [
                    'target_ip' => $ip_address,
                    'cleared_by_emergency_mode' => true,
                ],
                'medium'
            );
        }
    }

    /**
     * Update .htaccess security rules.
     *
     * @since    3.0.0
     */
    private function update_htaccess_security_rules() {
        $htaccess_file = ABSPATH . '.htaccess';
        
        if (!is_writable($htaccess_file)) {
            return false;
        }
        
        $security_rules = "
            # SecureAura Security Rules - Emergency Mode
            <Files wp-config.php>
                Order allow,deny
                Deny from all
            </Files>

            <Files .htaccess>
                Order allow,deny
                Deny from all
            </Files>

            # Disable directory browsing
            Options -Indexes

            # Protect against script injections
            <IfModule mod_rewrite.c>
                RewriteEngine On
                RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]
                RewriteCond %{QUERY_STRING} GLOBALS(=|[|%[0-9A-Z]{0,2}) [OR]
                RewriteCond %{QUERY_STRING} _REQUEST(=|[|%[0-9A-Z]{0,2}) [OR]
                RewriteCond %{QUERY_STRING} proc/self/environ [OR]
                RewriteCond %{QUERY_STRING} mosConfig_[a-zA-Z_]{1,21}(=|%3D) [OR]
                RewriteCond %{QUERY_STRING} base64_(en|de)code[^(]*\([^)]*\) [OR]
                RewriteCond %{QUERY_STRING} (<|%3C)([^s]*s)+cript.*(>|%3E) [NC,OR]
                RewriteCond %{QUERY_STRING} (\.|%2E)(\.|%2E)(%2F|/) [NC,OR]
                RewriteCond %{QUERY_STRING} ftp\: [NC,OR]
                RewriteCond %{QUERY_STRING} http\: [NC,OR]
                RewriteCond %{QUERY_STRING} https\: [NC,OR]
                RewriteCond %{QUERY_STRING} \=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} [NC,OR]
                RewriteCond %{QUERY_STRING} (\.|%2E)(%2F|/) [NC,OR]
                RewriteCond %{QUERY_STRING} \.$
                RewriteRule .* - [F,L]
            </IfModule>

            # Block access to sensitive files
            <FilesMatch \"(^#.*#|\.(bak|config|dist|fla|inc|ini|log|psd|sh|sql|sw[op])|~)$\">
                Order allow,deny
                Deny from all
                Satisfy All
            </FilesMatch>

        ";
        
        $current_content = file_get_contents($htaccess_file);
        
        // Remove existing SecureAura rules
        $pattern = '/# SecureAura Security Rules.*?# End SecureAura Security Rules/s';
        $current_content = preg_replace($pattern, '', $current_content);
        
        // Add new rules at the beginning
        $new_content = $security_rules . "\n" . $current_content;
        
        return file_put_contents($htaccess_file, $new_content);
    }

    /**
     * Block suspicious IPs.
     *
     * @since    3.0.0
     */
    private function block_suspicious_ips() {
        global $wpdb;
        
        // Get IPs with multiple failed attempts in last hour
        $suspicious_ips = $wpdb->get_results("
            SELECT ip_address, COUNT(*) as attempt_count
            FROM {$wpdb->prefix}" . SECURE_AURA_TABLE_LOGS . "
            WHERE event_type IN ('failed_login', 'brute_force_attempt')
            AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY ip_address
            HAVING attempt_count >= 5
        ");
        
        $blocked_table = $wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
        
        foreach ($suspicious_ips as $ip_data) {
            // Check if IP is already blocked
            $existing = $wpdb->get_var($wpdb->prepare("
                SELECT COUNT(*) FROM {$blocked_table}
                WHERE ip_address = %s AND is_active = 1
            ", $ip_data->ip_address));
            
            if ($existing == 0) {
                // Block the IP
                $wpdb->insert(
                    $blocked_table,
                    [
                        'ip_address' => $ip_data->ip_address,
                        'reason' => sprintf(__('Automatically blocked due to %d suspicious attempts', 'secure-aura'), $ip_data->attempt_count),
                        'blocked_by_user_id' => 0, // System blocked
                        'is_active' => 1,
                        'is_permanent' => 0,
                        'blocked_at' => current_time('mysql'),
                        'expires_at' => date('Y-m-d H:i:s', strtotime('+24 hours')),
                        'threat_type' => 'brute_force',
                    ],
                    ['%s', '%s', '%d', '%d', '%d', '%s', '%s', '%s']
                );
                
                // Apply to .htaccess
                $this->apply_ip_block_to_htaccess($ip_data->ip_address);
            }
        }
    }

    /**
     * Calculate emergency mode duration.
     *
     * @since    3.0.0
     * @return   string Duration in human readable format.
     */
    private function calculate_emergency_mode_duration() {
        $activated_at = get_option('secure_aura_emergency_mode_activated_at');
        
        if (!$activated_at) {
            return __('Unknown', 'secure-aura');
        }
        
        $activated_time = strtotime($activated_at);
        $current_time = current_time('timestamp');
        $duration = $current_time - $activated_time;
        
        if ($duration < 60) {
            return sprintf(__('%d seconds', 'secure-aura'), $duration);
        } elseif ($duration < 3600) {
            $minutes = floor($duration / 60);
            return sprintf(__('%d minutes', 'secure-aura'), $minutes);
        } else {
            $hours = floor($duration / 3600);
            $minutes = floor(($duration % 3600) / 60);
            return sprintf(__('%d hours %d minutes', 'secure-aura'), $hours, $minutes);
        }
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
     * Check if updates are available.
     *
     * @since    3.0.0
     * @return   bool True if updates are available.
     */
    private function check_updates_available() {
        // Check WordPress core updates
        $core_updates = get_core_updates();
        if (!empty($core_updates) && $core_updates[0]->response === 'upgrade') {
            return true;
        }
        
        // Check plugin updates
        $plugin_updates = get_site_transient('update_plugins');
        if (!empty($plugin_updates->response)) {
            return true;
        }
        
        // Check theme updates
        $theme_updates = get_site_transient('update_themes');
        if (!empty($theme_updates->response)) {
            return true;
        }
        
        return false;
    }

    /**
     * Cleanup method.
     *
     * @since    3.0.0
     */
    public function cleanup() {
        // Remove AJAX hooks
        remove_action('wp_ajax_secure_aura_emergency_mode', [$this, 'handle_emergency_mode']);
        remove_action('wp_ajax_secure_aura_get_blocked_ips', [$this, 'handle_get_blocked_ips']);
        remove_action('wp_ajax_secure_aura_block_ip', [$this, 'handle_block_ip']);
        remove_action('wp_ajax_secure_aura_unblock_ip', [$this, 'handle_unblock_ip']);
        remove_action('wp_ajax_secure_aura_start_scan', [$this, 'handle_start_scan']);
        remove_action('wp_ajax_secure_aura_get_scan_progress', [$this, 'handle_get_scan_progress']);
        remove_action('wp_ajax_secure_aura_get_system_info', [$this, 'handle_get_system_info']);
        remove_action('wp_ajax_secure_aura_get_realtime_data', [$this, 'handle_get_realtime_data']);
    }
}

?>