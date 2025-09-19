<?php
/**
 * Fired during plugin deactivation
 *
 * @link       https://secureaura.pro
 * @since      3.0.0
 *
 * @package    SecureAura
 * @subpackage SecureAura/includes
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Fired during plugin deactivation.
 *
 * This class defines all code necessary to run during the plugin's deactivation.
 *
 * @since      3.0.0
 * @package    SecureAura
 * @subpackage SecureAura/includes
 * @author     Bitekservices
 */
class Secure_Aura_Deactivator {

    /**
     * Plugin deactivation handler.
     *
     * Performs cleanup and safe shutdown of security features.
     *
     * @since    3.0.0
     */
    public static function deactivate() {
        // Log deactivation event
        self::log_deactivation_event();
        
        // Clear scheduled cron jobs
        self::clear_cron_jobs();
        
        // Disable real-time protection
        self::disable_real_time_protection();
        
        // Clean up temporary files
        self::cleanup_temporary_files();
        
        // Close any open incidents
        self::close_open_incidents();
        
        // Save deactivation summary
        self::save_deactivation_summary();
        
        // Send deactivation notification
        self::send_deactivation_notification();
        
        // Preserve user data and settings (don't delete)
        self::preserve_user_data();
        
        // Update deactivation timestamp
        update_option('secure_aura_deactivated_at', current_time('mysql'));
        update_option('secure_aura_activated', false);
        
        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Log deactivation event for audit trail.
     *
     * @since    3.0.0
     */
    private static function log_deactivation_event() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        // Check if table exists before logging
        if ($wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") === $table_name) {
            $wpdb->insert($table_name, [
                'event_type' => 'plugin_deactivation',
                'severity' => SECURE_AURA_SEVERITY_INFO,
                'source_ip' => self::get_client_ip(),
                'user_id' => get_current_user_id(),
                'event_data' => json_encode([
                    'version' => SECURE_AURA_VERSION,
                    'deactivated_by' => get_current_user_id(),
                    'deactivation_reason' => 'manual',
                    'active_modules' => self::get_active_modules(),
                    'settings_preserved' => true,
                    'data_preserved' => true,
                ]),
                'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
                'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
                'response_action' => 'deactivation_completed',
            ]);
        }
    }

    /**
     * Clear all scheduled cron jobs.
     *
     * @since    3.0.0
     */
    private static function clear_cron_jobs() {
        $cron_jobs = [
            SECURE_AURA_CRON_THREAT_INTEL_UPDATE,
            SECURE_AURA_CRON_FULL_SCAN,
            SECURE_AURA_CRON_LOG_CLEANUP,
            SECURE_AURA_CRON_CACHE_CLEANUP,
            SECURE_AURA_CRON_PERFORMANCE_CHECK,
            SECURE_AURA_CRON_INTEGRITY_CHECK,
            'secure_aura_create_initial_backup',
            'secure_aura_daily_threat_update',
            'secure_aura_weekly_deep_scan',
            'secure_aura_monthly_compliance_check',
        ];
        
        foreach ($cron_jobs as $job) {
            $timestamp = wp_next_scheduled($job);
            if ($timestamp) {
                wp_unschedule_event($timestamp, $job);
            }
            
            // Clear all instances of the hook
            wp_clear_scheduled_hook($job);
        }
        
        // Log cron cleanup
        error_log('SecureAura: Cleared ' . count($cron_jobs) . ' scheduled cron jobs during deactivation.');
    }

    /**
     * Disable real-time protection features.
     *
     * @since    3.0.0
     */
    private static function disable_real_time_protection() {
        // Disable emergency mode if active
        $emergency_mode = get_option('secure_aura_emergency_mode', false);
        if ($emergency_mode) {
            update_option('secure_aura_emergency_mode', false);
            update_option('secure_aura_emergency_mode_disabled_by_deactivation', true);
        }
        
        // Disable real-time monitoring
        update_option('secure_aura_real_time_monitoring', false);
        
        // Disable file integrity monitoring
        update_option('secure_aura_file_integrity_monitoring', false);
        
        // Disable behavioral monitoring
        update_option('secure_aura_behavioral_monitoring', false);
        
        // Save current protection status for reactivation
        $protection_status = [
            'emergency_mode' => $emergency_mode,
            'real_time_monitoring' => get_option('secure_aura_real_time_monitoring', true),
            'file_integrity_monitoring' => get_option('secure_aura_file_integrity_monitoring', true),
            'behavioral_monitoring' => get_option('secure_aura_behavioral_monitoring', false),
            'quantum_firewall' => get_option('secure_aura_quantum_firewall_enabled', true),
            'ai_threat_detection' => get_option('secure_aura_ai_threat_detection_enabled', false),
        ];
        
        update_option('secure_aura_protection_status_before_deactivation', $protection_status);
    }

    /**
     * Clean up temporary files and cache.
     *
     * @since    3.0.0
     */
    private static function cleanup_temporary_files() {
        $cleanup_dirs = [
            SECURE_AURA_CACHE_DIR,
            SECURE_AURA_UPLOADS_DIR . 'temp/',
            SECURE_AURA_UPLOADS_DIR . 'scans/',
        ];
        
        $total_cleaned = 0;
        $total_size_cleaned = 0;
        
        foreach ($cleanup_dirs as $dir) {
            if (file_exists($dir)) {
                $cleaned = self::cleanup_directory($dir, true); // true = keep directory structure
                $total_cleaned += $cleaned['files'];
                $total_size_cleaned += $cleaned['size'];
            }
        }
        
        // Clean up expired cached data from database
        self::cleanup_expired_cache_data();
        
        // Log cleanup results
        update_option('secure_aura_deactivation_cleanup', [
            'temp_files_cleaned' => $total_cleaned,
            'total_size_cleaned' => $total_size_cleaned,
            'cleanup_completed_at' => current_time('mysql'),
        ]);
    }

    /**
     * Clean up directory contents.
     *
     * @since    3.0.0
     * @param    string $dir Directory to clean.
     * @param    bool   $preserve_structure Whether to preserve directory structure.
     * @return   array  Cleanup statistics.
     */
    private static function cleanup_directory($dir, $preserve_structure = true) {
        $files_cleaned = 0;
        $size_cleaned = 0;
        
        if (!is_dir($dir)) {
            return ['files' => 0, 'size' => 0];
        }
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $size_cleaned += $file->getSize();
                if (unlink($file->getRealPath())) {
                    $files_cleaned++;
                }
            } elseif ($file->isDir() && !$preserve_structure) {
                rmdir($file->getRealPath());
            }
        }
        
        return ['files' => $files_cleaned, 'size' => $size_cleaned];
    }

    /**
     * Clean up expired cache data from database.
     *
     * @since    3.0.0
     */
    private static function cleanup_expired_cache_data() {
        global $wpdb;
        
        // Clean up expired threat intelligence cache
        $cache_options = $wpdb->get_results("
            SELECT option_name FROM {$wpdb->options} 
            WHERE option_name LIKE 'secure_aura_cache_%' 
            OR option_name LIKE '_transient_secure_aura_%'
            OR option_name LIKE '_transient_timeout_secure_aura_%'
        ");
        
        foreach ($cache_options as $option) {
            delete_option($option->option_name);
        }
    }

    /**
     * Close any open security incidents.
     *
     * @since    3.0.0
     */
    private static function close_open_incidents() {
        global $wpdb;
        
        $incidents_table = $wpdb->prefix . SECURE_AURA_TABLE_INCIDENT_REPORTS;
        
        // Check if table exists
        if ($wpdb->get_var("SHOW TABLES LIKE '{$incidents_table}'") === $incidents_table) {
            // Close open incidents with deactivation note
            $updated = $wpdb->update(
                $incidents_table,
                [
                    'status' => 'closed',
                    'response_actions' => $wpdb->prepare(
                        "CONCAT(COALESCE(response_actions, ''), %s)",
                        "\n\n[AUTO-CLOSED] Plugin deactivated at " . current_time('mysql')
                    ),
                    'updated_at' => current_time('mysql'),
                ],
                [
                    'status' => 'open'
                ]
            );
            
            if ($updated > 0) {
                error_log("SecureAura: Auto-closed {$updated} open incidents during deactivation.");
            }
        }
    }

    /**
     * Save deactivation summary for analysis.
     *
     * @since    3.0.0
     */
    private static function save_deactivation_summary() {
        $summary = [
            'deactivation_time' => current_time('mysql'),
            'version' => SECURE_AURA_VERSION,
            'deactivated_by_user' => get_current_user_id(),
            'active_duration' => self::calculate_active_duration(),
            'security_events_logged' => self::count_security_events(),
            'threats_blocked' => self::count_threats_blocked(),
            'scans_performed' => self::count_scans_performed(),
            'files_quarantined' => self::count_quarantined_files(),
            'incidents_handled' => self::count_incidents_handled(),
            'cleanup_performed' => true,
            'data_preserved' => true,
            'settings_preserved' => true,
            'reason' => 'manual_deactivation',
        ];
        
        update_option('secure_aura_deactivation_summary', $summary);
    }

    /**
     * Calculate how long the plugin was active.
     *
     * @since    3.0.0
     * @return   string Duration in human readable format.
     */
    private static function calculate_active_duration() {
        $activation_time = get_option('secure_aura_activation_time');
        if (!$activation_time) {
            return 'Unknown';
        }
        
        $activation_timestamp = strtotime($activation_time);
        $current_timestamp = current_time('timestamp');
        $duration_seconds = $current_timestamp - $activation_timestamp;
        
        return human_time_diff($activation_timestamp, $current_timestamp);
    }

    /**
     * Count total security events logged.
     *
     * @since    3.0.0
     * @return   int Number of security events.
     */
    private static function count_security_events() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        if ($wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") === $table_name) {
            return intval($wpdb->get_var("SELECT COUNT(*) FROM {$table_name}"));
        }
        
        return 0;
    }

    /**
     * Count total threats blocked.
     *
     * @since    3.0.0
     * @return   int Number of threats blocked.
     */
    private static function count_threats_blocked() {
        global $wpdb;
        
        $logs_table = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        if ($wpdb->get_var("SHOW TABLES LIKE '{$logs_table}'") === $logs_table) {
            return intval($wpdb->get_var("
                SELECT COUNT(*) FROM {$logs_table} 
                WHERE response_action IN ('block', 'quarantine', 'blocked')
            "));
        }
        
        return 0;
    }

    /**
     * Count total scans performed.
     *
     * @since    3.0.0
     * @return   int Number of scans performed.
     */
    private static function count_scans_performed() {
        global $wpdb;
        
        $logs_table = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        if ($wpdb->get_var("SHOW TABLES LIKE '{$logs_table}'") === $logs_table) {
            return intval($wpdb->get_var("
                SELECT COUNT(*) FROM {$logs_table} 
                WHERE event_type LIKE '%scan%'
            "));
        }
        
        return 0;
    }

    /**
     * Count files in quarantine.
     *
     * @since    3.0.0
     * @return   int Number of quarantined files.
     */
    private static function count_quarantined_files() {
        global $wpdb;
        
        $quarantine_table = $wpdb->prefix . SECURE_AURA_TABLE_QUARANTINE;
        
        if ($wpdb->get_var("SHOW TABLES LIKE '{$quarantine_table}'") === $quarantine_table) {
            return intval($wpdb->get_var("
                SELECT COUNT(*) FROM {$quarantine_table} 
                WHERE action_taken = 'quarantined'
            "));
        }
        
        return 0;
    }

    /**
     * Count incidents handled.
     *
     * @since    3.0.0
     * @return   int Number of incidents handled.
     */
    private static function count_incidents_handled() {
        global $wpdb;
        
        $incidents_table = $wpdb->prefix . SECURE_AURA_TABLE_INCIDENT_REPORTS;
        
        if ($wpdb->get_var("SHOW TABLES LIKE '{$incidents_table}'") === $incidents_table) {
            return intval($wpdb->get_var("SELECT COUNT(*) FROM {$incidents_table}"));
        }
        
        return 0;
    }

    /**
     * Send deactivation notification to admin.
     *
     * @since    3.0.0
     */
    private static function send_deactivation_notification() {
        $notification_enabled = get_option('secure_aura_email_notifications', true);
        if (!$notification_enabled) {
            return;
        }
        
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        $site_url = home_url();
        
        $summary = get_option('secure_aura_deactivation_summary', []);
        $threats_blocked = $summary['threats_blocked'] ?? 0;
        $scans_performed = $summary['scans_performed'] ?? 0;
        $active_duration = $summary['active_duration'] ?? 'Unknown';
        
        $subject = sprintf(__('[%s] SecureAura Security Plugin Deactivated', 'secure-aura'), $site_name);
        
        $message = sprintf(
            __('SecureAura has been deactivated on your website %s.

Security Summary During Active Period:
• Active Duration: %s
• Threats Blocked: %d
• Security Scans: %d
• Files Quarantined: %d

Your security data and settings have been preserved and will be restored if you reactivate the plugin.

Important: Your website is now less protected. Consider:
1. Reactivating SecureAura soon
2. Using alternative security measures
3. Monitoring your site more closely

To reactivate SecureAura, visit: %s

Your security data is safe!
The SecureAura Team', 'secure-aura'),
            $site_url,
            $active_duration,
            $threats_blocked,
            $scans_performed,
            $summary['files_quarantined'] ?? 0,
            admin_url('plugins.php')
        );
        
        $headers = [
            'Content-Type: text/plain; charset=UTF-8',
            'From: SecureAura <noreply@secureaura.pro>',
        ];
        
        wp_mail($admin_email, $subject, $message, $headers);
    }

    /**
     * Preserve user data and settings for future reactivation.
     *
     * @since    3.0.0
     */
    private static function preserve_user_data() {
        // Mark that data should be preserved
        update_option('secure_aura_data_preserved', true);
        
        // Create a backup of current settings
        $current_settings = get_option('secure_aura_settings', []);
        update_option('secure_aura_settings_backup', $current_settings);
        
        // Preserve important options that should survive deactivation
        $preserve_options = [
            'secure_aura_license_key',
            'secure_aura_license_type',
            'secure_aura_first_activation_date',
            'secure_aura_total_threats_blocked',
            'secure_aura_total_scans_performed',
            'secure_aura_user_preferences',
            'secure_aura_whitelist_rules',
            'secure_aura_custom_security_rules',
        ];
        
        foreach ($preserve_options as $option) {
            $value = get_option($option);
            if ($value !== false) {
                update_option($option . '_preserved', $value);
            }
        }
        
        // Don't delete database tables - preserve all security data
        // Tables will remain for forensic analysis and quick reactivation
    }

    /**
     * Get currently active modules.
     *
     * @since    3.0.0
     * @return   array List of active modules.
     */
    private static function get_active_modules() {
        $settings = get_option('secure_aura_settings', []);
        $active_modules = [];
        
        $module_settings = [
            'quantum_firewall_enabled' => 'Quantum Firewall',
            'ai_threat_detection_enabled' => 'AI Threat Engine',
            'behavioral_monitoring_enabled' => 'Behavioral Monitor',
            'real_time_scanning_enabled' => 'Real-time Scanner',
            'file_integrity_monitoring_enabled' => 'File Integrity Monitor',
            'database_protection' => 'Database Protection',
            'performance_monitoring' => 'Performance Monitor',
        ];
        
        foreach ($module_settings as $setting => $module_name) {
            if (!empty($settings[$setting])) {
                $active_modules[] = $module_name;
            }
        }
        
        return $active_modules;
    }

    /**
     * Get client IP address.
     *
     * @since    3.0.0
     * @return   string Client IP address.
     */
    private static function get_client_ip() {
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
     * Graceful shutdown of any running processes.
     *
     * @since    3.0.0
     */
    private static function shutdown_running_processes() {
        // Check for any running scans and gracefully stop them
        $running_scan = get_transient('secure_aura_scan_in_progress');
        if ($running_scan) {
            delete_transient('secure_aura_scan_in_progress');
            
            // Log interrupted scan
            global $wpdb;
            $logs_table = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
            if ($wpdb->get_var("SHOW TABLES LIKE '{$logs_table}'") === $logs_table) {
                $wpdb->insert($logs_table, [
                    'event_type' => 'scan_interrupted',
                    'severity' => SECURE_AURA_SEVERITY_MEDIUM,
                    'event_data' => json_encode([
                        'reason' => 'plugin_deactivation',
                        'scan_id' => $running_scan['scan_id'] ?? 'unknown',
                        'progress' => $running_scan['progress'] ?? 0,
                    ]),
                    'response_action' => 'scan_stopped',
                ]);
            }
        }
        
        // Stop any real-time monitoring processes
        delete_transient('secure_aura_realtime_monitoring_active');
        
        // Cancel any pending background tasks
        delete_transient('secure_aura_background_task_queue');
    }

    /**
     * Create deactivation report for diagnostics.
     *
     * @since    3.0.0
     */
    private static function create_deactivation_report() {
        $report = [
            'timestamp' => current_time('mysql'),
            'plugin_version' => SECURE_AURA_VERSION,
            'wp_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'deactivated_by' => get_current_user_id(),
            'server_info' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
            'memory_usage' => memory_get_usage(true),
            'peak_memory' => memory_get_peak_usage(true),
            'database_stats' => self::get_database_stats(),
            'active_plugins' => get_option('active_plugins', []),
            'active_theme' => get_stylesheet(),
            'multisite' => is_multisite(),
            'debug_mode' => defined('WP_DEBUG') && WP_DEBUG,
        ];
        
        // Save report for support purposes
        update_option('secure_aura_last_deactivation_report', $report);
        
        // If debug mode is enabled, also log to file
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('SecureAura Deactivation Report: ' . json_encode($report, JSON_PRETTY_PRINT));
        }
    }

    /**
     * Get basic database statistics.
     *
     * @since    3.0.0
     * @return   array Database statistics.
     */
    private static function get_database_stats() {
        global $wpdb;
        
        $stats = [];
        $tables = [
            SECURE_AURA_TABLE_LOGS,
            SECURE_AURA_TABLE_THREATS,
            SECURE_AURA_TABLE_BEHAVIORAL,
            SECURE_AURA_TABLE_FILE_INTEGRITY,
            SECURE_AURA_TABLE_BLOCKED_IPS,
        ];
        
        foreach ($tables as $table) {
            $table_name = $wpdb->prefix . $table;
            if ($wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") === $table_name) {
                $count = $wpdb->get_var("SELECT COUNT(*) FROM {$table_name}");
                $stats[$table] = intval($count);
            }
        }
        
        return $stats;
    }
}