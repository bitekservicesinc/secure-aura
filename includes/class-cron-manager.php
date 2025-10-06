<?php
/**
 * Cron Job Manager
 *
 * Manages all scheduled tasks for the plugin
 *
 * @package    SecureAura
 * @subpackage SecureAura/includes
 * @since      3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

class Secure_Aura_Cron_Manager {
    
    /**
     * Plugin settings
     *
     * @var array
     */
    private $settings;
    
    /**
     * Initialize the cron manager
     *
     * @since 3.0.0
     */
    public function __construct() {
        $this->settings = get_option('secure_aura_settings', []);
        
        // Register cron schedules
        add_filter('cron_schedules', [$this, 'add_cron_schedules']);
        
        // Register cron hooks
        add_action('secure_aura_scheduled_scan', [$this, 'run_scheduled_scan']);
        add_action('secure_aura_cleanup_old_data', [$this, 'cleanup_old_data']);
        add_action('secure_aura_update_threat_intel', [$this, 'update_threat_intelligence']);
        add_action('secure_aura_check_file_integrity', [$this, 'check_file_integrity']);
        add_action('secure_aura_database_optimization', [$this, 'optimize_database']);
        add_action('secure_aura_generate_reports', [$this, 'generate_scheduled_reports']);
        add_action('secure_aura_initial_scan', [$this, 'run_initial_scan']);
    }
    
    /**
     * Add custom cron schedules
     *
     * @since 3.0.0
     * @param array $schedules Existing schedules
     * @return array Modified schedules
     */
    public function add_cron_schedules($schedules) {
        // Every 5 minutes
        $schedules['every_5_minutes'] = [
            'interval' => 300,
            'display' => __('Every 5 Minutes', 'secure-aura'),
        ];
        
        // Every 15 minutes
        $schedules['every_15_minutes'] = [
            'interval' => 900,
            'display' => __('Every 15 Minutes', 'secure-aura'),
        ];
        
        // Every 30 minutes
        $schedules['every_30_minutes'] = [
            'interval' => 1800,
            'display' => __('Every 30 Minutes', 'secure-aura'),
        ];
        
        // Every 6 hours
        $schedules['every_6_hours'] = [
            'interval' => 21600,
            'display' => __('Every 6 Hours', 'secure-aura'),
        ];
        
        // Every 12 hours
        $schedules['every_12_hours'] = [
            'interval' => 43200,
            'display' => __('Every 12 Hours', 'secure-aura'),
        ];
        
        return $schedules;
    }
    
    /**
     * Setup all cron jobs
     *
     * @since 3.0.0
     */
    public function setup_cron_jobs() {
        // Scheduled security scans
        $this->schedule_security_scans();
        
        // Data cleanup (daily)
        if (!wp_next_scheduled('secure_aura_cleanup_old_data')) {
            wp_schedule_event(time(), 'daily', 'secure_aura_cleanup_old_data');
        }
        
        // Threat intelligence updates (every 6 hours)
        if (!wp_next_scheduled('secure_aura_update_threat_intel')) {
            wp_schedule_event(time(), 'every_6_hours', 'secure_aura_update_threat_intel');
        }
        
        // File integrity checks (hourly)
        if (!wp_next_scheduled('secure_aura_check_file_integrity')) {
            wp_schedule_event(time(), 'hourly', 'secure_aura_check_file_integrity');
        }
        
        // Database optimization (weekly)
        if (!wp_next_scheduled('secure_aura_database_optimization')) {
            wp_schedule_event(strtotime('next sunday 3am'), 'weekly', 'secure_aura_database_optimization');
        }
        
        // Report generation (weekly)
        if (!wp_next_scheduled('secure_aura_generate_reports')) {
            wp_schedule_event(strtotime('next monday 9am'), 'weekly', 'secure_aura_generate_reports');
        }
    }
    
    /**
     * Schedule security scans based on frequency setting
     *
     * @since 3.0.0
     */
    private function schedule_security_scans() {
        $frequency = $this->settings['scan_frequency'] ?? 'daily';
        
        // Clear existing schedule
        $timestamp = wp_next_scheduled('secure_aura_scheduled_scan');
        if ($timestamp) {
            wp_unschedule_event($timestamp, 'secure_aura_scheduled_scan');
        }
        
        // Schedule new scan based on frequency
        if ($frequency !== 'manual') {
            $schedule_map = [
                'hourly' => 'hourly',
                'daily' => 'daily',
                'weekly' => 'weekly',
            ];
            
            $schedule = $schedule_map[$frequency] ?? 'daily';
            
            // Schedule at low-traffic time (3 AM)
            $start_time = strtotime('tomorrow 3am');
            
            wp_schedule_event($start_time, $schedule, 'secure_aura_scheduled_scan');
        }
    }
    
    /**
     * Run scheduled security scan
     *
     * @since 3.0.0
     */
    public function run_scheduled_scan() {
        // Check if a scan is already running
        if (get_transient('secure_aura_scan_in_progress')) {
            return;
        }
        
        // Load scanner class
        if (!class_exists('Secure_Aura_Malware_Scanner')) {
            require_once SECURE_AURA_INCLUDES_DIR . 'class-malware-scanner.php';
        }
        
        $scanner = new Secure_Aura_Malware_Scanner();
        
        // Run full scan
        $results = $scanner->run_full_scan();
        
        // Send email report if configured
        if (!empty($this->settings['notify_on_scan'])) {
            if (!class_exists('Secure_Aura_Email_Notifications')) {
                require_once SECURE_AURA_INCLUDES_DIR . 'class-email-notifications.php';
            }
            
            $email = new Secure_Aura_Email_Notifications();
            $results['scheduled'] = true;
            $email->send_scan_report($results);
        }
        
        // Log the scan
        $this->log_cron_event('scheduled_scan', 'completed', [
            'files_scanned' => $results['files_scanned'] ?? 0,
            'threats_found' => count($results['threats_found'] ?? []),
        ]);
    }
    
    /**
     * Run initial scan after setup
     *
     * @since 3.0.0
     */
    public function run_initial_scan() {
        if (!class_exists('Secure_Aura_Malware_Scanner')) {
            require_once SECURE_AURA_INCLUDES_DIR . 'class-malware-scanner.php';
        }
        
        $scanner = new Secure_Aura_Malware_Scanner();
        $scanner->run_quick_scan();
        
        $this->log_cron_event('initial_scan', 'completed');
    }
    
    /**
     * Cleanup old data
     *
     * @since 3.0.0
     */
    public function cleanup_old_data() {
        $retention_days = $this->settings['log_retention_days'] ?? 90;
        
        // Load schema class
        if (!class_exists('Secure_Aura_Schema')) {
            require_once SECURE_AURA_PLUGIN_DIR . 'database/class-schema.php';
        }
        
        $schema = new Secure_Aura_Schema();
        $results = $schema->cleanup_old_data($retention_days);
        
        // Cleanup old quarantine files
        $this->cleanup_quarantine_files();
        
        // Cleanup old cache files
        $this->cleanup_cache_files();
        
        $this->log_cron_event('cleanup_old_data', 'completed', $results);
    }
    
    /**
     * Cleanup old quarantine files
     *
     * @since 3.0.0
     */
    private function cleanup_quarantine_files() {
        $quarantine_dir = SECURE_AURA_QUARANTINE_DIR;
        
        if (!is_dir($quarantine_dir)) {
            return;
        }
        
        $retention_days = 30; // Keep quarantined files for 30 days
        $cutoff_time = time() - ($retention_days * DAY_IN_SECONDS);
        
        $files = glob($quarantine_dir . '*');
        $deleted = 0;
        
        foreach ($files as $file) {
            if (is_file($file) && filemtime($file) < $cutoff_time) {
                if (unlink($file)) {
                    $deleted++;
                }
            }
        }
        
        return $deleted;
    }
    
    /**
     * Cleanup old cache files
     *
     * @since 3.0.0
     */
    private function cleanup_cache_files() {
        $cache_dir = SECURE_AURA_CACHE_DIR;
        
        if (!is_dir($cache_dir)) {
            return;
        }
        
        $files = glob($cache_dir . '*');
        $deleted = 0;
        
        foreach ($files as $file) {
            if (is_file($file) && filemtime($file) < (time() - DAY_IN_SECONDS)) {
                if (unlink($file)) {
                    $deleted++;
                }
            }
        }
        
        return $deleted;
    }
    
    /**
     * Update threat intelligence feeds
     *
     * @since 3.0.0
     */
    public function update_threat_intelligence() {
        // Check if threat intelligence is enabled
        if (empty($this->settings['threat_intelligence_feeds'])) {
            return;
        }
        
        $feeds = [
            'malicious_ips' => 'https://feeds.secureaura.pro/basic/malicious-ips.json',
            'malware_domains' => 'https://feeds.secureaura.pro/basic/malware-domains.json',
            'malware_signatures' => 'https://feeds.secureaura.pro/basic/signatures.json',
        ];
        
        $updated = 0;
        
        foreach ($feeds as $type => $url) {
            $response = wp_remote_get($url, [
                'timeout' => 30,
                'user-agent' => 'SecureAura/' . SECURE_AURA_VERSION,
            ]);
            
            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                $data = json_decode(wp_remote_retrieve_body($response), true);
                
                if ($data && is_array($data)) {
                    $this->import_threat_data($type, $data);
                    $updated++;
                }
            }
        }
        
        update_option('secure_aura_threat_intel_last_update', current_time('mysql'));
        
        $this->log_cron_event('update_threat_intel', 'completed', [
            'feeds_updated' => $updated,
        ]);
    }
    
    /**
     * Import threat intelligence data
     *
     * @since 3.0.0
     * @param string $type Data type
     * @param array $data Threat data
     */
    private function import_threat_data($type, $data) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_THREATS;
        
        foreach ($data as $item) {
            // Check if threat already exists
            $exists = $wpdb->get_var($wpdb->prepare(
                "SELECT id FROM {$table_name} WHERE indicator_value = %s AND indicator_type = %s",
                $item['value'] ?? '',
                $type
            ));
            
            if (!$exists) {
                $wpdb->insert($table_name, [
                    'threat_type' => $item['type'] ?? $type,
                    'indicator_value' => $item['value'] ?? '',
                    'indicator_type' => $type,
                    'confidence_score' => $item['confidence'] ?? 0.8,
                    'source' => 'threat_feed',
                    'is_active' => 1,
                    'first_seen' => current_time('mysql'),
                    'last_seen' => current_time('mysql'),
                ]);
            } else {
                // Update last seen
                $wpdb->update(
                    $table_name,
                    ['last_seen' => current_time('mysql')],
                    ['id' => $exists]
                );
            }
        }
    }
    
    /**
     * Check file integrity
     *
     * @since 3.0.0
     */
    public function check_file_integrity() {
        // Only run if file integrity monitoring is enabled
        if (empty($this->settings['file_integrity_monitoring_enabled'])) {
            return;
        }
        
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_FILE_INTEGRITY;
        
        // Get files to check
        $files = $wpdb->get_results("
            SELECT * FROM {$table_name} 
            WHERE is_monitored = 1 
            LIMIT 100
        ");
        
        $changes_detected = 0;
        
        foreach ($files as $file) {
            if (file_exists($file->file_path)) {
                $current_hash = hash_file('sha256', $file->file_path);
                
                if ($current_hash !== $file->file_hash) {
                    // File changed
                    $changes_detected++;
                    
                    // Update database
                    $wpdb->update(
                        $table_name,
                        [
                            'file_hash' => $current_hash,
                            'last_modified' => date('Y-m-d H:i:s', filemtime($file->file_path)),
                            'change_detected' => 1,
                        ],
                        ['id' => $file->id]
                    );
                    
                    // Log change
                    $this->log_file_change($file->file_path);
                }
            }
        }
        
        $this->log_cron_event('check_file_integrity', 'completed', [
            'files_checked' => count($files),
            'changes_detected' => $changes_detected,
        ]);
    }
    
    /**
     * Log file change
     *
     * @since 3.0.0
     * @param string $file_path File path
     */
    private function log_file_change($file_path) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $wpdb->insert($table_name, [
            'event_type' => 'file_change',
            'severity' => 'medium',
            'event_data' => json_encode([
                'file_path' => $file_path,
                'detected_at' => current_time('mysql'),
            ]),
            'created_at' => current_time('mysql'),
        ]);
    }
    
    /**
     * Optimize database tables
     *
     * @since 3.0.0
     */
    public function optimize_database() {
        global $wpdb;
        
        $tables = [
            SECURE_AURA_TABLE_LOGS,
            SECURE_AURA_TABLE_THREATS,
            SECURE_AURA_TABLE_BEHAVIORAL,
            SECURE_AURA_TABLE_FILE_INTEGRITY,
            SECURE_AURA_TABLE_BLOCKED_IPS,
            SECURE_AURA_TABLE_QUARANTINE,
        ];
        
        $optimized = 0;
        
        foreach ($tables as $table) {
            $table_name = $wpdb->prefix . $table;
            $wpdb->query("OPTIMIZE TABLE {$table_name}");
            $optimized++;
        }
        
        $this->log_cron_event('database_optimization', 'completed', [
            'tables_optimized' => $optimized,
        ]);
    }
    
    /**
     * Generate scheduled reports
     *
     * @since 3.0.0
     */
    public function generate_scheduled_reports() {
        // Generate weekly security report
        $report_data = $this->collect_weekly_stats();
        
        // Send email report
        if (!empty($this->settings['notify_on_scan'])) {
            if (!class_exists('Secure_Aura_Email_Notifications')) {
                require_once SECURE_AURA_INCLUDES_DIR . 'class-email-notifications.php';
            }
            
            $email = new Secure_Aura_Email_Notifications();
            // Send weekly summary email
        }
        
        $this->log_cron_event('generate_reports', 'completed');
    }
    
    /**
     * Collect weekly statistics
     *
     * @since 3.0.0
     * @return array Weekly stats
     */
    private function collect_weekly_stats() {
        global $wpdb;
        
        $logs_table = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $week_ago = date('Y-m-d H:i:s', strtotime('-1 week'));
        
        return [
            'total_events' => $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$logs_table} WHERE created_at >= %s",
                $week_ago
            )),
            'threats_blocked' => $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$logs_table} 
                WHERE created_at >= %s AND response_action = 'block'",
                $week_ago
            )),
        ];
    }
    
    /**
     * Log cron event
     *
     * @since 3.0.0
     * @param string $task Task name
     * @param string $status Task status
     * @param array $meta Additional metadata
     */
    private function log_cron_event($task, $status, $meta = []) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $wpdb->insert($table_name, [
            'event_type' => 'cron_task',
            'severity' => 'info',
            'event_data' => json_encode([
                'task' => $task,
                'status' => $status,
                'meta' => $meta,
            ]),
            'created_at' => current_time('mysql'),
        ]);
    }
    
    /**
     * Clear all scheduled cron jobs
     *
     * @since 3.0.0
     */
    public function clear_all_cron_jobs() {
        $cron_hooks = [
            'secure_aura_scheduled_scan',
            'secure_aura_cleanup_old_data',
            'secure_aura_update_threat_intel',
            'secure_aura_check_file_integrity',
            'secure_aura_database_optimization',
            'secure_aura_generate_reports',
            'secure_aura_initial_scan',
        ];
        
        foreach ($cron_hooks as $hook) {
            $timestamp = wp_next_scheduled($hook);
            if ($timestamp) {
                wp_unschedule_event($timestamp, $hook);
            }
        }
    }
    
    /**
     * Get next scheduled scan time
     *
     * @since 3.0.0
     * @return string|bool Next scan time or false
     */
    public function get_next_scan_time() {
        $timestamp = wp_next_scheduled('secure_aura_scheduled_scan');
        
        if ($timestamp) {
            return date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $timestamp);
        }
        
        return false;
    }
    
    /**
     * Manually trigger a scheduled task
     *
     * @since 3.0.0
     * @param string $task Task name
     * @return bool True if triggered successfully
     */
    public function trigger_task($task) {
        $valid_tasks = [
            'scheduled_scan',
            'cleanup_old_data',
            'update_threat_intel',
            'check_file_integrity',
            'database_optimization',
        ];
        
        if (!in_array($task, $valid_tasks)) {
            return false;
        }
        
        $method = str_replace('_', '_', $task);
        
        if (method_exists($this, $method)) {
            $this->$method();
            return true;
        }
        
        return false;
    }
}