<?php

/**
 * Fired during plugin activation
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
 * Fired during plugin activation.
 *
 * This class defines all code necessary to run during the plugin's activation.
 *
 * @since      3.0.0
 * @package    SecureAura
 * @subpackage SecureAura/includes
 * @author     Bitekservices
 */
class Secure_Aura_Activator
{

    /**
     * Short Description. (use period)
     *
     * Long Description.
     *
     * @since    3.0.0
     */
    public static function activate()
    {
        // Check system requirements
        self::check_system_requirements();

        // Create database tables
        self::create_database_tables();

        // Create secure directories
        self::create_secure_directories();

        // Set up file permissions
        self::setup_file_permissions();

        // Install default configuration
        self::install_default_configuration();

        // Create default security rules
        self::create_default_security_rules();

        // Download initial threat intelligence
        self::download_initial_threat_data();

        // Set up cron jobs
        self::setup_cron_jobs();

        // Create security capabilities
        self::create_security_capabilities();

        // Generate encryption keys
        self::generate_encryption_keys();

        // Set up .htaccess protection
        self::setup_htaccess_protection();

        // Initialize AI models (if Pro/Enterprise)
        self::initialize_ai_models();

        // Create initial backup
        self::create_initial_backup();

        // Send activation notification
        self::send_activation_notification();

        $cron_manager = new Secure_Aura_Cron_Manager();
        $cron_manager->setup_cron_jobs();

        // Set activation flag
        update_option('secure_aura_activated', true);
        update_option('secure_aura_activation_time', current_time('mysql'));
        update_option('secure_aura_version', SECURE_AURA_VERSION);

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Check system requirements before activation.
     *
     * @since    3.0.0
     * @throws   Exception If requirements are not met.
     */
    private static function check_system_requirements()
    {
        $errors = [];

        // Check PHP version
        if (version_compare(PHP_VERSION, SECURE_AURA_MIN_PHP, '<')) {
            $errors[] = sprintf(
                __('SecureAura requires PHP version %s or higher. Current version: %s', 'secure-aura'),
                SECURE_AURA_MIN_PHP,
                PHP_VERSION
            );
        }

        // Check WordPress version
        global $wp_version;
        if (version_compare($wp_version, SECURE_AURA_MIN_WP, '<')) {
            $errors[] = sprintf(
                __('SecureAura requires WordPress version %s or higher. Current version: %s', 'secure-aura'),
                SECURE_AURA_MIN_WP,
                $wp_version
            );
        }

        // Check required PHP extensions
        $required_extensions = [
            'openssl' => __('OpenSSL extension is required for encryption', 'secure-aura'),
            'curl' => __('cURL extension is required for external API calls', 'secure-aura'),
            'json' => __('JSON extension is required for data processing', 'secure-aura'),
            'mbstring' => __('Mbstring extension is required for string processing', 'secure-aura'),
            'hash' => __('Hash extension is required for security functions', 'secure-aura'),
            'zip' => __('ZIP extension is required for backup functionality', 'secure-aura'),
        ];

        foreach ($required_extensions as $extension => $description) {
            if (!extension_loaded($extension)) {
                $errors[] = $description;
            }
        }

        // Check memory limit
        $memory_limit = ini_get('memory_limit');
        $memory_bytes = wp_convert_hr_to_bytes($memory_limit);
        $required_memory = 128 * 1024 * 1024; // 128MB

        if ($memory_bytes < $required_memory) {
            $errors[] = sprintf(
                __('SecureAura requires at least 128MB of memory. Current limit: %s', 'secure-aura'),
                $memory_limit
            );
        }

        // Check file permissions
        $upload_dir = wp_upload_dir();
        if (!wp_is_writable($upload_dir['basedir'])) {
            $errors[] = __('WordPress uploads directory is not writable', 'secure-aura');
        }

        // Check if mod_rewrite is available
        if (!got_mod_rewrite()) {
            $errors[] = __('mod_rewrite is not available. Some features may not work properly.', 'secure-aura');
        }

        // If there are errors, stop activation
        if (!empty($errors)) {
            $error_message = '<h3>' . __('SecureAura Activation Failed', 'secure-aura') . '</h3>';
            $error_message .= '<p>' . __('The following requirements are not met:', 'secure-aura') . '</p>';
            $error_message .= '<ul>';
            foreach ($errors as $error) {
                $error_message .= '<li>' . esc_html($error) . '</li>';
            }
            $error_message .= '</ul>';

            wp_die($error_message, __('Plugin Activation Error', 'secure-aura'), ['back_link' => true]);
        }
    }

    /**
     * Create database tables.
     *
     * @since    3.0.0
     */
    private static function create_database_tables()
    {
        require_once SECURE_AURA_PLUGIN_DIR . 'database/class-schema.php';

        if (class_exists('Secure_Aura_Schema')) {
            $schema = new Secure_Aura_Schema();
            $schema->create_tables();
        }
    }

    /**
     * Create secure directories.
     *
     * @since    3.0.0
     */
    private static function create_secure_directories()
    {
        $directories = [
            SECURE_AURA_UPLOADS_DIR,
            SECURE_AURA_LOGS_DIR,
            SECURE_AURA_CACHE_DIR,
            SECURE_AURA_QUARANTINE_DIR,
            SECURE_AURA_BACKUPS_DIR,
            SECURE_AURA_REPORTS_DIR,
        ];

        foreach ($directories as $dir) {
            if (!file_exists($dir)) {
                wp_mkdir_p($dir);

                // Create index.php to prevent directory listing
                $index_file = $dir . 'index.php';
                if (!file_exists($index_file)) {
                    file_put_contents($index_file, '<?php // Silence is golden.');
                }

                // Create .htaccess for additional protection
                $htaccess_file = $dir . '.htaccess';
                if (!file_exists($htaccess_file)) {
                    $htaccess_content = "Order deny,allow\nDeny from all\n";
                    file_put_contents($htaccess_file, $htaccess_content);
                }
            }
        }
    }

    /**
     * Set up file permissions.
     *
     * @since    3.0.0
     */
    private static function setup_file_permissions()
    {
        // Set secure permissions for plugin directories
        $secure_dirs = [
            SECURE_AURA_LOGS_DIR => 0750,
            SECURE_AURA_CACHE_DIR => 0750,
            SECURE_AURA_QUARANTINE_DIR => 0700,
            SECURE_AURA_BACKUPS_DIR => 0700,
        ];

        foreach ($secure_dirs as $dir => $permission) {
            if (file_exists($dir)) {
                chmod($dir, $permission);
            }
        }

        // Set permissions for sensitive files
        $sensitive_files = [
            SECURE_AURA_PLUGIN_DIR . 'config/',
            SECURE_AURA_PLUGIN_DIR . 'logs/',
            SECURE_AURA_PLUGIN_DIR . 'cache/',
        ];

        foreach ($sensitive_files as $path) {
            if (file_exists($path)) {
                // Recursively set permissions
                self::set_directory_permissions($path);
            }
        }
    }

    /**
     * Recursively set directory permissions.
     *
     * @since    3.0.0
     * @param    string $path Directory path.
     */
    private static function set_directory_permissions($path)
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                chmod($item->getRealPath(), 0750);
            } else {
                chmod($item->getRealPath(), 0640);
            }
        }
    }

    /**
     * Install default configuration.
     *
     * @since    3.0.0
     */
    private static function install_default_configuration()
    {
        // Load default settings
        $default_config_file = SECURE_AURA_PLUGIN_DIR . 'config/default-settings.php';
        if (file_exists($default_config_file)) {
            $default_config = include $default_config_file;
        } else {
            $default_config = self::get_fallback_default_config();
        }

        // Save default configuration
        update_option('secure_aura_settings', $default_config);

        // Set initial security level based on hosting environment
        $security_level = self::detect_optimal_security_level();
        update_option('secure_aura_security_level', $security_level);

        // Create license key placeholder
        update_option('secure_aura_license_key', '');
        update_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE);

        // Set up notification settings
        update_option('secure_aura_notification_email', get_option('admin_email'));
        update_option('secure_aura_last_notification_check', current_time('mysql'));
    }

    /**
     * Get fallback default configuration if config file doesn't exist.
     *
     * @since    3.0.0
     * @return   array Default configuration array.
     */
    private static function get_fallback_default_config()
    {
        return [
            'security_level' => SECURE_AURA_LEVEL_ENHANCED,
            'quantum_firewall_enabled' => true,
            'ai_threat_detection_enabled' => false, // Free version limitation
            'behavioral_monitoring_enabled' => false, // Free version limitation
            'real_time_scanning_enabled' => true,
            'file_integrity_monitoring_enabled' => true,
            'firewall_mode' => 'learning',
            'auto_block_malicious_ips' => true,
            'ai_threat_threshold' => 0.7,
            'scan_frequency' => 'daily',
            'log_retention_days' => 30, // Free version limitation
            'email_notifications' => true,
            'debug_mode' => false,
            'performance_monitoring' => true,
        ];
    }

    /**
     * Detect optimal security level based on hosting environment.
     *
     * @since    3.0.0
     * @return   int Security level constant.
     */
    private static function detect_optimal_security_level()
    {
        // Check if this is a development environment
        if (defined('WP_DEBUG') && WP_DEBUG) {
            return SECURE_AURA_LEVEL_BASIC;
        }

        // Check server capabilities
        $memory_limit = wp_convert_hr_to_bytes(ini_get('memory_limit'));
        $max_execution_time = ini_get('max_execution_time');

        // High-performance server
        if ($memory_limit >= 512 * 1024 * 1024 && $max_execution_time >= 300) {
            return SECURE_AURA_LEVEL_QUANTUM;
        }

        // Medium-performance server
        if ($memory_limit >= 256 * 1024 * 1024 && $max_execution_time >= 60) {
            return SECURE_AURA_LEVEL_ENHANCED;
        }

        // Basic server
        return SECURE_AURA_LEVEL_BASIC;
    }

    /**
     * Create default security rules.
     *
     * @since    3.0.0
     */
    private static function create_default_security_rules()
    {
        global $wpdb;

        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_THREATS;

        // Default malicious IP ranges
        $default_threats = [
            // Known malicious IP ranges
            ['type' => 'ip_range', 'value' => '0.0.0.0/8', 'confidence' => 1.0, 'source' => 'builtin'],
            ['type' => 'ip_range', 'value' => '127.0.0.0/8', 'confidence' => 0.5, 'source' => 'builtin'],
            ['type' => 'ip_range', 'value' => '169.254.0.0/16', 'confidence' => 0.7, 'source' => 'builtin'],
            ['type' => 'ip_range', 'value' => '224.0.0.0/4', 'confidence' => 0.8, 'source' => 'builtin'],

            // Known malicious domains
            ['type' => 'domain', 'value' => 'malware-domain.com', 'confidence' => 1.0, 'source' => 'builtin'],
            ['type' => 'domain', 'value' => 'phishing-site.net', 'confidence' => 1.0, 'source' => 'builtin'],

            // Common attack patterns
            ['type' => 'url_pattern', 'value' => '/wp-admin/admin-ajax.php', 'confidence' => 0.3, 'source' => 'builtin'],
            ['type' => 'url_pattern', 'value' => '/xmlrpc.php', 'confidence' => 0.6, 'source' => 'builtin'],
            ['type' => 'url_pattern', 'value' => '/.env', 'confidence' => 0.9, 'source' => 'builtin'],
            ['type' => 'url_pattern', 'value' => '/config.php', 'confidence' => 0.8, 'source' => 'builtin'],
        ];

        foreach ($default_threats as $threat) {
            $wpdb->insert($table_name, [
                'threat_type' => $threat['type'],
                'indicator_value' => $threat['value'],
                'indicator_type' => $threat['type'],
                'confidence_score' => $threat['confidence'],
                'source' => $threat['source'],
                'is_active' => 1,
                'first_seen' => current_time('mysql'),
                'last_seen' => current_time('mysql'),
            ]);
        }
    }

    /**
     * Download initial threat intelligence data.
     *
     * @since    3.0.0
     */
    private static function download_initial_threat_data()
    {
        // Only download if we have an internet connection
        if (!self::check_internet_connection()) {
            return;
        }

        // Download basic threat feeds for free users
        $free_feeds = [
            'https://feeds.secureaura.pro/basic/malicious-ips.json',
            'https://feeds.secureaura.pro/basic/malware-domains.json',
        ];

        foreach ($free_feeds as $feed_url) {
            $response = wp_remote_get($feed_url, [
                'timeout' => 30,
                'user-agent' => 'SecureAura/' . SECURE_AURA_VERSION . ' WordPress Security Plugin'
            ]);

            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                $data = json_decode(wp_remote_retrieve_body($response), true);
                if ($data) {
                    self::import_threat_data($data);
                }
            }
        }

        // Set last update time
        update_option('secure_aura_threat_intel_last_update', current_time('mysql'));
    }

    /**
     * Import threat intelligence data.
     *
     * @since    3.0.0
     * @param    array $data Threat data array.
     */
    private static function import_threat_data($data)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_THREATS;

        foreach ($data as $threat) {
            $wpdb->insert($table_name, [
                'threat_type' => sanitize_text_field($threat['type'] ?? ''),
                'indicator_value' => sanitize_text_field($threat['value'] ?? ''),
                'indicator_type' => sanitize_text_field($threat['indicator_type'] ?? ''),
                'confidence_score' => floatval($threat['confidence'] ?? 0.5),
                'source' => sanitize_text_field($threat['source'] ?? 'external'),
                'tags' => sanitize_text_field($threat['tags'] ?? ''),
                'is_active' => 1,
                'first_seen' => current_time('mysql'),
                'last_seen' => current_time('mysql'),
            ]);
        }
    }

    /**
     * Check internet connection.
     *
     * @since    3.0.0
     * @return   bool True if internet connection is available.
     */
    private static function check_internet_connection()
    {
        $response = wp_remote_get('https://api.secureaura.pro/ping', [
            'timeout' => 10,
            'sslverify' => false
        ]);

        return !is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200;
    }

    /**
     * Set up cron jobs.
     *
     * @since    3.0.0
     */
    private static function setup_cron_jobs()
    {
        // Schedule threat intelligence updates
        if (!wp_next_scheduled(SECURE_AURA_CRON_THREAT_INTEL_UPDATE)) {
            wp_schedule_event(time() + 3600, 'hourly', SECURE_AURA_CRON_THREAT_INTEL_UPDATE);
        }

        // Schedule daily full scan
        if (!wp_next_scheduled(SECURE_AURA_CRON_FULL_SCAN)) {
            // Schedule for 2 AM local time
            $scan_time = strtotime('tomorrow 2:00 AM');
            wp_schedule_event($scan_time, 'daily', SECURE_AURA_CRON_FULL_SCAN);
        }

        // Schedule log cleanup
        if (!wp_next_scheduled(SECURE_AURA_CRON_LOG_CLEANUP)) {
            wp_schedule_event(time() + 86400, 'daily', SECURE_AURA_CRON_LOG_CLEANUP);
        }

        // Schedule cache cleanup
        if (!wp_next_scheduled(SECURE_AURA_CRON_CACHE_CLEANUP)) {
            wp_schedule_event(time() + 3600, 'hourly', SECURE_AURA_CRON_CACHE_CLEANUP);
        }

        // Schedule performance monitoring
        if (!wp_next_scheduled(SECURE_AURA_CRON_PERFORMANCE_CHECK)) {
            wp_schedule_event(time() + 1800, 'hourly', SECURE_AURA_CRON_PERFORMANCE_CHECK);
        }

        // Schedule file integrity check
        if (!wp_next_scheduled(SECURE_AURA_CRON_INTEGRITY_CHECK)) {
            wp_schedule_event(time() + 21600, 'twicedaily', SECURE_AURA_CRON_INTEGRITY_CHECK);
        }
    }

    /**
     * Create security capabilities for role-based access.
     *
     * @since    3.0.0
     */
    private static function create_security_capabilities()
    {
        $admin_role = get_role('administrator');

        if ($admin_role) {
            $security_capabilities = [
                SECURE_AURA_CAP_MANAGE_SECURITY,
                SECURE_AURA_CAP_VIEW_LOGS,
                SECURE_AURA_CAP_MANAGE_FIREWALL,
                SECURE_AURA_CAP_RUN_SCANS,
                SECURE_AURA_CAP_MANAGE_THREATS,
                SECURE_AURA_CAP_VIEW_REPORTS,
            ];

            foreach ($security_capabilities as $capability) {
                $admin_role->add_cap($capability);
            }
        }

        // Create security manager role
        add_role('secure_aura_manager', __('Security Manager', 'secure-aura'), [
            'read' => true,
            SECURE_AURA_CAP_VIEW_LOGS => true,
            SECURE_AURA_CAP_RUN_SCANS => true,
            SECURE_AURA_CAP_VIEW_REPORTS => true,
        ]);

        // Create security viewer role
        add_role('secure_aura_viewer', __('Security Viewer', 'secure-aura'), [
            'read' => true,
            SECURE_AURA_CAP_VIEW_LOGS => true,
            SECURE_AURA_CAP_VIEW_REPORTS => true,
        ]);
    }

    /**
     * Generate encryption keys for secure data storage.
     *
     * @since    3.0.0
     */
    private static function generate_encryption_keys()
    {
        // Generate master encryption key
        if (!get_option('secure_aura_master_key')) {
            $master_key = bin2hex(random_bytes(32)); // 256-bit key
            update_option('secure_aura_master_key', $master_key);
        }

        // Generate API key for internal communications
        if (!get_option('secure_aura_api_key')) {
            $api_key = wp_generate_password(64, true, true);
            update_option('secure_aura_api_key', $api_key);
        }

        // Generate salt for password hashing
        if (!get_option('secure_aura_password_salt')) {
            $salt = bin2hex(random_bytes(16)); // 128-bit salt
            update_option('secure_aura_password_salt', $salt);
        }

        // Generate CSRF token
        if (!get_option('secure_aura_csrf_token')) {
            $csrf_token = bin2hex(random_bytes(32));
            update_option('secure_aura_csrf_token', $csrf_token);
        }
    }

    /**
     * Set up .htaccess protection for sensitive directories.
     *
     * @since    3.0.0
     */
    private static function setup_htaccess_protection()
    {
        $protected_dirs = [
            SECURE_AURA_LOGS_DIR,
            SECURE_AURA_CACHE_DIR,
            SECURE_AURA_QUARANTINE_DIR,
            SECURE_AURA_BACKUPS_DIR,
            SECURE_AURA_PLUGIN_DIR . 'config/',
        ];

        $htaccess_content = "# SecureAura Protection\n";
        $htaccess_content .= "Order deny,allow\n";
        $htaccess_content .= "Deny from all\n";
        $htaccess_content .= "<Files ~ \"\\.(php|pl|py|jsp|asp|sh|cgi)$\">\n";
        $htaccess_content .= "    deny from all\n";
        $htaccess_content .= "</Files>\n";

        foreach ($protected_dirs as $dir) {
            if (file_exists($dir)) {
                $htaccess_file = $dir . '.htaccess';
                if (!file_exists($htaccess_file)) {
                    file_put_contents($htaccess_file, $htaccess_content);
                }
            }
        }

        // Protect main plugin directory
        $main_htaccess = SECURE_AURA_PLUGIN_DIR . '.htaccess';
        if (!file_exists($main_htaccess)) {
            $main_protection = "# SecureAura Plugin Protection\n";
            $main_protection .= "<Files ~ \"\\.(log|txt|md)$\">\n";
            $main_protection .= "    deny from all\n";
            $main_protection .= "</Files>\n";
            file_put_contents($main_htaccess, $main_protection);
        }
    }

    /**
     * Initialize AI models for Pro/Enterprise users.
     *
     * @since    3.0.0
     */
    private static function initialize_ai_models()
    {
        // This will be expanded for Pro/Enterprise versions
        $license_type = get_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE);

        if ($license_type !== SECURE_AURA_LICENSE_FREE) {
            // Download and initialize AI models
            self::download_ai_models();
        }

        // Set AI model status
        update_option('secure_aura_ai_models_initialized', false);
        update_option('secure_aura_ai_last_update', current_time('mysql'));
    }

    /**
     * Download AI models for threat detection.
     *
     * @since    3.0.0
     */
    private static function download_ai_models()
    {
        // Placeholder for AI model download
        // This will be implemented for Pro/Enterprise versions
        $ai_models_dir = SECURE_AURA_PLUGIN_DIR . 'vendor/ai-models/';
        wp_mkdir_p($ai_models_dir);

        // Create placeholder files
        $model_files = [
            'threat-detection-v3.model',
            'behavioral-analysis-v2.model',
            'malware-detection-v4.model',
        ];

        foreach ($model_files as $model_file) {
            $file_path = $ai_models_dir . $model_file;
            if (!file_exists($file_path)) {
                file_put_contents($file_path, '# AI Model Placeholder - Pro Version Required');
            }
        }
    }

    /**
     * Create initial backup of the site.
     *
     * @since    3.0.0
     */
    private static function create_initial_backup()
    {
        // Create a baseline backup before first scan
        $backup_data = [
            'created' => current_time('mysql'),
            'type' => 'initial',
            'version' => SECURE_AURA_VERSION,
            'wp_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'plugins' => get_option('active_plugins', []),
            'theme' => get_stylesheet(),
        ];

        // Store backup metadata
        update_option('secure_aura_initial_backup', $backup_data);

        // Schedule full backup creation
        wp_schedule_single_event(time() + 300, 'secure_aura_create_initial_backup');
    }

    /**
     * Send activation notification to admin.
     *
     * @since    3.0.0
     */
    private static function send_activation_notification()
    {
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        $site_url = home_url();

        $subject = sprintf(__('[%s] SecureAura Security Plugin Activated', 'secure-aura'), $site_name);

        $message = sprintf(
            __('SecureAura has been successfully activated on your website %s.

            Security Level: Enhanced
            Real-time Protection: Enabled
            Scheduled Scans: Daily at 2:00 AM

            Next Steps:
            1. Visit the SecureAura dashboard: %s
            2. Review your security settings
            3. Run your first security scan
            4. Consider upgrading to Pro for advanced features

            For support and documentation, visit: https://secureaura.pro/docs

            Stay secure!
            The SecureAura Team', 'secure-aura'),
            $site_url,
            admin_url('admin.php?page=secure-aura')
        );

        $headers = [
            'Content-Type: text/plain; charset=UTF-8',
            'From: SecureAura <noreply@secureaura.pro>',
        ];

        wp_mail($admin_email, $subject, $message, $headers);
    }

    /**
     * Log activation event.
     *
     * @since    3.0.0
     */
    private static function log_activation_event()
    {
        global $wpdb;

        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;

        $wpdb->insert($table_name, [
            'event_type' => 'plugin_activation',
            'severity' => SECURE_AURA_SEVERITY_INFO,
            'source_ip' => self::get_client_ip(),
            'user_id' => get_current_user_id(),
            'event_data' => json_encode([
                'version' => SECURE_AURA_VERSION,
                'wp_version' => get_bloginfo('version'),
                'php_version' => PHP_VERSION,
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            ]),
            'geolocation' => '',
            'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'response_action' => 'activation_completed',
        ]);
    }

    /**
     * Get client IP address.
     *
     * @since    3.0.0
     * @return   string Client IP address.
     */
    private static function get_client_ip()
    {
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
     * Validate plugin requirements during activation.
     *
     * @since    3.0.0
     * @return   bool True if all requirements are met.
     */
    private static function validate_requirements()
    {
        $requirements = [
            'php_version' => version_compare(PHP_VERSION, SECURE_AURA_MIN_PHP, '>='),
            'wp_version' => version_compare(get_bloginfo('version'), SECURE_AURA_MIN_WP, '>='),
            'memory_limit' => wp_convert_hr_to_bytes(ini_get('memory_limit')) >= (128 * 1024 * 1024),
            'disk_space' => disk_free_space(ABSPATH) >= (100 * 1024 * 1024), // 100MB
            'writable_uploads' => wp_is_writable(wp_upload_dir()['basedir']),
        ];

        $failed_requirements = array_filter($requirements, function ($met) {
            return !$met;
        });

        if (!empty($failed_requirements)) {
            update_option('secure_aura_failed_requirements', array_keys($failed_requirements));
            return false;
        }

        return true;
    }

    /**
     * Create activation summary.
     *
     * @since    3.0.0
     */
    private static function create_activation_summary()
    {
        $summary = [
            'activation_time' => current_time('mysql'),
            'version' => SECURE_AURA_VERSION,
            'security_level' => get_option('secure_aura_security_level'),
            'features_enabled' => [],
            'cron_jobs_scheduled' => 6,
            'database_tables_created' => 10,
            'directories_created' => 6,
            'default_rules_created' => 10,
            'encryption_keys_generated' => 4,
        ];

        // Determine enabled features based on license
        $license_type = get_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE);
        $features = secure_aura_get_license_features()[$license_type] ?? [];
        $summary['features_enabled'] = array_keys(array_filter($features));

        update_option('secure_aura_activation_summary', $summary);
    }
}
