<?php

/**
 * The core plugin class.
 *
 * This is used to define internationalization, admin-specific hooks, and
 * public-facing site hooks.
 *
 * Also maintains the unique identifier of this plugin as well as the current
 * version of the plugin.
 *
 * @since      3.0.0
 * @package    SecureAura
 * @subpackage SecureAura/includes
 * @author     Bitekservices
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

class Secure_Aura
{

    /**
     * The loader that's responsible for maintaining and registering all hooks that power
     * the plugin.
     *
     * @since    3.0.0
     * @access   protected
     * @var      Secure_Aura_Loader    $loader    Maintains and registers all hooks for the plugin.
     */
    protected $loader;

    /**
     * The unique identifier of this plugin.
     *
     * @since    3.0.0
     * @access   protected
     * @var      string    $plugin_name    The string used to uniquely identify this plugin.
     */
    protected $plugin_name;

    /**
     * The current version of the plugin.
     *
     * @since    3.0.0
     * @access   protected
     * @var      string    $version    The current version of the plugin.
     */
    protected $version;

    /**
     * The plugin configuration.
     *
     * @since    3.0.0
     * @access   protected
     * @var      array    $config    Plugin configuration array.
     */
    protected $config;

    /**
     * Security modules instances.
     *
     * @since    3.0.0
     * @access   protected
     * @var      array    $modules    Array of loaded security modules.
     */
    protected $modules;

    /**
     * Plugin components instances.
     *
     * @since    3.0.0
     * @access   protected
     * @var      array    $components    Array of plugin components.
     */
    protected $components;

    /**
     * Database manager instance.
     *
     * @since    3.0.0
     * @access   protected
     * @var      Secure_Aura_Database_Manager    $db_manager    Database manager instance.
     */
    protected $db_manager;

    /**
     * Email notifications manager instance.
     *
     * @since    3.0.0
     * @access   protected
     * @var      Secure_Aura_Email_Notifications    $email_notifications    Email notifications manager instance.
     */
    protected $email_notifications;

    /**
     * Define the core functionality of the plugin.
     *
     * Set the plugin name and the plugin version that can be used throughout the plugin.
     * Load the dependencies, define the locale, and set the hooks for the admin area and
     * the public-facing side of the site.
     *
     * @since    3.0.0
     */
    public function __construct()
    {
        if (defined('SECURE_AURA_VERSION')) {
            $this->version = SECURE_AURA_VERSION;
        } else {
            $this->version = '3.0.0';
        }

        $this->plugin_name = 'secure-aura';
        $this->modules = [];
        $this->components = [];

        $this->load_dependencies();
        $this->load_configuration();
        $this->init_database_manager();
        $this->set_locale();
        $this->define_admin_hooks();
        $this->define_public_hooks();
        $this->init_security_modules();
        $this->init_api_endpoints();
        $this->schedule_background_tasks();
    }

    /**
     * Load the required dependencies for this plugin.
     *
     * Include the following files that make up the plugin:
     *
     * - Secure_Aura_Loader. Orchestrates the hooks of the plugin.
     * - Secure_Aura_i18n. Defines internationalization functionality.
     * - Secure_Aura_Admin. Defines all hooks for the admin area.
     * - Secure_Aura_Public. Defines all hooks for the public side of the site.
     *
     * Create an instance of the loader which will be used to register the hooks
     * with WordPress.
     *
     * @since    3.0.0
     * @access   private
     */
    private function load_dependencies()
    {
        $this->loader = new Secure_Aura_Loader();

        // Load core classes
        $this->loader->load_core_classes();

        // Load security modules
        $this->loader->load_security_modules();

        // Load admin classes if in admin
        if (is_admin()) {
            $this->loader->load_admin_classes();
        }

        // Load public classes
        $this->loader->load_public_classes();

        // Load API classes if needed
        if (defined('REST_REQUEST') && REST_REQUEST) {
            $this->loader->load_api_classes();
        }

        // Load conditional classes
        $this->loader->load_conditional_classes();

        // Load license-based modules
        $this->loader->load_license_based_modules();

        // Load third-party dependencies
        $this->loader->load_dependencies();

        // Initialize loader hooks
        $this->loader->init_loader_hooks();
    }

    /**
     * Load plugin configuration.
     *
     * @since    3.0.0
     * @access   private
     */
    private function load_configuration()
    {
        // Load default configuration
        $default_config_file = SECURE_AURA_PLUGIN_DIR . 'config/default-settings.php';
        if (file_exists($default_config_file)) {
            $default_config = include $default_config_file;
        } else {
            $default_config = $this->get_default_config();
        }

        // Merge with user settings
        $user_config = get_option('secure_aura_settings', []);
        $this->config = array_merge($default_config, $user_config);

        // Apply filters to allow customization
        $this->config = apply_filters('secure_aura_config', $this->config);
    }

    /**
     * Get default plugin configuration.
     *
     * @since    3.0.0
     * @access   private
     * @return   array    Default configuration array.
     */
    private function get_default_config()
    {
        return [
            // Security Level
            'security_level' => SECURE_AURA_LEVEL_ENHANCED,

            // Core Features
            'quantum_firewall_enabled' => true,
            'ai_threat_detection_enabled' => true,
            'behavioral_monitoring_enabled' => true,
            'real_time_scanning_enabled' => true,
            'file_integrity_monitoring_enabled' => true,

            // Firewall Settings
            'firewall_mode' => 'learning', // learning, blocking, monitoring
            'auto_block_malicious_ips' => true,
            'geo_blocking_enabled' => false,
            'tor_blocking_enabled' => false,
            'vpn_blocking_enabled' => false,

            // AI Settings
            'ai_threat_threshold' => 0.7,
            'ai_learning_mode' => true,
            'ai_model_updates_enabled' => true,
            'behavioral_anomaly_threshold' => 0.8,

            // Scanning Settings
            'scan_frequency' => 'daily',
            'deep_scan_enabled' => true,
            'quarantine_malware' => true,
            'auto_clean_infections' => false,
            'scan_file_size_limit' => 50 * 1024 * 1024, // 50MB

            // Monitoring Settings
            'real_time_monitoring' => true,
            'log_retention_days' => 90,
            'performance_monitoring' => true,
            'compliance_monitoring' => false,

            // Notification Settings
            'email_notifications' => true,
            'admin_email' => get_option('admin_email'),
            'notification_threshold' => SECURE_AURA_SEVERITY_HIGH,
            'slack_webhook_url' => '',
            'custom_webhook_url' => '',

            // Advanced Settings
            'debug_mode' => false,
            'api_rate_limiting' => true,
            'database_protection' => true,
            'memory_protection' => true,
            'emergency_mode' => false,

            // License Settings
            'license_key' => '',
            'license_type' => SECURE_AURA_LICENSE_FREE,
            'auto_updates' => true,
        ];
    }

    /**
     * Initialize database manager.
     *
     * @since    3.0.0
     * @access   private
     */
    private function init_database_manager()
    {
        if (class_exists('Secure_Aura_Database_Manager')) {
            $this->db_manager = new Secure_Aura_Database_Manager();
            $this->components['database'] = $this->db_manager;
        }
    }

    /**
     * Define the locale for this plugin for internationalization.
     *
     * Uses the Secure_Aura_i18n class in order to set the domain and to register the hook
     * with WordPress.
     *
     * @since    3.0.0
     * @access   private
     */
    private function set_locale()
    {
        $plugin_i18n = new Secure_Aura_i18n();

        $this->loader->add_action('plugins_loaded', $plugin_i18n, 'load_plugin_textdomain');
    }

    /**
     * Register all of the hooks related to the admin area functionality
     * of the plugin.
     *
     * @since    3.0.0
     * @access   private
     */
    private function define_admin_hooks()
    {
        if (!is_admin()) {
            return;
        }

        if (class_exists('Secure_Aura_Admin')) {
            $plugin_admin = new Secure_Aura_Admin($this->get_plugin_name(), $this->get_version(), $this->config);
            $this->components['admin'] = $plugin_admin;

            // Admin hooks
            $this->loader->add_action('admin_enqueue_scripts', $plugin_admin, 'enqueue_styles');
            $this->loader->add_action('admin_enqueue_scripts', $plugin_admin, 'enqueue_scripts');
            $this->loader->add_action('admin_menu', $plugin_admin, 'add_admin_menu');
            $this->loader->add_action('admin_init', $plugin_admin, 'init_settings');
            $this->loader->add_action('admin_notices', $plugin_admin, 'show_admin_notices');

            // AJAX hooks
            if (class_exists('Secure_Aura_Ajax_Handler')) {
                $ajax_handler = new Secure_Aura_Ajax_Handler($this);
                $this->components['ajax'] = $ajax_handler;

                // Security scan AJAX
                $this->loader->add_action('wp_ajax_secure_aura_run_scan', $ajax_handler, 'handle_run_scan');
                $this->loader->add_action('wp_ajax_secure_aura_get_scan_status', $ajax_handler, 'handle_get_scan_status');

                // Threat intelligence AJAX
                $this->loader->add_action('wp_ajax_secure_aura_update_threat_intel', $ajax_handler, 'handle_update_threat_intel');
                $this->loader->add_action('wp_ajax_secure_aura_get_threat_stats', $ajax_handler, 'handle_get_threat_stats');

                // Firewall AJAX
                $this->loader->add_action('wp_ajax_secure_aura_update_firewall_rules', $ajax_handler, 'handle_update_firewall_rules');
                $this->loader->add_action('wp_ajax_secure_aura_block_ip', $ajax_handler, 'handle_block_ip');
                $this->loader->add_action('wp_ajax_secure_aura_unblock_ip', $ajax_handler, 'handle_unblock_ip');

                // Settings AJAX
                $this->loader->add_action('wp_ajax_secure_aura_save_settings', $ajax_handler, 'handle_save_settings');
                $this->loader->add_action('wp_ajax_secure_aura_reset_settings', $ajax_handler, 'handle_reset_settings');

                // Dashboard AJAX
                $this->loader->add_action('wp_ajax_secure_aura_get_dashboard_data', $ajax_handler, 'handle_get_dashboard_data');
                $this->loader->add_action('wp_ajax_secure_aura_get_real_time_stats', $ajax_handler, 'handle_get_real_time_stats');
            }

            if (!get_option('secure_aura_setup_complete')) {
                $setup_wizard = new Secure_Aura_Setup_Wizard();
            }

            $this->email_notifications = new Secure_Aura_Email_Notifications();
        }
    }

    /**
     * Register all of the hooks related to the public-facing functionality
     * of the plugin.
     *
     * @since    3.0.0
     * @access   private
     */
    private function define_public_hooks()
    {
        if (class_exists('Secure_Aura_Public')) {
            $plugin_public = new Secure_Aura_Public($this->get_plugin_name(), $this->get_version(), $this->config);
            $this->components['public'] = $plugin_public;

            // Public hooks
            $this->loader->add_action('wp_enqueue_scripts', $plugin_public, 'enqueue_styles');
            $this->loader->add_action('wp_enqueue_scripts', $plugin_public, 'enqueue_scripts');
            $this->loader->add_action('init', $plugin_public, 'init_frontend_protection', SECURE_AURA_PRIORITY_HIGHEST);

            // Security headers
            $this->loader->add_action('send_headers', $plugin_public, 'add_security_headers');

            // Login security
            $this->loader->add_filter('authenticate', $plugin_public, 'authenticate_user', 30, 3);
            $this->loader->add_action('wp_login_failed', $plugin_public, 'handle_failed_login');
            $this->loader->add_action('wp_login', $plugin_public, 'handle_successful_login', 10, 2);

            // Comment security
            $this->loader->add_filter('pre_comment_approved', $plugin_public, 'filter_comments', 99, 2);

            // File upload security
            $this->loader->add_filter('wp_handle_upload_prefilter', $plugin_public, 'scan_uploaded_files');
        }

        // Frontend protection
        if (class_exists('Secure_Aura_Frontend_Protection')) {
            $frontend_protection = new Secure_Aura_Frontend_Protection($this->config);
            $this->components['frontend_protection'] = $frontend_protection;

            $this->loader->add_action('init', $frontend_protection, 'init_protection', SECURE_AURA_PRIORITY_HIGHEST);
            $this->loader->add_action('wp_head', $frontend_protection, 'inject_client_protection');
        }
    }

    /**
     * Initialize security modules.
     *
     * @since    3.0.0
     * @access   private
     */
    private function init_security_modules()
    {
        $license_type = $this->config['license_type'] ?? SECURE_AURA_LICENSE_FREE;
        $available_features = secure_aura_get_license_features()[$license_type] ?? [];

        // Quantum Firewall
        if (
            !empty($available_features[SECURE_AURA_FEATURE_QUANTUM_FIREWALL]) &&
            $this->config['quantum_firewall_enabled'] &&
            class_exists('Secure_Aura_Quantum_Firewall')
        ) {

            $this->modules['quantum_firewall'] = new Secure_Aura_Quantum_Firewall($this->config);
            $this->loader->add_action('init', $this->modules['quantum_firewall'], 'init_firewall', SECURE_AURA_PRIORITY_HIGHEST);
        }

        // AI Threat Engine
        if (
            !empty($available_features[SECURE_AURA_FEATURE_AI_THREAT_ENGINE]) &&
            $this->config['ai_threat_detection_enabled'] &&
            class_exists('Secure_Aura_AI_Threat_Engine')
        ) {

            $this->modules['ai_threat_engine'] = new Secure_Aura_AI_Threat_Engine($this->config);
            $this->loader->add_action('init', $this->modules['ai_threat_engine'], 'init_ai_engine');
        }

        // Behavioral Monitor
        if (
            !empty($available_features[SECURE_AURA_FEATURE_BEHAVIORAL_MONITOR]) &&
            $this->config['behavioral_monitoring_enabled'] &&
            class_exists('Secure_Aura_Behavioral_Monitor')
        ) {

            $this->modules['behavioral_monitor'] = new Secure_Aura_Behavioral_Monitor($this->config);
            $this->loader->add_action('init', $this->modules['behavioral_monitor'], 'start_monitoring');
        }

        // Malware Scanner (always available)
        if ($this->config['real_time_scanning_enabled'] && class_exists('Secure_Aura_Malware_Scanner')) {
            $this->modules['malware_scanner'] = new Secure_Aura_Malware_Scanner($this->config);
            $this->loader->add_action('init', $this->modules['malware_scanner'], 'init_scanner');
        }

        // Threat Intelligence
        if (
            !empty($available_features[SECURE_AURA_FEATURE_THREAT_INTELLIGENCE]) &&
            class_exists('Secure_Aura_Threat_Intelligence')
        ) {

            $this->modules['threat_intelligence'] = new Secure_Aura_Threat_Intelligence($this->config);
            $this->loader->add_action('init', $this->modules['threat_intelligence'], 'init_threat_feeds');
        }

        // File Integrity Monitor
        if (
            $this->config['file_integrity_monitoring_enabled'] &&
            class_exists('Secure_Aura_File_Integrity')
        ) {

            $this->modules['file_integrity'] = new Secure_Aura_File_Integrity($this->config);
            $this->loader->add_action('init', $this->modules['file_integrity'], 'start_monitoring');
        }

        // Database Protection
        if (
            $this->config['database_protection'] &&
            class_exists('Secure_Aura_Database_Protection')
        ) {

            $this->modules['database_protection'] = new Secure_Aura_Database_Protection($this->config);
            $this->loader->add_action('init', $this->modules['database_protection'], 'init_protection', SECURE_AURA_PRIORITY_HIGH);
        }

        // Incident Response
        if (
            !empty($available_features[SECURE_AURA_FEATURE_INCIDENT_RESPONSE]) &&
            class_exists('Secure_Aura_Incident_Response')
        ) {

            $this->modules['incident_response'] = new Secure_Aura_Incident_Response($this->config);
            $this->loader->add_action('init', $this->modules['incident_response'], 'init_response_system');
        }

        // Compliance Manager
        if (
            !empty($available_features[SECURE_AURA_FEATURE_COMPLIANCE_MONITORING]) &&
            $this->config['compliance_monitoring'] &&
            class_exists('Secure_Aura_Compliance_Manager')
        ) {

            $this->modules['compliance_manager'] = new Secure_Aura_Compliance_Manager($this->config);
            $this->loader->add_action('init', $this->modules['compliance_manager'], 'init_compliance_monitoring');
        }

        // Performance Monitor
        if (
            $this->config['performance_monitoring'] &&
            class_exists('Secure_Aura_Performance_Monitor')
        ) {

            $this->modules['performance_monitor'] = new Secure_Aura_Performance_Monitor($this->config);
            $this->loader->add_action('init', $this->modules['performance_monitor'], 'start_monitoring');
        }
    }

    /**
     * Initialize API endpoints.
     *
     * @since    3.0.0
     * @access   private
     */
    private function init_api_endpoints()
    {
        if (class_exists('Secure_Aura_API_Manager')) {
            $api_manager = new Secure_Aura_API_Manager($this);
            $this->components['api_manager'] = $api_manager;

            $this->loader->add_action('rest_api_init', $api_manager, 'register_endpoints');
        }
    }

    /**
     * Schedule background tasks.
     *
     * @since    3.0.0
     * @access   private
     */
    private function schedule_background_tasks()
    {
        // Schedule threat intelligence updates
        if (!wp_next_scheduled(SECURE_AURA_CRON_THREAT_INTEL_UPDATE)) {
            wp_schedule_event(time(), 'hourly', SECURE_AURA_CRON_THREAT_INTEL_UPDATE);
        }

        // Schedule full system scans
        if ($this->config['scan_frequency'] !== 'manual' && !wp_next_scheduled(SECURE_AURA_CRON_FULL_SCAN)) {
            wp_schedule_event(time(), $this->config['scan_frequency'], SECURE_AURA_CRON_FULL_SCAN);
        }

        // Schedule log cleanup
        if (!wp_next_scheduled(SECURE_AURA_CRON_LOG_CLEANUP)) {
            wp_schedule_event(time(), 'daily', SECURE_AURA_CRON_LOG_CLEANUP);
        }

        // Schedule cache cleanup
        if (!wp_next_scheduled(SECURE_AURA_CRON_CACHE_CLEANUP)) {
            wp_schedule_event(time(), 'daily', SECURE_AURA_CRON_CACHE_CLEANUP);
        }

        // Schedule performance checks
        if ($this->config['performance_monitoring'] && !wp_next_scheduled(SECURE_AURA_CRON_PERFORMANCE_CHECK)) {
            wp_schedule_event(time(), 'hourly', SECURE_AURA_CRON_PERFORMANCE_CHECK);
        }

        // Schedule file integrity checks
        if ($this->config['file_integrity_monitoring_enabled'] && !wp_next_scheduled(SECURE_AURA_CRON_INTEGRITY_CHECK)) {
            wp_schedule_event(time(), 'twicedaily', SECURE_AURA_CRON_INTEGRITY_CHECK);
        }

        // Register cron hooks
        $this->loader->add_action(SECURE_AURA_CRON_THREAT_INTEL_UPDATE, $this, 'cron_update_threat_intelligence');
        $this->loader->add_action(SECURE_AURA_CRON_FULL_SCAN, $this, 'cron_run_full_scan');
        $this->loader->add_action(SECURE_AURA_CRON_LOG_CLEANUP, $this, 'cron_cleanup_logs');
        $this->loader->add_action(SECURE_AURA_CRON_CACHE_CLEANUP, $this, 'cron_cleanup_cache');
        $this->loader->add_action(SECURE_AURA_CRON_PERFORMANCE_CHECK, $this, 'cron_performance_check');
        $this->loader->add_action(SECURE_AURA_CRON_INTEGRITY_CHECK, $this, 'cron_integrity_check');
    }

    /**
     * Run the loader to execute all of the hooks with WordPress.
     *
     * @since    3.0.0
     */
    public function run()
    {
        $this->loader->run();

        // Validate that required classes are loaded
        if (!$this->loader->validate_required_classes()) {
            return false;
        }

        // Initialize emergency mode if needed
        if ($this->config['emergency_mode']) {
            $this->activate_emergency_mode();
        }

        // Log plugin initialization
        $this->log_event(SECURE_AURA_EVENT_CONFIGURATION_CHANGE, [
            'action' => 'plugin_initialized',
            'version' => $this->version,
            'security_level' => $this->config['security_level'],
            'modules_loaded' => array_keys($this->modules)
        ], SECURE_AURA_SEVERITY_INFO);

        return true;
    }

    /**
     * The name of the plugin used to uniquely identify it within the context of
     * WordPress and to define internationalization functionality.
     *
     * @since     3.0.0
     * @return    string    The name of the plugin.
     */
    public function get_plugin_name()
    {
        return $this->plugin_name;
    }

    /**
     * The reference to the class that orchestrates the hooks with the plugin.
     *
     * @since     3.0.0
     * @return    Secure_Aura_Loader    Orchestrates the hooks of the plugin.
     */
    public function get_loader()
    {
        return $this->loader;
    }

    /**
     * Retrieve the version number of the plugin.
     *
     * @since     3.0.0
     * @return    string    The version number of the plugin.
     */
    public function get_version()
    {
        return $this->version;
    }

    /**
     * Get plugin configuration.
     *
     * @since     3.0.0
     * @param     string    $key    Configuration key (optional).
     * @return    mixed     Configuration value or full config array.
     */
    public function get_config($key = null)
    {
        if ($key === null) {
            return $this->config;
        }

        return $this->config[$key] ?? null;
    }

    /**
     * Update plugin configuration.
     *
     * @since     3.0.0
     * @param     string|array    $key      Configuration key or array of key-value pairs.
     * @param     mixed           $value    Configuration value (if key is string).
     * @return    bool            True on success, false on failure.
     */
    public function set_config($key, $value = null)
    {
        if (is_array($key)) {
            // Update multiple config values
            $this->config = array_merge($this->config, $key);
        } else {
            // Update single config value
            $this->config[$key] = $value;
        }

        // Save to database
        $result = update_option('secure_aura_settings', $this->config);

        // Apply filters
        $this->config = apply_filters('secure_aura_config_updated', $this->config);

        return $result;
    }

    /**
     * Get a loaded security module.
     *
     * @since     3.0.0
     * @param     string    $module_name    The name of the module.
     * @return    object|null    The module instance or null if not found.
     */
    public function get_module($module_name)
    {
        return $this->modules[$module_name] ?? null;
    }

    /**
     * Get all loaded modules.
     *
     * @since     3.0.0
     * @return    array    Array of loaded modules.
     */
    public function get_modules()
    {
        return $this->modules;
    }

    /**
     * Get a plugin component.
     *
     * @since     3.0.0
     * @param     string    $component_name    The name of the component.
     * @return    object|null    The component instance or null if not found.
     */
    public function get_component($component_name)
    {
        return $this->components[$component_name] ?? null;
    }

    /**
     * Get database manager instance.
     *
     * @since     3.0.0
     * @return    Secure_Aura_Database_Manager|null    Database manager instance.
     */
    public function get_database_manager()
    {
        return $this->db_manager;
    }

    /**
     * Log a security event.
     *
     * @since     3.0.0
     * @param     string    $event_type    Type of event.
     * @param     array     $data          Event data.
     * @param     string    $severity      Event severity.
     * @return    bool      True on success, false on failure.
     */
    public function log_event($event_type, $data = [], $severity = SECURE_AURA_SEVERITY_MEDIUM)
    {
        if ($this->db_manager) {
            return $this->db_manager->log_event($event_type, $data, $severity);
        }

        return false;
    }

    /**
     * Activate emergency mode.
     *
     * @since     3.0.0
     * @return    bool    True on success, false on failure.
     */
    public function activate_emergency_mode()
    {
        // Update configuration
        $emergency_config = [
            'emergency_mode' => true,
            'security_level' => SECURE_AURA_LEVEL_FORTRESS,
            'quantum_firewall_enabled' => true,
            'auto_block_malicious_ips' => true,
            'ai_threat_threshold' => 0.5, // Lower threshold = more sensitive
            'behavioral_anomaly_threshold' => 0.6,
            'geo_blocking_enabled' => true,
            'tor_blocking_enabled' => true,
            'vpn_blocking_enabled' => true,
        ];

        $this->set_config($emergency_config);

        // Reinitialize security modules with new settings
        $this->reinitialize_modules();

        // Log emergency activation
        $this->log_event(SECURE_AURA_EVENT_EMERGENCY_MODE, [
            'action' => 'activated',
            'triggered_by' => get_current_user_id(),
            'ip_address' => $this->get_client_ip(),
            'timestamp' => current_time('mysql')
        ], SECURE_AURA_SEVERITY_CRITICAL);

        // Send notification
        $this->send_emergency_notification('Emergency mode activated');

        return true;
    }

    /**
     * Deactivate emergency mode.
     *
     * @since     3.0.0
     * @return    bool    True on success, false on failure.
     */
    public function deactivate_emergency_mode()
    {
        // Restore normal configuration
        $normal_config = [
            'emergency_mode' => false,
            'security_level' => SECURE_AURA_LEVEL_ENHANCED,
            'ai_threat_threshold' => 0.7,
            'behavioral_anomaly_threshold' => 0.8,
        ];

        $this->set_config($normal_config);

        // Reinitialize modules
        $this->reinitialize_modules();

        // Log emergency deactivation
        $this->log_event(SECURE_AURA_EVENT_EMERGENCY_MODE, [
            'action' => 'deactivated',
            'triggered_by' => get_current_user_id(),
            'ip_address' => $this->get_client_ip(),
            'timestamp' => current_time('mysql')
        ], SECURE_AURA_SEVERITY_HIGH);

        return true;
    }

    /**
     * Reinitialize security modules with updated configuration.
     *
     * @since     3.0.0
     * @access    private
     */
    private function reinitialize_modules()
    {
        foreach ($this->modules as $module_name => $module) {
            if (method_exists($module, 'update_config')) {
                $module->update_config($this->config);
            }

            if (method_exists($module, 'reinitialize')) {
                $module->reinitialize();
            }
        }
    }

    /**
     * Send emergency notification.
     *
     * @since     3.0.0
     * @param     string    $message    Notification message.
     * @access    private
     */
    private function send_emergency_notification($message)
    {
        if ($this->config['email_notifications']) {
            $notification_component = $this->get_component('notification');
            if ($notification_component && method_exists($notification_component, 'send_emergency_alert')) {
                $notification_component->send_emergency_alert($message);
            }
        }
    }

    /**
     * Get client IP address.
     *
     * @since     3.0.0
     * @return    string    Client IP address.
     */
    public function get_client_ip()
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
     * Cron job: Update threat intelligence.
     *
     * @since     3.0.0
     */
    public function cron_update_threat_intelligence()
    {
        $threat_intel = $this->get_module('threat_intelligence');
        if ($threat_intel && method_exists($threat_intel, 'update_feeds')) {
            $threat_intel->update_feeds();
        }
    }

    /**
     * Cron job: Run full system scan.
     *
     * @since     3.0.0
     */
    public function cron_run_full_scan()
    {
        $scanner = $this->get_module('malware_scanner');
        if ($scanner && method_exists($scanner, 'run_full_scan')) {
            $scanner->run_full_scan();
        }
    }

    /**
     * Cron job: Cleanup old logs.
     *
     * @since     3.0.0
     */
    public function cron_cleanup_logs()
    {
        if ($this->db_manager && method_exists($this->db_manager, 'cleanup_old_logs')) {
            $retention_days = $this->config['log_retention_days'] ?? 90;
            $this->db_manager->cleanup_old_logs($retention_days);
        }
    }

    /**
     * Cron job: Cleanup cache files.
     *
     * @since     3.0.0
     */
    public function cron_cleanup_cache()
    {
        $cache_manager = $this->get_component('cache_manager');
        if ($cache_manager && method_exists($cache_manager, 'cleanup_expired_cache')) {
            $cache_manager->cleanup_expired_cache();
        }
    }

    /**
     * Cron job: Performance check.
     *
     * @since     3.0.0
     */
    public function cron_performance_check()
    {
        $performance_monitor = $this->get_module('performance_monitor');
        if ($performance_monitor && method_exists($performance_monitor, 'run_performance_check')) {
            $performance_monitor->run_performance_check();
        }
    }

    /**
     * Cron job: File integrity check.
     *
     * @since     3.0.0
     */
    public function cron_integrity_check()
    {
        $file_integrity = $this->get_module('file_integrity');
        if ($file_integrity && method_exists($file_integrity, 'run_integrity_check')) {
            $file_integrity->run_integrity_check();
        }
    }

    /**
     * Get plugin status information.
     *
     * @since     3.0.0
     * @return    array    Plugin status information.
     */
    public function get_plugin_status()
    {
        return [
            'version' => $this->version,
            'security_level' => $this->config['security_level'],
            'emergency_mode' => $this->config['emergency_mode'],
            'modules_loaded' => count($this->modules),
            'components_loaded' => count($this->components),
            'license_type' => $this->config['license_type'],
            'last_scan' => get_option('secure_aura_last_scan', 'Never'),
            'threat_intel_updated' => get_option('secure_aura_threat_intel_updated', 'Never'),
            'database_version' => get_option('secure_aura_db_version', '0'),
        ];
    }

    /**
     * Check if a feature is available based on current license.
     *
     * @since     3.0.0
     * @param     string    $feature    Feature name.
     * @return    bool      True if feature is available, false otherwise.
     */
    public function is_feature_available($feature)
    {
        $license_type = $this->config['license_type'] ?? SECURE_AURA_LICENSE_FREE;
        $features = secure_aura_get_license_features()[$license_type] ?? [];

        return !empty($features[$feature]);
    }

    /**
     * Cleanup method called on plugin deactivation.
     *
     * @since     3.0.0
     */
    public function cleanup()
    {
        // Clear scheduled cron jobs
        wp_clear_scheduled_hook(SECURE_AURA_CRON_THREAT_INTEL_UPDATE);
        wp_clear_scheduled_hook(SECURE_AURA_CRON_FULL_SCAN);
        wp_clear_scheduled_hook(SECURE_AURA_CRON_LOG_CLEANUP);
        wp_clear_scheduled_hook(SECURE_AURA_CRON_CACHE_CLEANUP);
        wp_clear_scheduled_hook(SECURE_AURA_CRON_PERFORMANCE_CHECK);
        wp_clear_scheduled_hook(SECURE_AURA_CRON_INTEGRITY_CHECK);

        // Cleanup modules
        foreach ($this->modules as $module) {
            if (method_exists($module, 'cleanup')) {
                $module->cleanup();
            }
        }

        // Cleanup components
        foreach ($this->components as $component) {
            if (method_exists($component, 'cleanup')) {
                $component->cleanup();
            }
        }

        // Cleanup loader
        if ($this->loader && method_exists($this->loader, 'cleanup')) {
            $this->loader->cleanup();
        }
    }
}
