<?php
/**
 * SecureAura Loader
 *
 * Responsible for loading all plugin classes and managing dependencies
 *
 * @package    SecureAura
 * @subpackage SecureAura/includes
 * @since      3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * SecureAura Loader Class
 *
 * This class manages the loading of all plugin components including:
 * - Core classes
 * - Security modules
 * - Admin interface
 * - Public interface
 * - API endpoints
 * - Database operations
 *
 * @since      3.0.0
 * @package    SecureAura
 * @subpackage SecureAura/includes
 * @author     Bitekservices
 */
class Secure_Aura_Loader {

    /**
     * The array of actions registered with WordPress.
     *
     * @since    3.0.0
     * @access   protected
     * @var      array    $actions    The actions registered with WordPress to fire when the plugin loads.
     */
    protected $actions;

    /**
     * The array of filters registered with WordPress.
     *
     * @since    3.0.0
     * @access   protected
     * @var      array    $filters    The filters registered with WordPress to fire when the plugin loads.
     */
    protected $filters;

    /**
     * The array of shortcodes registered with WordPress.
     *
     * @since    3.0.0
     * @access   protected
     * @var      array    $shortcodes    The shortcodes registered with WordPress.
     */
    protected $shortcodes;

    /**
     * The array of loaded classes.
     *
     * @since    3.0.0
     * @access   protected
     * @var      array    $loaded_classes    Classes that have been loaded.
     */
    protected $loaded_classes;

    /**
     * Initialize the collections used to maintain the actions, filters, and shortcodes.
     *
     * @since    3.0.0
     */
    public function __construct() {
        $this->actions = [];
        $this->filters = [];
        $this->shortcodes = [];
        $this->loaded_classes = [];
    }

    /**
     * Add a new action to the collection to be registered with WordPress.
     *
     * @since    3.0.0
     * @param    string               $hook             The name of the WordPress action that is being registered.
     * @param    object               $component        A reference to the instance of the object on which the action is defined.
     * @param    string               $callback         The name of the function definition on the $component.
     * @param    int                  $priority         Optional. The priority at which the function should be fired. Default is 10.
     * @param    int                  $accepted_args    Optional. The number of arguments that should be passed to the $callback. Default is 1.
     */
    public function add_action($hook, $component, $callback, $priority = 10, $accepted_args = 1) {
        $this->actions = $this->add($this->actions, $hook, $component, $callback, $priority, $accepted_args);
    }

    /**
     * Add a new filter to the collection to be registered with WordPress.
     *
     * @since    3.0.0
     * @param    string               $hook             The name of the WordPress filter that is being registered.
     * @param    object               $component        A reference to the instance of the object on which the filter is defined.
     * @param    string               $callback         The name of the function definition on the $component.
     * @param    int                  $priority         Optional. The priority at which the function should be fired. Default is 10.
     * @param    int                  $accepted_args    Optional. The number of arguments that should be passed to the $callback. Default is 1.
     */
    public function add_filter($hook, $component, $callback, $priority = 10, $accepted_args = 1) {
        $this->filters = $this->add($this->filters, $hook, $component, $callback, $priority, $accepted_args);
    }

    /**
     * Add a new shortcode to the collection to be registered with WordPress.
     *
     * @since    3.0.0
     * @param    string               $tag              The name of the new shortcode.
     * @param    object               $component        A reference to the instance of the object on which the shortcode is defined.
     * @param    string               $callback         The name of the function definition on the $component.
     */
    public function add_shortcode($tag, $component, $callback) {
        $this->shortcodes = $this->add($this->shortcodes, $tag, $component, $callback);
    }

    /**
     * A utility function that is used to register the actions, filters, and shortcodes into a single collection.
     *
     * @since    3.0.0
     * @access   private
     * @param    array                $hooks            The collection of hooks that is being registered (that is, actions, filters, or shortcodes).
     * @param    string               $hook             The name of the WordPress filter that is being registered.
     * @param    object               $component        A reference to the instance of the object on which the filter is defined.
     * @param    string               $callback         The name of the function definition on the $component.
     * @param    int                  $priority         The priority at which the function should be fired.
     * @param    int                  $accepted_args    The number of arguments that should be passed to the $callback.
     * @return   array                                  The collection of actions, filters, and shortcodes registered with WordPress.
     */
    private function add($hooks, $hook, $component, $callback, $priority = 10, $accepted_args = 1) {
        $hooks[] = [
            'hook'          => $hook,
            'component'     => $component,
            'callback'      => $callback,
            'priority'      => $priority,
            'accepted_args' => $accepted_args
        ];

        return $hooks;
    }

    /**
     * Register the filters, actions, and shortcodes with WordPress.
     *
     * @since    3.0.0
     */
    public function run() {
        foreach ($this->filters as $hook) {
            add_filter($hook['hook'], [$hook['component'], $hook['callback']], $hook['priority'], $hook['accepted_args']);
        }

        foreach ($this->actions as $hook) {
            add_action($hook['hook'], [$hook['component'], $hook['callback']], $hook['priority'], $hook['accepted_args']);
        }

        foreach ($this->shortcodes as $hook) {
            add_shortcode($hook['hook'], [$hook['component'], $hook['callback']]);
        }
    }

    /**
     * Load a class file if it exists and hasn't been loaded yet.
     *
     * @since    3.0.0
     * @param    string $class_name The name of the class to load.
     * @param    string $file_path The path to the class file.
     * @return   bool True if the class was loaded successfully, false otherwise.
     */
    public function load_class($class_name, $file_path) {
        // Check if class is already loaded
        if (isset($this->loaded_classes[$class_name])) {
            return true;
        }

        // Check if file exists
        if (!file_exists($file_path)) {
            error_log("SecureAura: Class file not found: {$file_path}");
            return false;
        }

        // Include the file
        require_once $file_path;

        // Check if class exists after inclusion
        if (!class_exists($class_name)) {
            error_log("SecureAura: Class not found after inclusion: {$class_name}");
            return false;
        }

        // Mark class as loaded
        $this->loaded_classes[$class_name] = $file_path;
        
        return true;
    }

    /**
     * Load all core classes required for the plugin.
     *
     * @since    3.0.0
     */
    public function load_core_classes() {
        $core_classes = [
            // Activation/Deactivation
            'Secure_Aura_Activator'   => SECURE_AURA_INCLUDES_DIR . 'class-activator.php',
            'Secure_Aura_Deactivator' => SECURE_AURA_INCLUDES_DIR . 'class-deactivator.php',
            
            // Utility Functions
            'Secure_Aura_Functions'   => SECURE_AURA_INCLUDES_DIR . 'functions.php',
            
            // Database Management
            'Secure_Aura_Database_Manager' => SECURE_AURA_PLUGIN_DIR . 'database/class-database-manager.php',
            'Secure_Aura_Schema'           => SECURE_AURA_PLUGIN_DIR . 'database/class-schema.php',
        ];

        foreach ($core_classes as $class_name => $file_path) {
            $this->load_class($class_name, $file_path);
        }
    }

    /**
     * Load all security modules.
     *
     * @since    3.0.0
     */
    public function load_security_modules() {
        $security_modules = [
            'Secure_Aura_Quantum_Firewall'    => SECURE_AURA_MODULES_DIR . 'class-quantum-firewall.php',
            'Secure_Aura_AI_Threat_Engine'    => SECURE_AURA_MODULES_DIR . 'class-ai-threat-engine.php',
            'Secure_Aura_Behavioral_Monitor'  => SECURE_AURA_MODULES_DIR . 'class-behavioral-monitor.php',
            'Secure_Aura_Malware_Scanner'     => SECURE_AURA_MODULES_DIR . 'class-malware-scanner.php',
            'Secure_Aura_Threat_Intelligence' => SECURE_AURA_MODULES_DIR . 'class-threat-intelligence.php',
            'Secure_Aura_Database_Protection' => SECURE_AURA_MODULES_DIR . 'class-database-protection.php',
            'Secure_Aura_File_Integrity'      => SECURE_AURA_MODULES_DIR . 'class-file-integrity.php',
            'Secure_Aura_Incident_Response'   => SECURE_AURA_MODULES_DIR . 'class-incident-response.php',
            'Secure_Aura_Compliance_Manager'  => SECURE_AURA_MODULES_DIR . 'class-compliance-manager.php',
            'Secure_Aura_Performance_Monitor' => SECURE_AURA_MODULES_DIR . 'class-performance-monitor.php',
        ];

        foreach ($security_modules as $class_name => $file_path) {
            $this->load_class($class_name, $file_path);
        }
    }

    /**
     * Load admin-related classes.
     *
     * @since    3.0.0
     */
    public function load_admin_classes() {
        if (!is_admin()) {
            return;
        }

        $admin_classes = [
            'Secure_Aura_Admin'        => SECURE_AURA_ADMIN_DIR . 'class-admin.php',
            'Secure_Aura_Dashboard'    => SECURE_AURA_ADMIN_DIR . 'class-dashboard.php',
            'Secure_Aura_Settings'     => SECURE_AURA_ADMIN_DIR . 'class-settings.php',
            'Secure_Aura_Ajax_Handler' => SECURE_AURA_ADMIN_DIR . 'class-ajax-handler.php',
        ];

        foreach ($admin_classes as $class_name => $file_path) {
            $this->load_class($class_name, $file_path);
        }
    }

    /**
     * Load public-facing classes.
     *
     * @since    3.0.0
     */
    public function load_public_classes() {
        $public_classes = [
            'Secure_Aura_Public'              => SECURE_AURA_PUBLIC_DIR . 'class-public.php',
            'Secure_Aura_Frontend_Protection' => SECURE_AURA_PUBLIC_DIR . 'class-frontend-protection.php',
            'Secure_Aura_Captcha_Handler'     => SECURE_AURA_PUBLIC_DIR . 'class-captcha-handler.php',
        ];

        foreach ($public_classes as $class_name => $file_path) {
            $this->load_class($class_name, $file_path);
        }
    }

    /**
     * Load API classes.
     *
     * @since    3.0.0
     */
    public function load_api_classes() {
        $api_classes = [
            'Secure_Aura_API_Manager'     => SECURE_AURA_PLUGIN_DIR . 'api/class-api-manager.php',
            'Secure_Aura_Threat_API'      => SECURE_AURA_PLUGIN_DIR . 'api/class-threat-api.php',
            'Secure_Aura_Scan_API'        => SECURE_AURA_PLUGIN_DIR . 'api/class-scan-api.php',
            'Secure_Aura_Monitoring_API'  => SECURE_AURA_PLUGIN_DIR . 'api/class-monitoring-api.php',
        ];

        foreach ($api_classes as $class_name => $file_path) {
            $this->load_class($class_name, $file_path);
        }
    }

    /**
     * Load classes conditionally based on the current context.
     *
     * @since    3.0.0
     */
    public function load_conditional_classes() {
        // Load AJAX classes if this is an AJAX request
        if (wp_doing_ajax()) {
            $this->load_class('Secure_Aura_Ajax_Handler', SECURE_AURA_ADMIN_DIR . 'class-ajax-handler.php');
        }

        // Load REST API classes if this is a REST request
        if (defined('REST_REQUEST') && REST_REQUEST) {
            $this->load_api_classes();
        }

        // Load cron classes if this is a cron request
        if (wp_doing_cron()) {
            $this->load_class('Secure_Aura_Cron_Manager', SECURE_AURA_INCLUDES_DIR . 'class-cron-manager.php');
        }

        // Load CLI classes if this is a WP-CLI request
        if (defined('WP_CLI') && WP_CLI) {
            $this->load_class('Secure_Aura_CLI', SECURE_AURA_INCLUDES_DIR . 'class-cli.php');
        }
    }

    /**
     * Autoload classes using PSR-4 standard.
     *
     * @since    3.0.0
     * @param    string $class_name The name of the class to load.
     */
    public function autoload($class_name) {
        // Only handle SecureAura classes
        if (strpos($class_name, 'Secure_Aura_') !== 0) {
            return;
        }

        // Convert class name to file path
        $file_path = $this->class_name_to_file_path($class_name);
        
        if ($file_path && file_exists($file_path)) {
            require_once $file_path;
        }
    }

    /**
     * Convert class name to file path following our naming convention.
     *
     * @since    3.0.0
     * @param    string $class_name The class name to convert.
     * @return   string|false The file path or false if not found.
     */
    private function class_name_to_file_path($class_name) {
        // Remove Secure_Aura_ prefix
        $class_name = str_replace('Secure_Aura_', '', $class_name);
        
        // Convert to lowercase and replace underscores with hyphens
        $file_name = 'class-' . strtolower(str_replace('_', '-', $class_name)) . '.php';
        
        // Define search paths based on class type
        $search_paths = [
            SECURE_AURA_INCLUDES_DIR,
            SECURE_AURA_MODULES_DIR,
            SECURE_AURA_ADMIN_DIR,
            SECURE_AURA_PUBLIC_DIR,
            SECURE_AURA_PLUGIN_DIR . 'api/',
            SECURE_AURA_PLUGIN_DIR . 'database/',
        ];
        
        // Search for the file in each path
        foreach ($search_paths as $path) {
            $full_path = $path . $file_name;
            if (file_exists($full_path)) {
                return $full_path;
            }
        }
        
        return false;
    }

    /**
     * Get loaded classes for debugging purposes.
     *
     * @since    3.0.0
     * @return   array List of loaded classes.
     */
    public function get_loaded_classes() {
        return $this->loaded_classes;
    }

    /**
     * Check if a specific class has been loaded.
     *
     * @since    3.0.0
     * @param    string $class_name The name of the class to check.
     * @return   bool True if loaded, false otherwise.
     */
    public function is_class_loaded($class_name) {
        return isset($this->loaded_classes[$class_name]);
    }

    /**
     * Load third-party dependencies using Composer autoloader.
     *
     * @since    3.0.0
     */
    public function load_dependencies() {
        $composer_autoload = SECURE_AURA_PLUGIN_DIR . 'vendor/autoload.php';
        
        if (file_exists($composer_autoload)) {
            require_once $composer_autoload;
        }
    }

    /**
     * Initialize hooks and filters for the loader itself.
     *
     * @since    3.0.0
     */
    public function init_loader_hooks() {
        // Register our autoloader
        spl_autoload_register([$this, 'autoload']);
        
        // Hook into WordPress to load classes at appropriate times
        add_action('init', [$this, 'late_load_classes'], 0);
        add_action('admin_init', [$this, 'load_admin_classes'], 0);
        add_action('rest_api_init', [$this, 'load_api_classes'], 0);
    }

    /**
     * Load classes that should be loaded later in the WordPress lifecycle.
     *
     * @since    3.0.0
     */
    public function late_load_classes() {
        // Load classes that depend on WordPress being fully initialized
        $late_classes = [
            'Secure_Aura_Cron_Manager'     => SECURE_AURA_INCLUDES_DIR . 'class-cron-manager.php',
            'Secure_Aura_Notification'     => SECURE_AURA_INCLUDES_DIR . 'class-notification.php',
            'Secure_Aura_Cache_Manager'    => SECURE_AURA_INCLUDES_DIR . 'class-cache-manager.php',
        ];

        foreach ($late_classes as $class_name => $file_path) {
            $this->load_class($class_name, $file_path);
        }
    }

    /**
     * Load security modules based on current license and configuration.
     *
     * @since    3.0.0
     */
    public function load_license_based_modules() {
        $license_type = get_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE);
        $features = secure_aura_get_license_features()[$license_type] ?? [];
        
        // Only load modules that are available for current license
        $feature_modules = [
            SECURE_AURA_FEATURE_QUANTUM_FIREWALL    => 'Secure_Aura_Quantum_Firewall',
            SECURE_AURA_FEATURE_AI_THREAT_ENGINE    => 'Secure_Aura_AI_Threat_Engine',
            SECURE_AURA_FEATURE_BEHAVIORAL_MONITOR  => 'Secure_Aura_Behavioral_Monitor',
            SECURE_AURA_FEATURE_THREAT_INTELLIGENCE => 'Secure_Aura_Threat_Intelligence',
            SECURE_AURA_FEATURE_ZERO_DAY_PROTECTION => 'Secure_Aura_Zero_Day_Protection',
            SECURE_AURA_FEATURE_INCIDENT_RESPONSE   => 'Secure_Aura_Incident_Response',
            SECURE_AURA_FEATURE_COMPLIANCE_MONITORING => 'Secure_Aura_Compliance_Manager',
        ];
        
        foreach ($feature_modules as $feature => $class_name) {
            if (!empty($features[$feature])) {
                $file_path = SECURE_AURA_MODULES_DIR . 'class-' . strtolower(str_replace('_', '-', str_replace('Secure_Aura_', '', $class_name))) . '.php';
                $this->load_class($class_name, $file_path);
            }
        }
    }

    /**
     * Handle loading errors gracefully.
     *
     * @since    3.0.0
     * @param    string $class_name The class that failed to load.
     * @param    string $error_message The error message.
     */
    public function handle_loading_error($class_name, $error_message) {
        // Log the error
        if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            error_log("SecureAura Loading Error [{$class_name}]: {$error_message}");
        }
        
        // Store error for admin notification
        $loading_errors = get_option('secure_aura_loading_errors', []);
        $loading_errors[] = [
            'class' => $class_name,
            'error' => $error_message,
            'timestamp' => current_time('mysql'),
        ];
        
        // Keep only last 10 errors
        $loading_errors = array_slice($loading_errors, -10);
        update_option('secure_aura_loading_errors', $loading_errors);
        
        // Show admin notice if in admin area
        if (is_admin()) {
            add_action('admin_notices', function() use ($class_name, $error_message) {
                if (current_user_can('manage_options')) {
                    echo '<div class="notice notice-error"><p>';
                    echo sprintf(
                        esc_html__('SecureAura: Failed to load %s - %s', 'secure-aura'),
                        esc_html($class_name),
                        esc_html($error_message)
                    );
                    echo '</p></div>';
                }
            });
        }
    }

    /**
     * Validate that all required classes are loaded.
     *
     * @since    3.0.0
     * @return   bool True if all required classes are loaded, false otherwise.
     */
    public function validate_required_classes() {
        $required_classes = [
            'Secure_Aura',
            'Secure_Aura_Database_Manager',
            'Secure_Aura_Malware_Scanner',
        ];
        
        $missing_classes = [];
        
        foreach ($required_classes as $class_name) {
            if (!class_exists($class_name)) {
                $missing_classes[] = $class_name;
            }
        }
        
        if (!empty($missing_classes)) {
            $this->handle_loading_error(
                'Required Classes',
                'Missing required classes: ' . implode(', ', $missing_classes)
            );
            return false;
        }
        
        return true;
    }

    /**
     * Cleanup method to remove autoloader and clear memory.
     *
     * @since    3.0.0
     */
    public function cleanup() {
        // Remove our autoloader
        spl_autoload_unregister([$this, 'autoload']);
        
        // Clear loaded classes array
        $this->loaded_classes = [];
        
        // Clear hooks arrays
        $this->actions = [];
        $this->filters = [];
        $this->shortcodes = [];
    }

    /**
     * Get performance metrics for the loader.
     *
     * @since    3.0.0
     * @return   array Performance metrics.
     */
    public function get_performance_metrics() {
        return [
            'classes_loaded' => count($this->loaded_classes),
            'actions_registered' => count($this->actions),
            'filters_registered' => count($this->filters),
            'shortcodes_registered' => count($this->shortcodes),
            'memory_usage' => memory_get_usage(true),
            'peak_memory' => memory_get_peak_usage(true),
        ];
    }

    /**
     * Debug method to output loader information.
     *
     * @since    3.0.0
     */
    public function debug_info() {
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return;
        }
        
        $metrics = $this->get_performance_metrics();
        
        error_log('SecureAura Loader Debug Info:');
        error_log('Classes Loaded: ' . $metrics['classes_loaded']);
        error_log('Actions Registered: ' . $metrics['actions_registered']);
        error_log('Filters Registered: ' . $metrics['filters_registered']);
        error_log('Memory Usage: ' . size_format($metrics['memory_usage']));
        error_log('Peak Memory: ' . size_format($metrics['peak_memory']));
        
        if (!empty($this->loaded_classes)) {
            error_log('Loaded Classes: ' . implode(', ', array_keys($this->loaded_classes)));
        }
    }
}