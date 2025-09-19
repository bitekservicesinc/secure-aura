<?php
/**
 * SecureAura - Advanced WordPress Security Suite
 *
 * @package           SecureAura
 * @author            Bitekservices
 * @copyright         2024 SecureAura
 * @license           GPL-2.0-or-later
 *
 * @wordpress-plugin
 * Plugin Name:       SecureAura - Advanced Security Suite
 * Plugin URI:        https://secureaura.pro
 * Description:       Revolutionary WordPress security with AI-powered threat detection, quantum firewall, and military-grade protection that surpasses traditional security plugins.
 * Version:           3.0.0
 * Requires at least: 5.8
 * Requires PHP:      8.0
 * Author:            Bitekservices
 * Author URI:        https://secureaura.pro
 * Text Domain:       secure-aura
 * Domain Path:       /languages
 * License:           GPL v2 or later
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Network:           true
 * Update URI:        https://api.secureaura.pro/updates
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied. SecureAura protection activated.');
}

/**
 * Currently plugin version.
 * Start at version 3.0.0 and use SemVer - https://semver.org
 * Rename this for your plugin and update it as you release new versions.
 */
define('SECURE_AURA_VERSION', '3.0.0');

/**
 * Plugin core constants
 */
define('SECURE_AURA_PLUGIN_FILE', __FILE__);
define('SECURE_AURA_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('SECURE_AURA_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('SECURE_AURA_PLUGIN_URL', plugin_dir_url(__FILE__));
define('SECURE_AURA_INCLUDES_DIR', SECURE_AURA_PLUGIN_DIR . 'includes/');
define('SECURE_AURA_MODULES_DIR', SECURE_AURA_PLUGIN_DIR . 'modules/');
define('SECURE_AURA_ADMIN_DIR', SECURE_AURA_PLUGIN_DIR . 'admin/');
define('SECURE_AURA_PUBLIC_DIR', SECURE_AURA_PLUGIN_DIR . 'public/');
define('SECURE_AURA_ASSETS_URL', SECURE_AURA_PLUGIN_URL . 'assets/');

/**
 * The code that runs during plugin activation.
 * This action is documented in includes/class-activator.php
 */
function activate_secure_aura() {
    require_once SECURE_AURA_INCLUDES_DIR . 'class-activator.php';
    Secure_Aura_Activator::activate();
}

/**
 * The code that runs during plugin deactivation.
 * This action is documented in includes/class-deactivator.php
 */
function deactivate_secure_aura() {
    require_once SECURE_AURA_INCLUDES_DIR . 'class-deactivator.php';
    Secure_Aura_Deactivator::deactivate();
}

// Register activation and deactivation hooks
register_activation_hook(__FILE__, 'activate_secure_aura');
register_deactivation_hook(__FILE__, 'deactivate_secure_aura');

/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since    3.0.0
 */
function run_secure_aura() {
    
    // Load plugin constants
    require_once SECURE_AURA_INCLUDES_DIR . 'constants.php';
    
    // Load the plugin loader
    require_once SECURE_AURA_INCLUDES_DIR . 'class-loader.php';
    
    // Load the main plugin class
    require_once SECURE_AURA_INCLUDES_DIR . 'class-secure-aura.php';
    
    // Initialize the plugin
    $plugin = new Secure_Aura();
    $plugin->run();
}

/**
 * Check if the current PHP version meets the minimum requirement
 */
function secure_aura_check_php_version() {
    if (version_compare(PHP_VERSION, '8.0', '<')) {
        add_action('admin_notices', function() {
            echo '<div class="notice notice-error"><p>';
            echo sprintf(
                esc_html__('SecureAura requires PHP version 8.0 or higher. You are running version %s. Please upgrade PHP to activate SecureAura.', 'secure-aura'),
                PHP_VERSION
            );
            echo '</p></div>';
        });
        return false;
    }
    return true;
}

/**
 * Check if WordPress version meets the minimum requirement
 */
function secure_aura_check_wp_version() {
    global $wp_version;
    if (version_compare($wp_version, '5.8', '<')) {
        add_action('admin_notices', function() {
            global $wp_version;
            echo '<div class="notice notice-error"><p>';
            echo sprintf(
                esc_html__('SecureAura requires WordPress version 5.8 or higher. You are running version %s. Please upgrade WordPress to activate SecureAura.', 'secure-aura'),
                $wp_version
            );
            echo '</p></div>';
        });
        return false;
    }
    return true;
}

/**
 * Check for required PHP extensions
 */
function secure_aura_check_requirements() {
    $required_extensions = [
        'openssl',
        'curl',
        'json',
        'mbstring',
        'hash'
    ];
    
    $missing_extensions = [];
    foreach ($required_extensions as $extension) {
        if (!extension_loaded($extension)) {
            $missing_extensions[] = $extension;
        }
    }
    
    if (!empty($missing_extensions)) {
        add_action('admin_notices', function() use ($missing_extensions) {
            echo '<div class="notice notice-error"><p>';
            echo sprintf(
                esc_html__('SecureAura requires the following PHP extensions: %s. Please install these extensions to activate SecureAura.', 'secure-aura'),
                implode(', ', $missing_extensions)
            );
            echo '</p></div>';
        });
        return false;
    }
    
    return true;
}

/**
 * Initialize the plugin only if all requirements are met
 */
function secure_aura_init() {
    // Check system requirements
    if (!secure_aura_check_php_version() || 
        !secure_aura_check_wp_version() || 
        !secure_aura_check_requirements()) {
        return;
    }
    
    // All requirements met, initialize the plugin
    run_secure_aura();
}

// Hook into WordPress init
add_action('plugins_loaded', 'secure_aura_init');

/**
 * Add plugin action links
 */
function secure_aura_add_action_links($links) {
    $settings_link = '<a href="' . admin_url('admin.php?page=secure-aura') . '">' . esc_html__('Dashboard', 'secure-aura') . '</a>';
    $settings_link .= ' | <a href="' . admin_url('admin.php?page=secure-aura-settings') . '">' . esc_html__('Settings', 'secure-aura') . '</a>';
    $pro_link = '<a href="https://secureaura.pro/upgrade" target="_blank" style="color: #ff6600; font-weight: bold;">' . esc_html__('Upgrade to Pro', 'secure-aura') . '</a>';
    
    array_unshift($links, $settings_link);
    array_push($links, $pro_link);
    
    return $links;
}
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'secure_aura_add_action_links');

/**
 * Add plugin meta links
 */
function secure_aura_add_meta_links($links, $file) {
    if ($file === plugin_basename(__FILE__)) {
        $links[] = '<a href="https://secureaura.pro/docs" target="_blank">' . esc_html__('Documentation', 'secure-aura') . '</a>';
        $links[] = '<a href="https://secureaura.pro/support" target="_blank">' . esc_html__('Support', 'secure-aura') . '</a>';
        $links[] = '<a href="https://secureaura.pro/changelog" target="_blank">' . esc_html__('Changelog', 'secure-aura') . '</a>';
    }
    return $links;
}
add_filter('plugin_row_meta', 'secure_aura_add_meta_links', 10, 2);

/**
 * Load plugin textdomain for internationalization
 */
function secure_aura_load_textdomain() {
    load_plugin_textdomain(
        'secure-aura',
        false,
        dirname(plugin_basename(__FILE__)) . '/languages/'
    );
}
add_action('init', 'secure_aura_load_textdomain');

/**
 * Register security headers early
 */
function secure_aura_early_security_headers() {
    // Only apply to admin or if the plugin is configured to protect frontend
    if (is_admin() || get_option('secure_aura_protect_frontend', true)) {
        // Security headers for enhanced protection
        if (!headers_sent()) {
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: SAMEORIGIN');
            header('X-XSS-Protection: 1; mode=block');
            header('Referrer-Policy: strict-origin-when-cross-origin');
            
            // HSTS header for HTTPS sites
            if (is_ssl()) {
                header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
            }
        }
    }
}
add_action('init', 'secure_aura_early_security_headers', 1);

/**
 * Emergency shutdown functionality
 * This can be triggered via direct file access in emergency situations
 */
if (defined('SECURE_AURA_EMERGENCY_SHUTDOWN') && SECURE_AURA_EMERGENCY_SHUTDOWN === true) {
    function secure_aura_emergency_shutdown() {
        wp_die(
            esc_html__('Site temporarily unavailable for security maintenance. Please try again later.', 'secure-aura'),
            esc_html__('Security Maintenance', 'secure-aura'),
            ['response' => 503]
        );
    }
    add_action('init', 'secure_aura_emergency_shutdown', 0);
}

/**
 * Plugin update checker (for Pro version)
 */
if (!function_exists('secure_aura_check_for_updates')) {
    function secure_aura_check_for_updates() {
        // This will be implemented for Pro version with licensing
        if (get_option('secure_aura_pro_license_key')) {
            // Check for updates from our server
            // Implementation will be added for Pro version
        }
    }
    add_action('admin_init', 'secure_aura_check_for_updates');
}

/**
 * Log critical errors during plugin initialization
 */
function secure_aura_log_critical_error($error) {
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('SecureAura Critical Error: ' . $error);
    }
    
    // Store in database for admin notification
    $errors = get_option('secure_aura_critical_errors', []);
    $errors[] = [
        'error' => $error,
        'timestamp' => current_time('mysql'),
        'php_version' => PHP_VERSION,
        'wp_version' => get_bloginfo('version')
    ];
    
    // Keep only last 10 errors
    $errors = array_slice($errors, -10);
    update_option('secure_aura_critical_errors', $errors);
}

/**
 * Handle fatal errors gracefully
 */
function secure_aura_fatal_error_handler() {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR])) {
        secure_aura_log_critical_error($error['message'] . ' in ' . $error['file'] . ' on line ' . $error['line']);
    }
}
register_shutdown_function('secure_aura_fatal_error_handler');

/**
 * That's all folks! The rest of the plugin functionality is loaded
 * through the class-loader.php and class-secure-aura.php files.
 * 
 * This main file is kept clean and minimal for better maintainability.
 */