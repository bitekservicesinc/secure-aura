<?php
/**
 * BiTek AI Security Guard Uninstall Script
 * 
 * This file runs when the plugin is deleted from WordPress.
 * It cleans up all plugin data including options, logs, and files.
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Additional security check
if (!current_user_can('activate_plugins')) {
    exit;
}

/**
 * Clean up all plugin data
 */
function bitek_ai_security_clean_uninstall() {
    // Remove plugin options
    delete_option('bitek_ai_security_options');
    
    // Remove any transients
    delete_transient('bitek_ai_security_api_test');
    
    // Get plugin directory
    $plugin_dir = plugin_dir_path(__FILE__);
    $log_dir = $plugin_dir . 'logs';
    
    // Remove all log files
    if (file_exists($log_dir) && is_dir($log_dir)) {
        $log_files = glob($log_dir . '/*');
        
        if ($log_files) {
            foreach ($log_files as $file) {
                if (is_file($file)) {
                    unlink($file);
                }
            }
        }
        
        // Remove .htaccess protection file
        $htaccess_file = $log_dir . '/.htaccess';
        if (file_exists($htaccess_file)) {
            unlink($htaccess_file);
        }
        
        // Remove logs directory
        @rmdir($log_dir);
    }
    
    // Clear any scheduled events (if we had any)
    wp_clear_scheduled_hook('bitek_ai_security_cleanup');
    
    // Remove user meta related to this plugin (if any)
    delete_metadata('user', 0, 'bitek_ai_security_dismissed_notices', '', true);
    
    // Log the uninstallation (final log entry)
    error_log('BiTek AI Security Guard: Plugin uninstalled and all data removed');
}

// Execute cleanup
bitek_ai_security_clean_uninstall();

// Final security check - ensure we're in the right context
if (defined('ABSPATH') && defined('WP_UNINSTALL_PLUGIN')) {
    // All cleanup completed successfully
    exit;
}