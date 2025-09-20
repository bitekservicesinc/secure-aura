<?php
/**
 * SecureAura Utility Functions
 *
 * Global utility functions used throughout the plugin
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
 * Check if SecureAura is properly loaded
 *
 * @since    3.0.0
 * @return   bool True if SecureAura is loaded
 */
function secure_aura_is_loaded() {
    return class_exists('Secure_Aura') && function_exists('secure_aura_get_instance');
}

/**
 * Get SecureAura plugin instance
 *
 * @since    3.0.0
 * @return   object|null SecureAura instance or null
 */
function secure_aura_get_instance() {
    global $secure_aura_instance;
    return $secure_aura_instance ?? null;
}

/**
 * Get client IP address with proxy detection
 *
 * @since    3.0.0
 * @return   string Client IP address
 */
function secure_aura_get_client_ip() {
    $ip_headers = [
        'HTTP_CF_CONNECTING_IP',     // Cloudflare
        'HTTP_X_FORWARDED_FOR',      // Load balancers/proxies
        'HTTP_X_FORWARDED',          // Proxies
        'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster environments
        'HTTP_FORWARDED_FOR',        // RFC 7239
        'HTTP_FORWARDED',            // RFC 7239
        'HTTP_X_REAL_IP',            // Nginx proxy
        'REMOTE_ADDR'                // Standard
    ];
    
    foreach ($ip_headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            $ip = trim($ips[0]);
            
            // Validate IP address
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Check if IP address is whitelisted
 *
 * @since    3.0.0
 * @param    string $ip_address IP to check
 * @return   bool   True if whitelisted
 */
function secure_aura_is_ip_whitelisted($ip_address) {
    $whitelist = get_option('secure_aura_whitelist_ips', '');
    
    if (empty($whitelist)) {
        return false;
    }
    
    $whitelist_entries = array_filter(array_map('trim', explode("\n", $whitelist)));
    
    foreach ($whitelist_entries as $entry) {
        if (secure_aura_ip_in_range($ip_address, $entry)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Check if IP address is in CIDR range
 *
 * @since    3.0.0
 * @param    string $ip    IP address to check
 * @param    string $range CIDR range (e.g., 192.168.1.0/24)
 * @return   bool   True if IP is in range
 */
function secure_aura_ip_in_range($ip, $range) {
    if (strpos($range, '/') === false) {
        // Single IP address
        return $ip === $range;
    }
    
    list($subnet, $mask) = explode('/', $range);
    
    if (!filter_var($ip, FILTER_VALIDATE_IP) || !filter_var($subnet, FILTER_VALIDATE_IP)) {
        return false;
    }
    
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);
    $mask_long = (-1 << (32 - (int)$mask));
    
    return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
}

/**
 * Check if IP address is blocked
 *
 * @since    3.0.0
 * @param    string $ip_address IP to check
 * @return   bool   True if blocked
 */
function secure_aura_is_ip_blocked($ip_address) {
    global $wpdb;
    
    $table_name = $wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
    
    $blocked = $wpdb->get_var($wpdb->prepare("
        SELECT COUNT(*) FROM {$table_name} 
        WHERE ip_address = %s 
        AND (expires_at IS NULL OR expires_at > NOW())
    ", $ip_address));
    
    return intval($blocked) > 0;
}

/**
 * Log security event
 *
 * @since    3.0.0
 * @param    string $event_type Event type
 * @param    array  $data       Event data
 * @param    string $severity   Event severity
 * @param    string $action     Response action taken
 * @return   bool   True on success
 */
function secure_aura_log_event($event_type, $data = [], $severity = SECURE_AURA_SEVERITY_MEDIUM, $action = '') {
    global $wpdb;
    
    $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
    
    $result = $wpdb->insert($table_name, [
        'event_type' => sanitize_text_field($event_type),
        'severity' => sanitize_text_field($severity),
        'source_ip' => secure_aura_get_client_ip(),
        'user_id' => get_current_user_id(),
        'event_data' => wp_json_encode($data),
        'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
        'request_uri' => substr($_SERVER['REQUEST_URI'] ?? '', 0, 500),
        'response_action' => sanitize_text_field($action),
        'created_at' => current_time('mysql')
    ]);
    
    return $result !== false;
}

/**
 * Get file hash for integrity checking
 *
 * @since    3.0.0
 * @param    string $file_path Path to file
 * @param    string $algorithm Hash algorithm
 * @return   string|false File hash or false on failure
 */
function secure_aura_get_file_hash($file_path, $algorithm = 'sha256') {
    if (!file_exists($file_path) || !is_readable($file_path)) {
        return false;
    }
    
    return hash_file($algorithm, $file_path);
}

/**
 * Sanitize and validate file path
 *
 * @since    3.0.0
 * @param    string $file_path File path to sanitize
 * @return   string|false Sanitized path or false if invalid
 */
function secure_aura_sanitize_file_path($file_path) {
    // Remove null bytes
    $file_path = str_replace(chr(0), '', $file_path);
    
    // Normalize path separators
    $file_path = wp_normalize_path($file_path);
    
    // Check for directory traversal attempts
    if (strpos($file_path, '../') !== false || strpos($file_path, '..\\') !== false) {
        return false;
    }
    
    // Ensure path is within WordPress directory
    $wp_path = wp_normalize_path(ABSPATH);
    if (strpos($file_path, $wp_path) !== 0) {
        return false;
    }
    
    return $file_path;
}

/**
 * Check if file type is allowed for scanning
 *
 * @since    3.0.0
 * @param    string $file_path File path
 * @return   bool   True if file type is scannable
 */
function secure_aura_is_scannable_file($file_path) {
    $scan_types = get_option('secure_aura_scan_file_types', [
        'php', 'js', 'html', 'htm', 'css', 'sql', 'py', 'pl', 'sh', 'bat'
    ]);
    
    $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
    
    return in_array($extension, $scan_types);
}

/**
 * Check if directory should be excluded from scanning
 *
 * @since    3.0.0
 * @param    string $dir_path Directory path
 * @return   bool   True if directory should be excluded
 */
function secure_aura_is_excluded_directory($dir_path) {
    $excluded_dirs = get_option('secure_aura_exclude_dirs', [
        'wp-content/cache',
        'wp-content/backup',
        'wp-content/updraft',
        'node_modules',
        '.git',
        '.svn'
    ]);
    
    $normalized_path = wp_normalize_path($dir_path);
    
    foreach ($excluded_dirs as $excluded_dir) {
        $excluded_path = wp_normalize_path(ABSPATH . $excluded_dir);
        if (strpos($normalized_path, $excluded_path) === 0) {
            return true;
        }
    }
    
    return false;
}

/**
 * Format file size in human readable format
 *
 * @since    3.0.0
 * @param    int $bytes     File size in bytes
 * @param    int $precision Decimal precision
 * @return   string Formatted file size
 */
function secure_aura_format_bytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    
    for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
    }
    
    return round($bytes, $precision) . ' ' . $units[$i];
}

/**
 * Check if current user has SecureAura capability
 *
 * @since    3.0.0
 * @param    string $capability Capability to check
 * @return   bool   True if user has capability
 */
function secure_aura_current_user_can($capability) {
    if (!is_user_logged_in()) {
        return false;
    }
    
    // Map SecureAura capabilities to WordPress capabilities
    $capability_map = [
        SECURE_AURA_CAP_MANAGE_SECURITY => 'manage_options',
        SECURE_AURA_CAP_VIEW_LOGS => 'manage_options',
        SECURE_AURA_CAP_MANAGE_FIREWALL => 'manage_options',
        SECURE_AURA_CAP_RUN_SCANS => 'manage_options',
        SECURE_AURA_CAP_MANAGE_THREATS => 'manage_options',
        SECURE_AURA_CAP_VIEW_REPORTS => 'manage_options'
    ];
    
    $wp_capability = $capability_map[$capability] ?? $capability;
    
    return current_user_can($wp_capability);
}

/**
 * Generate secure random string
 *
 * @since    3.0.0
 * @param    int    $length String length
 * @param    string $chars  Character set
 * @return   string Random string
 */
function secure_aura_generate_random_string($length = 32, $chars = '') {
    if (empty($chars)) {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    }
    
    $string = '';
    $chars_length = strlen($chars);
    
    for ($i = 0; $i < $length; $i++) {
        $string .= $chars[random_int(0, $chars_length - 1)];
    }
    
    return $string;
}

/**
 * Encrypt sensitive data
 *
 * @since    3.0.0
 * @param    string $data Data to encrypt
 * @param    string $key  Encryption key (optional)
 * @return   string|false Encrypted data or false on failure
 */
function secure_aura_encrypt_data($data, $key = '') {
    if (empty($key)) {
        $key = get_option('secure_aura_master_key', '');
        if (empty($key)) {
            return false;
        }
    }
    
    $method = SECURE_AURA_ENCRYPTION_METHOD;
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
    
    $encrypted = openssl_encrypt($data, $method, $key, 0, $iv);
    
    if ($encrypted === false) {
        return false;
    }
    
    return base64_encode($iv . $encrypted);
}

/**
 * Decrypt sensitive data
 *
 * @since    3.0.0
 * @param    string $encrypted_data Encrypted data
 * @param    string $key            Encryption key (optional)
 * @return   string|false Decrypted data or false on failure
 */
function secure_aura_decrypt_data($encrypted_data, $key = '') {
    if (empty($key)) {
        $key = get_option('secure_aura_master_key', '');
        if (empty($key)) {
            return false;
        }
    }
    
    $data = base64_decode($encrypted_data);
    if ($data === false) {
        return false;
    }
    
    $method = SECURE_AURA_ENCRYPTION_METHOD;
    $iv_length = openssl_cipher_iv_length($method);
    
    $iv = substr($data, 0, $iv_length);
    $encrypted = substr($data, $iv_length);
    
    return openssl_decrypt($encrypted, $method, $key, 0, $iv);
}

/**
 * Hash password securely
 *
 * @since    3.0.0
 * @param    string $password Password to hash
 * @return   string Hashed password
 */
function secure_aura_hash_password($password) {
    return password_hash($password, SECURE_AURA_PASSWORD_HASH_ALGORITHM);
}

/**
 * Verify password against hash
 *
 * @since    3.0.0
 * @param    string $password Password to verify
 * @param    string $hash     Stored hash
 * @return   bool   True if password is valid
 */
function secure_aura_verify_password($password, $hash) {
    return password_verify($password, $hash);
}

/**
 * Get security score based on multiple factors
 *
 * @since    3.0.0
 * @return   array Security score data
 */
function secure_aura_calculate_security_score() {
    $score = 0;
    $factors = [];
    $max_score = 100;
    
    // Plugin active (20 points)
    $score += 20;
    $factors['plugin_active'] = 20;
    
    // Firewall enabled (25 points)
    if (get_option('secure_aura_quantum_firewall_enabled', true)) {
        $score += 25;
        $factors['firewall_enabled'] = 25;
    }
    
    // Recent scan (20 points)
    $last_scan = get_option('secure_aura_last_scan_time', '');
    if ($last_scan && strtotime($last_scan) > (time() - 7 * 24 * 60 * 60)) {
        $score += 20;
        $factors['recent_scan'] = 20;
    }
    
    // Real-time protection (15 points)
    if (get_option('secure_aura_real_time_scanning_enabled', true)) {
        $score += 15;
        $factors['real_time_protection'] = 15;
    }
    
    // File integrity monitoring (10 points)
    if (get_option('secure_aura_file_integrity_monitoring_enabled', true)) {
        $score += 10;
        $factors['file_integrity'] = 10;
    }
    
    // Emergency mode (10 points)
    if (get_option('secure_aura_emergency_mode', false)) {
        $score += 10;
        $factors['emergency_mode'] = 10;
    }
    
    // Determine status
    if ($score >= 90) {
        $status = 'excellent';
        $status_text = __('Excellent', 'secure-aura');
        $status_class = 'excellent';
    } elseif ($score >= 70) {
        $status = 'good';
        $status_text = __('Good', 'secure-aura');
        $status_class = 'good';
    } elseif ($score >= 50) {
        $status = 'warning';
        $status_text = __('Needs Improvement', 'secure-aura');
        $status_class = 'warning';
    } else {
        $status = 'critical';
        $status_text = __('Critical', 'secure-aura');
        $status_class = 'critical';
    }
    
    return [
        'score' => min($score, $max_score),
        'max_score' => $max_score,
        'percentage' => min(round(($score / $max_score) * 100), 100),
        'status' => $status,
        'status_text' => $status_text,
        'status_class' => $status_class,
        'factors' => $factors
    ];
}

/**
 * Check if feature is available for current license
 *
 * @since    3.0.0
 * @param    string $feature Feature name
 * @return   bool   True if feature is available
 */
function secure_aura_is_feature_available($feature) {
    $license_type = get_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE);
    $features = secure_aura_get_license_features()[$license_type] ?? [];
    
    return !empty($features[$feature]);
}

/**
 * Get user-friendly time difference
 *
 * @since    3.0.0
 * @param    string $datetime DateTime string
 * @return   string Human-readable time difference
 */
function secure_aura_time_ago($datetime) {
    if (empty($datetime)) {
        return __('Never', 'secure-aura');
    }
    
    $time_ago = human_time_diff(strtotime($datetime), current_time('timestamp'));
    return sprintf(__('%s ago', 'secure-aura'), $time_ago);
}

/**
 * Clean up expired data
 *
 * @since    3.0.0
 * @param    string $data_type Type of data to clean
 * @param    int    $days      Days to retain
 * @return   int    Number of records cleaned
 */
function secure_aura_cleanup_expired_data($data_type, $days = 30) {
    global $wpdb;
    
    $tables = [
        'logs' => SECURE_AURA_TABLE_LOGS,
        'threats' => SECURE_AURA_TABLE_THREATS,
        'behavioral' => SECURE_AURA_TABLE_BEHAVIORAL,
        'quarantine' => SECURE_AURA_TABLE_QUARANTINE
    ];
    
    if (!isset($tables[$data_type])) {
        return 0;
    }
    
    $table_name = $wpdb->prefix . $tables[$data_type];
    $cutoff_date = date('Y-m-d H:i:s', strtotime("-{$days} days"));
    
    $deleted = $wpdb->query($wpdb->prepare("
        DELETE FROM {$table_name} 
        WHERE created_at < %s
    ", $cutoff_date));
    
    return intval($deleted);
}

/**
 * Get threat severity color
 *
 * @since    3.0.0
 * @param    string $severity Severity level
 * @return   string CSS color class
 */
function secure_aura_get_severity_color($severity) {
    $colors = [
        SECURE_AURA_SEVERITY_INFO => 'info',
        SECURE_AURA_SEVERITY_LOW => 'success',
        SECURE_AURA_SEVERITY_MEDIUM => 'warning',
        SECURE_AURA_SEVERITY_HIGH => 'danger',
        SECURE_AURA_SEVERITY_CRITICAL => 'danger',
        SECURE_AURA_SEVERITY_EMERGENCY => 'danger'
    ];
    
    return $colors[$severity] ?? 'secondary';
}

/**
 * Check if WordPress is in debug mode
 *
 * @since    3.0.0
 * @return   bool True if debug mode is enabled
 */
function secure_aura_is_debug_mode() {
    return defined('WP_DEBUG') && WP_DEBUG;
}

/**
 * Get WordPress and server information
 *
 * @since    3.0.0
 * @return   array System information
 */
function secure_aura_get_system_info() {
    global $wpdb;
    
    return [
        'wordpress' => [
            'version' => get_bloginfo('version'),
            'multisite' => is_multisite(),
            'language' => get_locale(),
            'timezone' => wp_timezone_string(),
            'debug_mode' => secure_aura_is_debug_mode(),
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
            'last_scan' => get_option('secure_aura_last_scan_time', 'Never')
        ]
    ];
}

/**
 * Validate nonce with SecureAura-specific action
 *
 * @since    3.0.0
 * @param    string $nonce  Nonce value
 * @param    string $action Action name
 * @return   bool   True if nonce is valid
 */
function secure_aura_verify_nonce($nonce, $action) {
    return wp_verify_nonce($nonce, 'secure_aura_' . $action);
}

/**
 * Create SecureAura-specific nonce
 *
 * @since    3.0.0
 * @param    string $action Action name
 * @return   string Nonce value
 */
function secure_aura_create_nonce($action) {
    return wp_create_nonce('secure_aura_' . $action);
}

/**
 * Check if current request is AJAX
 *
 * @since    3.0.0
 * @return   bool True if AJAX request
 */
function secure_aura_is_ajax_request() {
    return wp_doing_ajax() || (defined('DOING_AJAX') && DOING_AJAX);
}

/**
 * Check if current request is from admin area
 *
 * @since    3.0.0
 * @return   bool True if admin request
 */
function secure_aura_is_admin_request() {
    return is_admin() && !secure_aura_is_ajax_request();
}

/**
 * Get plugin activation status
 *
 * @since    3.0.0
 * @return   array Activation status information
 */
function secure_aura_get_activation_status() {
    return [
        'activated' => get_option('secure_aura_activated', false),
        'activation_time' => get_option('secure_aura_activation_time', ''),
        'setup_complete' => get_option('secure_aura_setup_complete', false),
        'first_run' => get_option('secure_aura_first_run', true)
    ];
}

/**
 * Mark setup as complete
 *
 * @since    3.0.0
 */
function secure_aura_complete_setup() {
    update_option('secure_aura_setup_complete', true);
    update_option('secure_aura_first_run', false);
    update_option('secure_aura_setup_completed_at', current_time('mysql'));
}

/**
 * Get plugin performance metrics
 *
 * @since    3.0.0
 * @return   array Performance metrics
 */
function secure_aura_get_performance_metrics() {
    return [
        'memory_usage' => memory_get_usage(true),
        'peak_memory' => memory_get_peak_usage(true),
        'execution_time' => microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'],
        'database_queries' => get_num_queries(),
        'cache_hits' => wp_cache_get_cache_hits(),
        'cache_misses' => wp_cache_get_cache_misses()
    ];
}

/**
 * Schedule a one-time event
 *
 * @since    3.0.0
 * @param    string $hook Hook name
 * @param    array  $args Arguments
 * @param    int    $delay Delay in seconds
 * @return   bool   True if scheduled successfully
 */
function secure_aura_schedule_single_event($hook, $args = [], $delay = 0) {
    $timestamp = time() + $delay;
    return wp_schedule_single_event($timestamp, $hook, $args);
}

/**
 * Check if a cron job is scheduled
 *
 * @since    3.0.0
 * @param    string $hook Hook name
 * @return   bool   True if scheduled
 */
function secure_aura_is_scheduled($hook) {
    return wp_next_scheduled($hook) !== false;
}

/**
 * Emergency cleanup function for critical situations
 *
 * @since    3.0.0
 * @return   bool True on success
 */
function secure_aura_emergency_cleanup() {
    // Clear all caches
    wp_cache_flush();
    
    // Clear transients
    delete_transient('secure_aura_scan_in_progress');
    delete_transient('secure_aura_scan_progress');
    delete_transient('secure_aura_emergency_mode');
    
    // Reset emergency mode
    update_option('secure_aura_emergency_mode', false);
    
    // Log emergency cleanup
    secure_aura_log_event(
        'emergency_cleanup',
        ['triggered_by' => get_current_user_id()],
        SECURE_AURA_SEVERITY_HIGH,
        'emergency_cleanup'
    );
    
    return true;
}

?>