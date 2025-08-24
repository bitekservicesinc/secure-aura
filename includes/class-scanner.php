<?php
/**
 * BiTek AI Scanner Class
 * 
 * AI-powered malware and file integrity scanner
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class BiTek_AI_Scanner {
    
    private $options;
    private $scan_results = array();
    private $malware_signatures = array();
    
    public function __construct($options) {
        $this->options = $options;
        $this->init_malware_signatures();
    }
    
    /**
     * Run a full security scan
     * 
     * This function performs a comprehensive scan of WordPress core files, plugins,
     * themes, and uploads directory. It checks for malware signatures, performs AI-based
     * analysis, and logs the results.
     * 
     * @return array Summary of the scan results including time taken, files scanned, and threats found.
     */
    public function run_full_scan() {
        $start_time = microtime(true);
        $this->scan_results = array();
        
        // Scan WordPress core files
        if ($this->options['scan_core_files']) {
            $this->scan_wordpress_core();
        }
        
        // Scan plugins
        if ($this->options['scan_plugins']) {
            $this->scan_plugins();
        }
        
        // Scan themes
        if ($this->options['scan_themes']) {
            $this->scan_themes();
        }
        
        // Scan uploads directory
        $this->scan_uploads();
        
        // File integrity check
        if ($this->options['file_change_detection']) {
            $this->check_file_integrity();
        }
        
        $scan_time = round(microtime(true) - $start_time, 2);
        
        $summary = array(
            'scan_time' => $scan_time,
            'files_scanned' => count($this->scan_results),
            'threats_found' => $this->count_threats(),
            'results' => $this->scan_results
        );
        
        $this->log_scan_results($summary);
        
        return $summary;
    }
    
    /**
     * Run daily scan if enabled
     * 
     * This function checks if the daily scan option is enabled and runs a full scan.
     * If threats are found, it sends an email notification to the site administrator.
     */
    public function run_daily_scan() {
        if (!$this->options['daily_scan']) {
            return;
        }
        
        $results = $this->run_full_scan();
        
        if ($results['threats_found'] > 0 && $this->options['email_notifications']) {
            $this->send_threat_notification($results);
        }
    }
    
    /**
     * Scan WordPress core files for malware
     * 
     * This function scans essential WordPress core files for known malware signatures
     * and updates the scan results.
     */
    private function scan_wordpress_core() {
        $wp_core_files = array(
            ABSPATH . 'wp-config.php',
            ABSPATH . 'wp-load.php',
            ABSPATH . 'wp-blog-header.php',
            ABSPATH . 'index.php',
            ABSPATH . 'wp-admin/index.php',
            ABSPATH . 'wp-includes/version.php'
        );
        
        foreach ($wp_core_files as $file) {
            if (file_exists($file)) {
                $this->scan_file($file, 'core');
            }
        }
    }
    
    /**
     * Scan the plugins directory for files
     * 
     * This function scans all plugins in the WordPress plugins directory,
     * excluding large files and certain file types.
     */
    private function scan_plugins() {
        $plugins_dir = WP_PLUGIN_DIR;
        $this->scan_directory($plugins_dir, 'plugin');
    }
    
    /**
     * Scan the themes directory for files
     * 
     * This function scans all themes in the WordPress themes directory,
     * excluding large files and certain file types.
     */
    private function scan_themes() {
        $themes_dir = get_theme_root();
        $this->scan_directory($themes_dir, 'theme');
    }
    
    /**
     * Scan the uploads directory for files
     * 
     * This function scans the uploads directory and its subdirectories,
     * excluding large files and certain file types.
     */
    private function scan_uploads() {
        $upload_dir = wp_upload_dir();
        $this->scan_directory($upload_dir['basedir'], 'upload');
    }
    
    /**
     * Scan a directory recursively for files
     * 
     * This function scans all files in the given directory and its subdirectories,
     * excluding large files and certain file types.
     * 
     * @param string $directory Directory to scan
     * @param string $type Type of files (core, plugin, theme, upload)
     */
    private function scan_directory($directory, $type) {
        if (!is_dir($directory)) {
            return;
        }
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory)
        );
        
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $file_path = $file->getPathname();
                
                // Skip large files (over 10MB)
                if ($file->getSize() > 10485760) {
                    continue;
                }
                
                // Skip certain file types
                $extension = strtolower($file->getExtension());
                if (in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'mp3', 'mp4', 'zip'])) {
                    continue;
                }
                
                $this->scan_file($file_path, $type);
            }
        }
    }
    /**
     * Scan a single file for malware and threats
     * 
     * @param string $file_path Path to the file
     * @param string $type Type of file (core, plugin, theme, upload)
     */
    private function scan_file($file_path, $type) {
        if (!is_readable($file_path)) {
            return;
        }
        
        $file_content = file_get_contents($file_path);
        if ($file_content === false) {
            return;
        }
        
        $threats = array();
        
        // Signature-based detection
        foreach ($this->malware_signatures as $signature_name => $signature_pattern) {
            if (preg_match($signature_pattern, $file_content)) {
                $threats[] = array(
                    'type' => 'signature',
                    'name' => $signature_name,
                    'severity' => $this->get_threat_severity($signature_name)
                );
            }
        }
        
        // AI-based detection for suspicious code
        if (!empty($this->options['huggingface_api_key']) && !empty($threats)) {
            $ai_result = $this->ai_malware_analysis($file_content, $file_path);
            if ($ai_result['malicious']) {
                $threats[] = array(
                    'type' => 'ai_detection',
                    'name' => $ai_result['reason'],
                    'severity' => 'high'
                );
            }
        }
        
        // Heuristic analysis
        $heuristic_threats = $this->heuristic_analysis($file_content, $file_path);
        $threats = array_merge($threats, $heuristic_threats);
        
        if (!empty($threats)) {
            $this->scan_results[] = array(
                'file' => $file_path,
                'type' => $type,
                'threats' => $threats,
                'status' => 'infected',
                'file_size' => filesize($file_path),
                'last_modified' => filemtime($file_path)
            );
        } else {
            $this->scan_results[] = array(
                'file' => $file_path,
                'type' => $type,
                'threats' => array(),
                'status' => 'clean',
                'file_size' => filesize($file_path),
                'last_modified' => filemtime($file_path)
            );
        }
    }
    
    /**
     * AI-based malware analysis using Hugging Face API
     * 
     * @param string $file_content Content of the file
     * @param string $file_path Path to the file
     * @return array Analysis result with 'malicious' flag and reason
     */
    private function ai_malware_analysis($file_content, $file_path) {
        $api_key = $this->options['huggingface_api_key'];
        $model = 'huggingface/CodeBERTa-small-v1';
        
        // Prepare content for AI analysis (first 2000 chars)
        $analysis_content = substr($file_content, 0, 2000);
        
        $api_url = "https://api-inference.huggingface.co/models/{$model}";
        
        $args = array(
            'body' => json_encode(array('inputs' => $analysis_content)),
            'headers' => array(
                'Authorization' => 'Bearer ' . $api_key,
                'Content-Type' => 'application/json',
            ),
            'timeout' => 30,
            'method' => 'POST'
        );
        
        $response = wp_remote_post($api_url, $args);
        
        if (is_wp_error($response)) {
            return array('malicious' => false, 'reason' => 'API Error');
        }
        
        $response_code = wp_remote_retrieve_response_code($response);
        $response_body = wp_remote_retrieve_body($response);
        
        if ($response_code !== 200) {
            return array('malicious' => false, 'reason' => 'API Error');
        }
        
        $data = json_decode($response_body, true);
        
        // Analyze AI response for malicious indicators
        if (isset($data[0]) && is_array($data[0])) {
            foreach ($data[0] as $prediction) {
                if (isset($prediction['label']) && isset($prediction['score'])) {
                    $label = strtoupper($prediction['label']);
                    if (in_array($label, ['MALICIOUS', 'SUSPICIOUS', 'THREAT']) && $prediction['score'] > 0.7) {
                        return array(
                            'malicious' => true,
                            'reason' => sprintf('AI detected malicious code (confidence: %.2f)', $prediction['score'])
                        );
                    }
                }
            }
        }
        
        return array('malicious' => false, 'reason' => 'Clean');
    }
    
    /**
     * Heuristic analysis for suspicious patterns in files
     * 
     * @param string $file_content Content of the file
     * @param string $file_path Path to the file
     * @return array List of detected threats
     */
    private function heuristic_analysis($file_content, $file_path) {
        $threats = array();
        $file_extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        
        // Check for suspicious PHP patterns
        if ($file_extension === 'php') {
            $php_threats = $this->analyze_php_file($file_content);
            $threats = array_merge($threats, $php_threats);
        }
        
        // Check for obfuscated JavaScript
        if (in_array($file_extension, ['js', 'html', 'htm'])) {
            $js_threats = $this->analyze_javascript($file_content);
            $threats = array_merge($threats, $js_threats);
        }
        
        // Check for suspicious file names
        $filename = basename($file_path);
        if ($this->is_suspicious_filename($filename)) {
            $threats[] = array(
                'type' => 'suspicious_filename',
                'name' => 'Suspicious filename: ' . $filename,
                'severity' => 'medium'
            );
        }
        
        return $threats;
    }
    
    /**
     * Analyze PHP file content for dangerous functions and obfuscation
     * 
     * @param string $content Content of the PHP file
     * @return array List of detected threats
     */
    private function analyze_php_file($content) {
        $threats = array();
        
        // Check for dangerous PHP functions
        $dangerous_functions = array(
            'eval', 'exec', 'system', 'shell_exec', 'passthru', 'file_get_contents',
            'file_put_contents', 'fopen', 'fwrite', 'base64_decode', 'gzinflate',
            'str_rot13', 'preg_replace', 'assert', 'create_function'
        );
        
        foreach ($dangerous_functions as $func) {
            if (preg_match('/\b' . preg_quote($func) . '\s*\(/i', $content)) {
                $threats[] = array(
                    'type' => 'dangerous_function',
                    'name' => 'Dangerous PHP function: ' . $func,
                    'severity' => 'high'
                );
            }
        }
        
        // Check for obfuscated code patterns
        $obfuscation_patterns = array(
            '/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*["\'][^"\']*["\'];\s*eval\s*\(/i' => 'Obfuscated eval',
            '/base64_decode\s*\(\s*["\'][A-Za-z0-9+\/=]{100,}["\']/' => 'Large base64 encoded string',
            '/gzinflate\s*\(\s*base64_decode/' => 'Compressed and encoded code',
            '/\$_[A-Z]+\[["\'][^"\']*["\']\]/' => 'Suspicious global variable usage'
        );
        
        foreach ($obfuscation_patterns as $pattern => $description) {
            if (preg_match($pattern, $content)) {
                $threats[] = array(
                    'type' => 'obfuscation',
                    'name' => $description,
                    'severity' => 'high'
                );
            }
        }
        
        return $threats;
    }
    
    /**
     * Analyze JavaScript content for suspicious patterns
     * 
     * @param string $content Content of the JavaScript file
     * @return array List of detected threats
     */
    private function analyze_javascript($content) {
        $threats = array();
        
        // Check for suspicious JavaScript patterns
        $js_patterns = array(
            '/eval\s*\(/i' => 'JavaScript eval usage',
            '/document\.write\s*\(/i' => 'Document.write usage',
            '/setTimeout\s*\(\s*["\'][^"\']*["\']/' => 'Suspicious setTimeout',
            '/unescape\s*\(/i' => 'JavaScript unescape',
            '/String\.fromCharCode/i' => 'Character encoding obfuscation'
        );
        
        foreach ($js_patterns as $pattern => $description) {
            if (preg_match($pattern, $content)) {
                $threats[] = array(
                    'type' => 'suspicious_js',
                    'name' => $description,
                    'severity' => 'medium'
                );
            }
        }
        
        return $threats;
    }
    
    /**
     * Check if the filename is suspicious based on common patterns
     * 
     * @param string $filename Name of the file
     * @return bool True if suspicious, false otherwise
     */
    private function is_suspicious_filename($filename) {
        $suspicious_patterns = array(
            '/^[a-z]{1,3}\.php$/',
            '/^\d+\.php$/',
            '/^[a-zA-Z]{10,}\.php$/',
            '/\.(php|phtml|php3|php4|php5|phps)\..*$/',
            '/\.(txt|log|bak)\.php$/',
        );
        
        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $filename)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check file integrity against stored checksums
     * 
     * This function compares current file checksums with stored values
     * and updates the database with the latest checksums.
     */
    private function check_file_integrity() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_file_integrity';
        
        // Get current file checksums
        $current_files = $this->get_core_file_checksums();
        
        foreach ($current_files as $file_path => $current_hash) {
            $stored_hash = $wpdb->get_var($wpdb->prepare(
                "SELECT file_hash FROM {$table_name} WHERE file_path = %s",
                $file_path
            ));
            
            if ($stored_hash && $stored_hash !== $current_hash) {
                $this->scan_results[] = array(
                    'file' => $file_path,
                    'type' => 'core',
                    'threats' => array(array(
                        'type' => 'file_modified',
                        'name' => 'Core file modified',
                        'severity' => 'high'
                    )),
                    'status' => 'modified',
                    'file_size' => filesize($file_path),
                    'last_modified' => filemtime($file_path)
                );
            }
            
            // Update or insert file hash
            $wpdb->replace(
                $table_name,
                array(
                    'file_path' => $file_path,
                    'file_hash' => $current_hash,
                    'file_size' => filesize($file_path),
                    'last_modified' => date('Y-m-d H:i:s', filemtime($file_path)),
                    'checked_at' => current_time('mysql')
                )
            );
        }
    }
    
    /**
     * Get checksums of core WordPress files
     * 
     * This function retrieves the checksums of essential WordPress core files
     * to monitor for unauthorized changes.
     * 
     * @return array Associative array of file paths and their checksums
     */
    private function get_core_file_checksums() {
        $core_files = array(
            ABSPATH . 'wp-config.php',
            ABSPATH . 'wp-load.php',
            ABSPATH . 'wp-blog-header.php',
            ABSPATH . 'index.php'
        );
        
        $checksums = array();
        
        foreach ($core_files as $file) {
            if (file_exists($file) && is_readable($file)) {
                $checksums[$file] = hash_file('sha256', $file);
            }
        }
        
        return $checksums;
    }
    
    /**
     * Initialize malware signatures for detection
     * 
     * This function sets up the regular expressions used to identify common
     * malware patterns in files.
     */
    private function init_malware_signatures() {
        $this->malware_signatures = array(
            'backdoor_generic' => '/(?:eval|base64_decode|gzinflate|str_rot13)\s*\(\s*(?:base64_decode|gzinflate|str_rot13)/i',
            'webshell_c99' => '/c99shell|c100shell|r57shell|webshell/i',
            'malicious_iframe' => '/<iframe[^>]*src[^>]*(?:viagra|casino|pharmacy)/i',
            'phishing_redirect' => '/header\s*\(\s*["\']location:\s*http/i',
            'sql_injection' => '/union\s+select.*from.*information_schema/i',
            'file_inclusion' => '/include\s*\(\s*\$_(?:GET|POST|REQUEST)/i',
            'command_execution' => '/(?:system|exec|shell_exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST)/i',
            'crypto_miner' => '/coinhive|cryptoloot|jsecoin|minergate/i',
            'trojan_uploader' => '/move_uploaded_file.*\$_FILES/i',
            'backdoor_password' => '/\$password\s*=\s*["\'][a-f0-9]{32}["\']/i'
        );
    }
    
    /**
     * Get threat severity based on signature name
     * 
     * @param string $signature_name Name of the malware signature
     * @return string Severity level (high, medium, low)
     */
    private function get_threat_severity($signature_name) {
        $high_severity = array('backdoor_generic', 'webshell_c99', 'command_execution', 'trojan_uploader');
        $medium_severity = array('malicious_iframe', 'phishing_redirect', 'file_inclusion', 'crypto_miner');
        
        if (in_array($signature_name, $high_severity)) {
            return 'high';
        } elseif (in_array($signature_name, $medium_severity)) {
            return 'medium';
        }
        
        return 'low';
    }
    
    /**
     * Count the number of threats found in the scan results
     * 
     * @return int Number of threats detected
     */
    private function count_threats() {
        $count = 0;
        foreach ($this->scan_results as $result) {
            if ($result['status'] !== 'clean') {
                $count++;
            }
        }
        return $count;
    }
    
    /**
     * Log scan results to the security event log
     * 
     * This function records the scan summary and details in the security log.
     * 
     * @param array $summary Scan summary including files scanned, threats found, etc.
     */
    private function log_scan_results($summary) {
        if (class_exists('BiTek_AI_Security_Guard')) {
            $instance = BiTek_AI_Security_Guard::get_instance();
            $instance->bitek_log_security_event('scan_completed', 
                sprintf('Scan completed: %d files scanned, %d threats found', 
                    $summary['files_scanned'], 
                    $summary['threats_found']
                ),
                $summary
            );
        }
    }
    
    /**
     * Send email notification for detected threats
     * 
     * This function sends an email to the site administrator with details of the threats found.
     * 
     * @param array $results Scan results including threats found, files scanned, etc.
     */
    private function send_threat_notification($results) {
        $admin_email = $this->options['admin_email'] ?: get_option('admin_email');
        $site_name = get_bloginfo('name');
        
        $subject = sprintf('[%s] Security Threats Detected', $site_name);
        
        $message = sprintf(
            "Security scan detected %d threats on your website.\n\n",
            $results['threats_found']
        );
        
        $message .= "Scan Summary:\n";
        $message .= sprintf("- Files scanned: %d\n", $results['files_scanned']);
        $message .= sprintf("- Threats found: %d\n", $results['threats_found']);
        $message .= sprintf("- Scan time: %s seconds\n\n", $results['scan_time']);
        
        $message .= "Please log into your WordPress admin panel to review the detailed scan results.\n";
        $message .= admin_url('admin.php?page=bitek-security-logs');
        
        wp_mail($admin_email, $subject, $message);
    }
}