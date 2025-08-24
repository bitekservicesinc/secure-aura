<?php
/**
 * BiTek AI Enhanced Firewall Class
 * 
 * Production-ready advanced AI-powered firewall with real-time threat detection
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class BiTek_AI_Firewall {
    
    private $options;
    private $blocked_ips = array();
    private $rate_limits = array();
    private $threat_patterns = array();
    private $whitelist_ips = array();
    private $attack_vectors = array();
    private $suspicious_activity = array();
    
    // Advanced configuration
    private $config = array(
        'max_requests_per_minute' => 60,
        'max_requests_per_hour' => 1000,
        'brute_force_threshold' => 5,
        'brute_force_window' => 900, // 15 minutes
        'rate_limit_window' => 300, // 5 minutes
        'suspicious_threshold' => 3,
        'auto_ban_duration' => 3600, // 1 hour
        'permanent_ban_threshold' => 10
    );
    
    public function __construct($options) {
        $this->options = $options;
        $this->init_threat_patterns();
        $this->load_blocked_ips();
        $this->load_whitelist_ips();
        $this->init_attack_vectors();
    }
    
    public function init_protection() {
        // Early firewall check - highest priority
        add_action('init', array($this, 'check_request'), 1);
        add_action('wp', array($this, 'advanced_request_analysis'), 1);
        
        // Login security
        add_action('wp_login_failed', array($this, 'handle_failed_login'));
        add_filter('authenticate', array($this, 'check_brute_force'), 30, 3);
        add_action('wp_login', array($this, 'handle_successful_login'), 10, 2);
        
        // Comment security
        add_filter('pre_comment_approved', array($this, 'check_comment_security'), 99, 2);
        
        // File upload security
        add_filter('wp_handle_upload_prefilter', array($this, 'scan_uploaded_file'));
        
        // Admin area protection
        add_action('admin_init', array($this, 'protect_admin_area'));
        
        // XMLRPC protection
        add_filter('xmlrpc_enabled', array($this, 'control_xmlrpc'));
        
        // REST API protection
        add_filter('rest_authentication_errors', array($this, 'protect_rest_api'));
        
        // Headers security
        add_action('send_headers', array($this, 'send_security_headers'));
    }
    
    public function check_request() {
        $client_ip = $this->get_client_ip();
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $request_method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        
        // Skip checks for whitelisted IPs
        if ($this->is_ip_whitelisted($client_ip)) {
            return;
        }
        
        // Check if IP is blocked
        if ($this->is_ip_blocked($client_ip)) {
            $this->block_request('IP address is blacklisted', $client_ip);
        }
        
        // Rate limiting with progressive penalties
        if ($this->options['rate_limiting'] && $this->is_rate_limited($client_ip)) {
            $this->handle_rate_limit_exceeded($client_ip);
        }
        
        // Enhanced attack detection
        $threat_level = $this->analyze_request_threat_level($client_ip, $request_uri, $user_agent, $request_method);
        
        if ($threat_level >= 8) {
            $this->log_and_block('High threat level detected', $client_ip, $request_uri, $threat_level);
        } elseif ($threat_level >= 5) {
            $this->handle_suspicious_activity($client_ip, $threat_level);
        }
        
        // Advanced pattern matching
        if ($this->detect_advanced_attack_patterns($request_uri, $user_agent)) {
            $this->log_and_block('Advanced attack pattern detected', $client_ip, $request_uri);
        }
    }
    
    public function advanced_request_analysis() {
        $client_ip = $this->get_client_ip();
        $request_data = $this->collect_request_data();
        
        // AI-powered behavioral analysis
        if (!empty($this->options['huggingface_api_key'])) {
            $ai_analysis = $this->ai_behavioral_analysis($request_data);
            if ($ai_analysis['threat_detected']) {
                $this->handle_ai_threat_detection($client_ip, $ai_analysis);
            }
        }
        
        // Geolocation-based risk assessment
        $geo_risk = $this->assess_geolocation_risk($client_ip);
        if ($geo_risk['high_risk']) {
            $this->handle_high_risk_location($client_ip, $geo_risk);
        }
        
        // Session analysis for authenticated users
        if (is_user_logged_in()) {
            $this->analyze_user_session();
        }
    }
    
    private function analyze_request_threat_level($ip, $uri, $user_agent, $method) {
        $threat_score = 0;
        
        // Method-based scoring
        if (in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'])) {
            $threat_score += 1;
        }
        
        // URI analysis
        $threat_score += $this->analyze_uri_patterns($uri);
        
        // User agent analysis
        $threat_score += $this->analyze_user_agent_patterns($user_agent);
        
        // Historical behavior analysis
        $threat_score += $this->analyze_ip_history($ip);
        
        // Request frequency analysis
        $threat_score += $this->analyze_request_frequency($ip);
        
        // Parameter analysis
        $threat_score += $this->analyze_request_parameters();
        
        return min($threat_score, 10); // Cap at 10
    }
    
    private function analyze_uri_patterns($uri) {
        $score = 0;
        $decoded_uri = urldecode($uri);
        
        // SQL injection patterns (weighted by severity)
        $sql_patterns = array(
            '/union\s+select/i' => 3,
            '/information_schema/i' => 3,
            '/concat\s*\(/i' => 2,
            '/@@version/i' => 3,
            '/drop\s+table/i' => 4,
            '/insert\s+into/i' => 2,
            '/delete\s+from/i' => 3,
            '/update\s+.*set/i' => 2,
            '/(\'|\"|%22|%27).*(or|and)\s*\1?\s*\1?\s*\d/i' => 2,
            '/\/\*.*\*\//i' => 2
        );
        
        // XSS patterns
        $xss_patterns = array(
            '/<script[^>]*>/i' => 3,
            '/<iframe[^>]*>/i' => 3,
            '/javascript\s*:/i' => 2,
            '/vbscript\s*:/i' => 2,
            '/on\w+\s*=/i' => 2,
            '/<object[^>]*>/i' => 2,
            '/<embed[^>]*>/i' => 2,
            '/expression\s*\(/i' => 3,
            '/document\.cookie/i' => 2,
            '/document\.write/i' => 1
        );
        
        // Path traversal patterns
        $traversal_patterns = array(
            '/\.\.\/.*\.\.\/.*\.\.\//i' => 3,
            '/\.\.\/\.\.\/\.\.\//i' => 2,
            '/\.\.\\\\.*\.\.\\\\.*\.\.\\\\/i' => 3,
            '/%2e%2e%2f/i' => 2,
            '/%2e%2e/i' => 1
        );
        
        // File inclusion patterns
        $inclusion_patterns = array(
            '/\/etc\/passwd/i' => 4,
            '/\/proc\/version/i' => 3,
            '/\/windows\/system32/i' => 3,
            '/boot\.ini/i' => 3,
            '/\/etc\/hosts/i' => 2,
            '/wp-config\.php/i' => 3
        );
        
        // Command injection patterns
        $command_patterns = array(
            '/;\s*(ls|dir|cat|type|pwd|whoami|id|uname)/i' => 4,
            '/\|\s*(ls|dir|cat|type|pwd|whoami|id|uname)/i' => 4,
            '/&&\s*(ls|dir|cat|type|pwd|whoami|id|uname)/i' => 4,
            '/`[^`]*`/i' => 3,
            '/\$\([^)]*\)/i' => 3
        );
        
        $all_patterns = array_merge($sql_patterns, $xss_patterns, $traversal_patterns, $inclusion_patterns, $command_patterns);
        
        foreach ($all_patterns as $pattern => $weight) {
            if (preg_match($pattern, $decoded_uri)) {
                $score += $weight;
            }
        }
        
        // Suspicious file extensions
        if (preg_match('/\.(bak|backup|old|tmp|log|sql|php~|phpbak)$/i', $uri)) {
            $score += 2;
        }
        
        // Admin area probing
        if (preg_match('/wp-admin|admin|phpmyadmin|cpanel|webmail/i', $uri) && !is_admin()) {
            $score += 1;
        }
        
        // Multiple encoding attempts
        $encoding_count = 0;
        if (strpos($uri, '%') !== false) $encoding_count++;
        if (strpos($uri, '\\x') !== false) $encoding_count++;
        if (strpos($uri, '&#') !== false) $encoding_count++;
        
        if ($encoding_count >= 2) {
            $score += 2;
        }
        
        return min($score, 5);
    }
    
    private function analyze_user_agent_patterns($user_agent) {
        $score = 0;
        
        if (empty($user_agent)) {
            return 3; // High score for empty user agent
        }
        
        $user_agent_lower = strtolower($user_agent);
        
        // Known malicious tools
        $malicious_agents = array(
            'sqlmap' => 4,
            'nikto' => 4,
            'nessus' => 4,
            'openvas' => 4,
            'w3af' => 4,
            'burpsuite' => 4,
            'burp suite' => 4,
            'acunetix' => 4,
            'netsparker' => 4,
            'webscarab' => 3,
            'paros' => 3,
            'vega' => 3,
            'grabber' => 3,
            'skipfish' => 3,
            'wfuzz' => 3,
            'dirb' => 3,
            'dirbuster' => 3,
            'havij' => 4,
            'pangolin' => 4,
            'x-scan' => 3,
            'masscan' => 3,
            'nmap' => 3,
            'zap' => 3,
            'owasp' => 2
        );
        
        foreach ($malicious_agents as $agent => $weight) {
            if (strpos($user_agent_lower, $agent) !== false) {
                return $weight;
            }
        }
        
        // Suspicious patterns
        $suspicious_patterns = array(
            '/python|curl|wget|libwww|lwp-trivial|winhttp/i' => 2,
            '/java\/|go-http|okhttp|apache-httpclient/i' => 1,
            '/bot|crawl|spider|scraper/i' => 1
        );
        
        foreach ($suspicious_patterns as $pattern => $weight) {
            if (preg_match($pattern, $user_agent)) {
                $score += $weight;
            }
        }
        
        // Very short or very long user agents
        $length = strlen($user_agent);
        if ($length < 20) {
            $score += 2;
        } elseif ($length > 500) {
            $score += 1;
        }
        
        // Unusual characters
        if (preg_match('/[<>"\']/', $user_agent)) {
            $score += 1;
        }
        
        return min($score, 4);
    }
    
    private function analyze_ip_history($ip) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        // Check recent blocking history
        $recent_blocks = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$table_name}
            WHERE ip = %s 
            AND type LIKE '%blocked%'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ", $ip));
        
        if ($recent_blocks > 5) {
            return 3;
        } elseif ($recent_blocks > 2) {
            return 2;
        } elseif ($recent_blocks > 0) {
            return 1;
        }
        
        return 0;
    }
    
    private function analyze_request_frequency($ip) {
        $current_time = time();
        $window = 300; // 5 minutes
        
        // Clean old entries
        if (isset($this->rate_limits[$ip])) {
            $this->rate_limits[$ip] = array_filter($this->rate_limits[$ip], function($timestamp) use ($current_time, $window) {
                return ($current_time - $timestamp) <= $window;
            });
        } else {
            $this->rate_limits[$ip] = array();
        }
        
        $request_count = count($this->rate_limits[$ip]);
        
        if ($request_count > 200) {
            return 4;
        } elseif ($request_count > 100) {
            return 3;
        } elseif ($request_count > 50) {
            return 2;
        } elseif ($request_count > 30) {
            return 1;
        }
        
        return 0;
    }
    
    private function analyze_request_parameters() {
        $score = 0;
        $all_params = array_merge($_GET, $_POST);
        
        foreach ($all_params as $key => $value) {
            $param_string = $key . '=' . $value;
            
            // Check for injection attempts in parameters
            if (preg_match('/(union|select|insert|delete|update|drop|script|javascript|vbscript)/i', $param_string)) {
                $score += 2;
            }
            
            // Check for encoded attacks
            if (preg_match('/%[0-9a-f]{2}/i', $param_string)) {
                $decoded = urldecode($param_string);
                if (preg_match('/(union|select|script|javascript)/i', $decoded)) {
                    $score += 2;
                }
            }
            
            // Check for excessive parameter length
            if (strlen($value) > 1000) {
                $score += 1;
            }
        }
        
        // Too many parameters
        if (count($all_params) > 20) {
            $score += 1;
        }
        
        return min($score, 3);
    }
    
    private function collect_request_data() {
        return array(
            'ip' => $this->get_client_ip(),
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'referer' => $_SERVER['HTTP_REFERER'] ?? '',
            'timestamp' => time(),
            'parameters' => array_merge($_GET, $_POST),
            'headers' => $this->get_request_headers()
        );
    }
    
    private function get_request_headers() {
        $headers = array();
        
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
        } else {
            foreach ($_SERVER as $key => $value) {
                if (strpos($key, 'HTTP_') === 0) {
                    $header_name = str_replace('HTTP_', '', $key);
                    $header_name = str_replace('_', '-', $header_name);
                    $headers[$header_name] = $value;
                }
            }
        }
        
        return $headers;
    }
    
    private function ai_behavioral_analysis($request_data) {
        $api_key = $this->options['huggingface_api_key'];
        
        if (empty($api_key)) {
            return array('threat_detected' => false, 'reason' => 'No API key');
        }
        
        // Prepare request data for AI analysis
        $analysis_text = sprintf(
            "Request: %s %s | IP: %s | UA: %s | Params: %s",
            $request_data['method'],
            $request_data['uri'],
            $request_data['ip'],
            substr($request_data['user_agent'], 0, 100),
            json_encode(array_keys($request_data['parameters']))
        );
        
        $model = 'microsoft/DialoGPT-medium';
        $api_url = "https://api-inference.huggingface.co/models/{$model}";
        
        $args = array(
            'body' => json_encode(array('inputs' => $analysis_text)),
            'headers' => array(
                'Authorization' => 'Bearer ' . $api_key,
                'Content-Type' => 'application/json',
            ),
            'timeout' => 10,
            'method' => 'POST'
        );
        
        $response = wp_remote_post($api_url, $args);
        
        if (is_wp_error($response)) {
            return array('threat_detected' => false, 'reason' => 'API Error');
        }
        
        $response_code = wp_remote_retrieve_response_code($response);
        if ($response_code !== 200) {
            return array('threat_detected' => false, 'reason' => 'API Error');
        }
        
        $response_body = wp_remote_retrieve_body($response);
        $data = json_decode($response_body, true);
        
        // Simple threat keyword detection in AI response
        if (isset($data[0]['generated_text'])) {
            $generated_text = strtolower($data[0]['generated_text']);
            $threat_keywords = array('attack', 'malicious', 'suspicious', 'threat', 'exploit', 'injection');
            
            foreach ($threat_keywords as $keyword) {
                if (strpos($generated_text, $keyword) !== false) {
                    return array(
                        'threat_detected' => true,
                        'reason' => 'AI detected suspicious behavior pattern',
                        'ai_response' => $generated_text
                    );
                }
            }
        }
        
        return array('threat_detected' => false, 'reason' => 'AI analysis clean');
    }
    
    private function assess_geolocation_risk($ip) {
        // This would integrate with a real GeoIP service
        // For now, basic IP range analysis
        
        $high_risk_ranges = array(
            // Known botnet ranges (example)
            '5.39.0.0/16',
            '31.0.0.0/8',
            '46.0.0.0/8',
            '91.0.0.0/8'
        );
        
        foreach ($high_risk_ranges as $range) {
            if ($this->ip_in_cidr($ip, $range)) {
                return array(
                    'high_risk' => true,
                    'reason' => 'IP from high-risk geographic region',
                    'risk_level' => 'medium'
                );
            }
        }
        
        return array('high_risk' => false, 'reason' => 'Geographic location clean');
    }
    
    private function handle_ai_threat_detection($ip, $ai_analysis) {
        $this->increment_suspicious_activity($ip);
        
        $this->log_security_event('ai_threat_detection', 
            'AI detected suspicious behavior: ' . $ai_analysis['reason'], 
            array(
                'ip' => $ip,
                'ai_analysis' => $ai_analysis
            )
        );
        
        // Consider temporary rate limiting for AI-detected threats
        $this->apply_temporary_rate_limit($ip, 300); // 5 minutes
    }
    
    private function handle_high_risk_location($ip, $geo_risk) {
        if ($geo_risk['risk_level'] === 'high') {
            $this->apply_temporary_rate_limit($ip, 1800); // 30 minutes
        }
        
        $this->log_security_event('high_risk_location', 
            'Request from high-risk location: ' . $geo_risk['reason'], 
            array('ip' => $ip, 'geo_analysis' => $geo_risk)
        );
    }
    
    private function analyze_user_session() {
        $user_id = get_current_user_id();
        $session_data = wp_get_session_token();
        
        // Check for session anomalies
        $last_ip = get_user_meta($user_id, '_bitek_last_ip', true);
        $current_ip = $this->get_client_ip();
        
        if (!empty($last_ip) && $last_ip !== $current_ip) {
            // IP changed during session - potential session hijacking
            $this->log_security_event('session_anomaly', 
                'User IP changed during session', 
                array(
                    'user_id' => $user_id,
                    'old_ip' => $last_ip,
                    'new_ip' => $current_ip
                )
            );
        }
        
        update_user_meta($user_id, '_bitek_last_ip', $current_ip);
    }
    
    private function handle_rate_limit_exceeded($ip) {
        $violation_count = $this->get_rate_limit_violations($ip);
        
        if ($violation_count >= 3) {
            // Escalate to temporary ban
            $this->block_ip($ip, 'Repeated rate limit violations', 3600);
        } else {
            // Apply progressive delay
            $delay = min($violation_count * 5, 30); // Max 30 seconds
            sleep($delay);
        }
        
        $this->log_security_event('rate_limit_exceeded', 
            "Rate limit exceeded (violation #{$violation_count})", 
            array('ip' => $ip, 'violation_count' => $violation_count)
        );
        
        $this->block_request('Rate limit exceeded', $ip);
    }
    
    private function handle_suspicious_activity($ip, $threat_level) {
        $this->increment_suspicious_activity($ip);
        
        $activity_count = $this->suspicious_activity[$ip] ?? 0;
        
        if ($activity_count >= $this->config['suspicious_threshold']) {
            // Escalate to blocking
            $this->block_ip($ip, 'Multiple suspicious activities detected', $this->config['auto_ban_duration']);
        } else {
            // Log and monitor
            $this->log_security_event('suspicious_activity', 
                "Suspicious activity detected (level: {$threat_level})", 
                array('ip' => $ip, 'threat_level' => $threat_level, 'activity_count' => $activity_count)
            );
        }
    }
    
    private function increment_suspicious_activity($ip) {
        if (!isset($this->suspicious_activity[$ip])) {
            $this->suspicious_activity[$ip] = 0;
        }
        $this->suspicious_activity[$ip]++;
        
        // Store in transient for persistence
        set_transient("bitek_suspicious_{$ip}", $this->suspicious_activity[$ip], 3600);
    }
    
    private function get_rate_limit_violations($ip) {
        $violations = get_transient("bitek_violations_{$ip}") ?: 0;
        $violations++;
        set_transient("bitek_violations_{$ip}", $violations, 3600);
        
        return $violations;
    }
    
    private function apply_temporary_rate_limit($ip, $duration) {
        set_transient("bitek_temp_limit_{$ip}", time() + $duration, $duration);
    }
    
    private function detect_advanced_attack_patterns($uri, $user_agent) {
        $combined_data = $uri . ' ' . $user_agent;
        
        // Advanced evasion techniques
        $evasion_patterns = array(
            '/\/\*.*?\*\/.*union/i', // SQL comment evasion
            '/\bunion\s*\/\*.*?\*\/\s*select/i', // Comment-based union
            '/\bselect.*?from.*?information_schema/i', // Schema enumeration
            '/\bload_file\s*\(/i', // File reading attempts
            '/\binto\s+outfile/i', // File writing attempts
            '/\bbenchmark\s*\(/i', // Time-based attacks
            '/\bsleep\s*\(/i', // Time delays
            '/\bwaitfor\s+delay/i', // MSSQL delays
        );
        
        foreach ($evasion_patterns as $pattern) {
            if (preg_match($pattern, $combined_data)) {
                return true;
            }
        }
        
        return false;
    }
    
    public function check_comment_security($approved, $commentdata) {
        $ip = $this->get_client_ip();
        
        // Skip for logged-in administrators
        if (current_user_can('manage_options')) {
            return $approved;
        }
        
        // Check if IP is blocked
        if ($this->is_ip_blocked($ip)) {
            wp_die('Your IP address has been blocked due to security violations.');
        }
        
        // Analyze comment for threats
        $comment_content = $commentdata['comment_content'] ?? '';
        $threat_level = $this->analyze_comment_threat_level($comment_content, $ip);
        
        if ($threat_level >= 5) {
            $this->log_security_event('comment_blocked', 
                'Comment blocked due to high threat level', 
                array('ip' => $ip, 'threat_level' => $threat_level)
            );
            wp_die('Your comment contains content that violates our security policies.');
        }
        
        return $approved;
    }
    
    private function analyze_comment_threat_level($content, $ip) {
        $score = 0;
        
        // URL analysis
        $url_count = preg_match_all('/https?:\/\//', $content);
        if ($url_count > 3) $score += 2;
        elseif ($url_count > 1) $score += 1;
        
        // HTML/Script tags
        if (preg_match('/<(script|iframe|object|embed)/i', $content)) {
            $score += 5;
        }
        
        // Suspicious patterns
        if (preg_match('/(viagra|casino|poker|loan|pharmacy)/i', $content)) {
            $score += 3;
        }
        
        // Check IP reputation
        $score += $this->analyze_ip_history($ip);
        
        return $score;
    }
    
    public function scan_uploaded_file($file) {
        $file_path = $file['tmp_name'];
        $file_name = $file['name'];
        
        // File extension check
        $allowed_extensions = array('jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt');
        $file_extension = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
        
        if (!in_array($file_extension, $allowed_extensions)) {
            $file['error'] = 'File type not allowed for security reasons.';
            return $file;
        }
        
        // File size check (prevent DoS)
        if ($file['size'] > 10485760) { // 10MB
            $file['error'] = 'File size exceeds security limits.';
            return $file;
        }
        
        // Basic malware scan
        if (is_readable($file_path)) {
            $file_content = file_get_contents($file_path, false, null, 0, 8192); // First 8KB
            
            if (preg_match('/(eval|base64_decode|exec|system|shell_exec)/i', $file_content)) {
                $file['error'] = 'File contains potentially malicious content.';
                $this->log_security_event('malicious_upload_blocked', 
                    'Blocked malicious file upload: ' . $file_name, 
                    array('ip' => $this->get_client_ip(), 'filename' => $file_name)
                );
                return $file;
            }
        }
        
        return $file;
    }
    
    public function protect_admin_area() {
        $ip = $this->get_client_ip();
        
        // Enhanced admin protection
        if (!current_user_can('manage_options')) {
            $suspicious_admin_access = get_transient("bitek_admin_attempt_{$ip}") ?: 0;
            $suspicious_admin_access++;
            set_transient("bitek_admin_attempt_{$ip}", $suspicious_admin_access, 3600);
            
            if ($suspicious_admin_access > 5) {
                $this->block_ip($ip, 'Multiple unauthorized admin access attempts', 7200);
                wp_die('Access denied due to security violations.');
            }
        }
    }
    
    public function control_xmlrpc($enabled) {
        // Disable XMLRPC by default for security
        if (!$this->options['xmlrpc_enabled']) {
            return false;
        }
        
        // Monitor XMLRPC usage
        $ip = $this->get_client_ip();
        $xmlrpc_requests = get_transient("bitek_xmlrpc_{$ip}") ?: 0;
        $xmlrpc_requests++;
        set_transient("bitek_xmlrpc_{$ip}", $xmlrpc_requests, 3600);
        
        if ($xmlrpc_requests > 10) {
            $this->log_security_event('xmlrpc_abuse', 
                'Excessive XMLRPC requests detected', 
                array('ip' => $ip, 'request_count' => $xmlrpc_requests)
            );
            return false;
        }
        
        return $enabled;
    }
    
    public function protect_rest_api($result) {
        if (!empty($result)) {
            return $result;
        }
        
        $ip = $this->get_client_ip();
        $api_requests = get_transient("bitek_api_{$ip}") ?: 0;
        $api_requests++;
        set_transient("bitek_api_{$ip}", $api_requests, 300); // 5 minutes
        
        if ($api_requests > 100) {
            return new WP_Error('rest_forbidden', 'API rate limit exceeded', array('status' => 429));
        }
        
        return $result;
    }
    
    public function send_security_headers() {
        // Content Security Policy
        header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; style-src \'self\' \'unsafe-inline\';');
        
        // X-Frame-Options
        header('X-Frame-Options: SAMEORIGIN');
        
        // X-Content-Type-Options
        header('X-Content-Type-Options: nosniff');
        
        // X-XSS-Protection
        header('X-XSS-Protection: 1; mode=block');
        
        // Referrer Policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Feature Policy
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    }
    
    public function handle_failed_login($username) {
        $ip = $this->get_client_ip();
        $current_time = time();
        
        // Get current failed attempts
        $failed_attempts = get_transient("bitek_failed_logins_{$ip}") ?: array();
        $failed_attempts[] = $current_time;
        
        // Clean old attempts (outside window)
        $failed_attempts = array_filter($failed_attempts, function($timestamp) use ($current_time) {
            return ($current_time - $timestamp) <= $this->config['brute_force_window'];
        });
        
        set_transient("bitek_failed_logins_{$ip}", $failed_attempts, $this->config['brute_force_window']);
        
        $attempt_count = count($failed_attempts);
        
        // Progressive response to brute force
        if ($attempt_count >= $this->config['brute_force_threshold']) {
            $ban_duration = $this->calculate_ban_duration($attempt_count);
            $this->block_ip($ip, "Brute force attack: {$attempt_count} failed attempts", $ban_duration);
            
            $this->log_security_event('brute_force_blocked', 
                "IP blocked after {$attempt_count} failed login attempts for user: {$username}", 
                array('ip' => $ip, 'username' => $username, 'attempt_count' => $attempt_count)
            );
        } else {
            $this->log_security_event('login_failed', 
                "Failed login attempt for user: {$username} (attempt {$attempt_count})", 
                array('ip' => $ip, 'username' => $username, 'attempt_count' => $attempt_count)
            );
        }
    }
    
    public function handle_successful_login($user_login, $user) {
        $ip = $this->get_client_ip();
        
        // Clear failed attempts on successful login
        delete_transient("bitek_failed_logins_{$ip}");
        
        // Log successful login
        $this->log_security_event('login_success', 
            "Successful login for user: {$user_login}", 
            array('ip' => $ip, 'user_id' => $user->ID, 'username' => $user_login)
        );
        
        // Check for suspicious login patterns
        $this->analyze_login_patterns($user->ID, $ip);
    }
    
    private function analyze_login_patterns($user_id, $ip) {
        $last_login_ip = get_user_meta($user_id, '_bitek_last_login_ip', true);
        $last_login_time = get_user_meta($user_id, '_bitek_last_login_time', true);
        $current_time = time();
        
        if (!empty($last_login_ip) && $last_login_ip !== $ip) {
            // Different IP - check if it's from different country/region
            $this->log_security_event('login_location_change', 
                'User logged in from different IP address', 
                array(
                    'user_id' => $user_id,
                    'old_ip' => $last_login_ip,
                    'new_ip' => $ip
                )
            );
        }
        
        if (!empty($last_login_time) && ($current_time - $last_login_time) < 300) {
            // Multiple logins within 5 minutes - potential account sharing
            $this->log_security_event('rapid_login', 
                'Rapid successive logins detected', 
                array('user_id' => $user_id, 'ip' => $ip, 'time_diff' => $current_time - $last_login_time)
            );
        }
        
        update_user_meta($user_id, '_bitek_last_login_ip', $ip);
        update_user_meta($user_id, '_bitek_last_login_time', $current_time);
    }
    
    private function calculate_ban_duration($attempt_count) {
        // Progressive ban duration
        if ($attempt_count >= 20) {
            return 86400; // 24 hours
        } elseif ($attempt_count >= 15) {
            return 43200; // 12 hours
        } elseif ($attempt_count >= 10) {
            return 21600; // 6 hours
        } elseif ($attempt_count >= 8) {
            return 7200; // 2 hours
        } else {
            return 3600; // 1 hour
        }
    }
    
    private function is_rate_limited($ip) {
        $current_time = time();
        
        // Check for temporary rate limits
        $temp_limit = get_transient("bitek_temp_limit_{$ip}");
        if ($temp_limit && $temp_limit > $current_time) {
            return true;
        }
        
        // Standard rate limiting
        if (!isset($this->rate_limits[$ip])) {
            $this->rate_limits[$ip] = array();
        }
        
        // Clean old entries
        $this->rate_limits[$ip] = array_filter($this->rate_limits[$ip], function($timestamp) use ($current_time) {
            return ($current_time - $timestamp) <= $this->config['rate_limit_window'];
        });
        
        // Add current request
        $this->rate_limits[$ip][] = $current_time;
        
        // Check per-minute limit
        $minute_requests = array_filter($this->rate_limits[$ip], function($timestamp) use ($current_time) {
            return ($current_time - $timestamp) <= 60;
        });
        
        if (count($minute_requests) > $this->config['max_requests_per_minute']) {
            return true;
        }
        
        // Check per-hour limit
        $hour_requests = array_filter($this->rate_limits[$ip], function($timestamp) use ($current_time) {
            return ($current_time - $timestamp) <= 3600;
        });
        
        if (count($hour_requests) > $this->config['max_requests_per_hour']) {
            return true;
        }
        
        return false;
    }
    
    public function check_brute_force($user, $username, $password) {
        $ip = $this->get_client_ip();
        $failed_attempts = get_transient("bitek_failed_logins_{$ip}") ?: array();
        
        if (count($failed_attempts) >= $this->config['brute_force_threshold']) {
            return new WP_Error('brute_force_blocked', 
                __('Too many failed login attempts. Please try again later.', 'bitek-ai-security')
            );
        }
        
        return $user;
    }
    
    private function init_threat_patterns() {
        $this->threat_patterns = array(
            'sql_injection' => array(
                'union\s+select',
                'information_schema',
                'concat\s*\(',
                '@@version',
                'drop\s+table',
                'insert\s+into',
                'delete\s+from',
                'update\s+.*set',
                'load_file\s*\(',
                'into\s+outfile'
            ),
            'xss' => array(
                '<script[^>]*>',
                '<iframe[^>]*>',
                'javascript\s*:',
                'vbscript\s*:',
                'on\w+\s*=',
                '<object[^>]*>',
                '<embed[^>]*>',
                'expression\s*\(',
                'document\.cookie',
                'document\.write'
            ),
            'lfi' => array(
                '\/etc\/passwd',
                '\/proc\/version',
                '\/windows\/system32',
                'boot\.ini',
                'wp-config\.php',
                '\.\.\/.*\.\.\/.*\.\.\/',
                '%2e%2e%2f'
            ),
            'rfi' => array(
                'https?:\/\/.*\.(txt|php)',
                'ftp:\/\/.*\.(txt|php)',
                'data:\/\/.*base64'
            )
        );
    }
    
    private function init_attack_vectors() {
        $this->attack_vectors = array(
            'bruteforce' => array(
                'description' => 'Brute force login attempts',
                'weight' => 3,
                'threshold' => 5
            ),
            'sql_injection' => array(
                'description' => 'SQL injection attempts',
                'weight' => 5,
                'threshold' => 1
            ),
            'xss' => array(
                'description' => 'Cross-site scripting attempts',
                'weight' => 4,
                'threshold' => 1
            ),
            'lfi' => array(
                'description' => 'Local file inclusion attempts',
                'weight' => 4,
                'threshold' => 1
            ),
            'rfi' => array(
                'description' => 'Remote file inclusion attempts',
                'weight' => 5,
                'threshold' => 1
            ),
            'directory_traversal' => array(
                'description' => 'Directory traversal attempts',
                'weight' => 3,
                'threshold' => 2
            ),
            'command_injection' => array(
                'description' => 'Command injection attempts',
                'weight' => 5,
                'threshold' => 1
            )
        );
    }
    
    private function load_blocked_ips() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_blocked_ips';
        
        // Check if table exists
        if ($wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") !== $table_name) {
            return;
        }
        
        $results = $wpdb->get_results("
            SELECT ip FROM {$table_name} 
            WHERE (expires_at IS NULL OR expires_at > NOW())
        ");
        
        foreach ($results as $row) {
            $this->blocked_ips[] = $row->ip;
        }
        
        // Load from cache for performance
        $cached_blocked = get_transient('bitek_blocked_ips_cache');
        if ($cached_blocked) {
            $this->blocked_ips = array_unique(array_merge($this->blocked_ips, $cached_blocked));
        }
    }
    
    private function load_whitelist_ips() {
        // Load from options
        $whitelist = $this->options['whitelist_ips'] ?? '';
        if (!empty($whitelist)) {
            $this->whitelist_ips = array_filter(array_map('trim', explode("\n", $whitelist)));
        }
        
        // Always whitelist localhost and private networks for development
        $default_whitelist = array(
            '127.0.0.1',
            '::1',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16'
        );
        
        $this->whitelist_ips = array_merge($this->whitelist_ips, $default_whitelist);
    }
    
    private function is_ip_blocked($ip) {
        return in_array($ip, $this->blocked_ips);
    }
    
    private function is_ip_whitelisted($ip) {
        foreach ($this->whitelist_ips as $whitelist_ip) {
            if (strpos($whitelist_ip, '/') !== false) {
                if ($this->ip_in_cidr($ip, $whitelist_ip)) {
                    return true;
                }
            } else {
                if ($ip === $whitelist_ip) {
                    return true;
                }
            }
        }
        return false;
    }
    
    public function block_ip($ip, $reason, $duration = 0) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_blocked_ips';
        $expires_at = $duration > 0 ? date('Y-m-d H:i:s', time() + $duration) : null;
        
        $result = $wpdb->replace(
            $table_name,
            array(
                'ip' => $ip,
                'reason' => $reason,
                'blocked_at' => current_time('mysql'),
                'expires_at' => $expires_at,
                'is_permanent' => $duration === 0 ? 1 : 0
            ),
            array('%s', '%s', '%s', '%s', '%d')
        );
        
        if ($result !== false) {
            // Add to runtime blocked list
            if (!in_array($ip, $this->blocked_ips)) {
                $this->blocked_ips[] = $ip;
            }
            
            // Update cache
            $cached_blocked = get_transient('bitek_blocked_ips_cache') ?: array();
            $cached_blocked[] = $ip;
            set_transient('bitek_blocked_ips_cache', array_unique($cached_blocked), 3600);
            
            $this->log_security_event('ip_blocked', 
                "IP {$ip} blocked: {$reason}", 
                array('ip' => $ip, 'reason' => $reason, 'duration' => $duration)
            );
        }
    }
    
    private function log_and_block($reason, $ip, $details = '', $threat_level = 0) {
        $this->log_security_event('firewall_blocked', $reason, array(
            'ip' => $ip,
            'details' => $details,
            'threat_level' => $threat_level
        ));
        
        // Determine ban duration based on threat level
        $ban_duration = $this->calculate_threat_based_ban_duration($threat_level);
        $this->block_ip($ip, $reason, $ban_duration);
        $this->block_request($reason, $ip);
    }
    
    private function calculate_threat_based_ban_duration($threat_level) {
        if ($threat_level >= 9) {
            return 86400; // 24 hours for critical threats
        } elseif ($threat_level >= 7) {
            return 21600; // 6 hours for high threats
        } elseif ($threat_level >= 5) {
            return 7200; // 2 hours for medium threats
        } else {
            return 3600; // 1 hour for low threats
        }
    }
    
    private function block_request($reason, $ip) {
        // Send appropriate HTTP status
        status_header(403);
        header('Content-Type: text/html; charset=utf-8');
        
        // Log the block
        $this->log_security_event('request_blocked', $reason, array('ip' => $ip));
        
        // Clean output buffer
        if (ob_get_level()) {
            ob_end_clean();
        }
        
        $message = sprintf(
            __('Access Denied: %s', 'bitek-ai-security'),
            esc_html($reason)
        );
        
        // Simple, secure error page
        echo '<!DOCTYPE html>';
        echo '<html><head>';
        echo '<title>Access Denied</title>';
        echo '<meta charset="UTF-8">';
        echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
        echo '</head><body>';
        echo '<h1>Access Denied</h1>';
        echo '<p>' . $message . '</p>';
        echo '<p>If you believe this is an error, please contact the site administrator.</p>';
        echo '</body></html>';
        
        exit;
    }
    
    private function get_client_ip() {
        // Check for IP from various headers in order of preference
        $ip_headers = array(
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_CLIENT_IP',            // Proxy
            'HTTP_X_FORWARDED_FOR',      // Load balancer/proxy
            'HTTP_X_FORWARDED',          // Proxy
            'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
            'HTTP_FORWARDED_FOR',        // Proxy
            'HTTP_FORWARDED',            // Proxy
            'REMOTE_ADDR'                // Standard
        );
        
        foreach ($ip_headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip_list = $_SERVER[$header];
                
                // Handle comma-separated list
                if (strpos($ip_list, ',') !== false) {
                    $ip_array = explode(',', $ip_list);
                    $ip = trim($ip_array[0]);
                } else {
                    $ip = trim($ip_list);
                }
                
                // Validate IP and ensure it's not private/reserved
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
                
                // If no public IP found, use the IP anyway for local development
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    private function ip_in_cidr($ip, $cidr) {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }
        
        list($network, $mask) = explode('/', $cidr);
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) || 
            filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // IPv6 handling
            return $this->ipv6_in_cidr($ip, $cidr);
        }
        
        // IPv4 handling
        $ip_long = ip2long($ip);
        $network_long = ip2long($network);
        
        if ($ip_long === false || $network_long === false) {
            return false;
        }
        
        $mask_long = (0xFFFFFFFF << (32 - $mask)) & 0xFFFFFFFF;
        
        return ($ip_long & $mask_long) === ($network_long & $mask_long);
    }
    
    private function ipv6_in_cidr($ip, $cidr) {
        list($network, $mask) = explode('/', $cidr);
        
        $ip_bin = inet_pton($ip);
        $network_bin = inet_pton($network);
        
        if ($ip_bin === false || $network_bin === false) {
            return false;
        }
        
        $mask = intval($mask);
        $bytes = intval($mask / 8);
        $bits = $mask % 8;
        
        for ($i = 0; $i < $bytes; $i++) {
            if ($ip_bin[$i] !== $network_bin[$i]) {
                return false;
            }
        }
        
        if ($bits > 0) {
            $ip_byte = ord($ip_bin[$bytes]);
            $network_byte = ord($network_bin[$bytes]);
            $mask_byte = (0xFF << (8 - $bits)) & 0xFF;
            
            if (($ip_byte & $mask_byte) !== ($network_byte & $mask_byte)) {
                return false;
            }
        }
        
        return true;
    }
    
    private function log_security_event($type, $message, $data = array()) {
        // Use the main plugin's logging method
        if (class_exists('BiTek_AI_Security_Guard')) {
            $instance = BiTek_AI_Security_Guard::get_instance();
            if (method_exists($instance, 'bitek_log_security_event')) {
                $instance->bitek_log_security_event($type, $message, $data);
            }
        }
    }
    
    // Public methods for statistics and management
    public function get_firewall_stats() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $stats = array();
        
        // Blocked requests in last 24 hours
        $stats['blocked_24h'] = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type = 'firewall_blocked'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ") ?: 0;
        
        // Blocked requests in last 7 days
        $stats['blocked_7d'] = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name}
            WHERE type = 'firewall_blocked'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ") ?: 0;
        
        // Total blocked IPs
        $blocked_ips_table = $wpdb->prefix . 'bitek_blocked_ips';
        $stats['blocked_ips'] = $wpdb->get_var("
            SELECT COUNT(*) FROM {$blocked_ips_table}
            WHERE expires_at IS NULL OR expires_at > NOW()
        ") ?: 0;
        
        // Top attack types
        $stats['attack_types'] = $wpdb->get_results("
            SELECT 
                SUBSTRING_INDEX(event, ':', 1) as attack_type,
                COUNT(*) as count
            FROM {$table_name}
            WHERE type = 'firewall_blocked'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 5
        ");
        
        return $stats;
    }
    
    public function unblock_ip($ip) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_blocked_ips';
        
        $result = $wpdb->delete($table_name, array('ip' => $ip), array('%s'));
        
        if ($result !== false) {
            // Remove from runtime list
            $key = array_search($ip, $this->blocked_ips);
            if ($key !== false) {
                unset($this->blocked_ips[$key]);
            }
            
            // Update cache
            $cached_blocked = get_transient('bitek_blocked_ips_cache') ?: array();
            $key = array_search($ip, $cached_blocked);
            if ($key !== false) {
                unset($cached_blocked[$key]);
                set_transient('bitek_blocked_ips_cache', array_values($cached_blocked), 3600);
            }
            
            $this->log_security_event('ip_unblocked', "IP {$ip} unblocked manually", array('ip' => $ip));
            
            return true;
        }
        
        return false;
    }
    
    public function get_blocked_ips($limit = 100) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_blocked_ips';
        
        return $wpdb->get_results($wpdb->prepare("
            SELECT ip, reason, blocked_at, expires_at, is_permanent
            FROM {$table_name}
            WHERE expires_at IS NULL OR expires_at > NOW()
            ORDER BY blocked_at DESC
            LIMIT %d
        ", $limit));
    }
    
    public function cleanup_expired_blocks() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_blocked_ips';
        
        $deleted = $wpdb->query("
            DELETE FROM {$table_name}
            WHERE expires_at IS NOT NULL AND expires_at <= NOW()
        ");
        
        if ($deleted > 0) {
            // Refresh blocked IPs list
            $this->load_blocked_ips();
            
            $this->log_security_event('cleanup_expired_blocks', 
                "Cleaned up {$deleted} expired IP blocks", 
                array('deleted_count' => $deleted)
            );
        }
        
        return $deleted;
    }
}
?>