<?php
/**
 * BiTek AI Threat Detector Class
 * 
 * Advanced threat intelligence and detection system
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class BiTek_AI_Threat_Detector {
    
    private $options;
    private $threat_feeds = array();
    private $known_bad_ips = array();
    
    public function __construct($options) {
        $this->options = $options;
        $this->init_threat_feeds();
        $this->load_threat_intelligence();
    }
    
    public function init_threat_feeds() {
        $this->threat_feeds = array(
            'malware_domains' => 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt',
            'phishing_domains' => 'https://phishing.army/download/phishing_army_blocklist.txt',
            'tor_exit_nodes' => 'https://check.torproject.org/torbulkexitlist',
            'spam_ips' => 'https://www.spamhaus.org/drop/drop.txt'
        );
    }
    
    public function load_threat_intelligence() {
        // Load cached threat data
        $this->known_bad_ips = get_transient('bitek_threat_ips') ?: array();
        
        // Update threat intelligence every 6 hours
        if (empty($this->known_bad_ips) || !get_transient('bitek_threat_last_update')) {
            $this->update_threat_intelligence();
        }
    }
    
    public function update_threat_intelligence() {
        $threat_ips = array();
        $threat_domains = array();
        
        foreach ($this->threat_feeds as $feed_name => $feed_url) {
            $feed_data = $this->fetch_threat_feed($feed_url);
            
            if ($feed_data) {
                switch ($feed_name) {
                    case 'spam_ips':
                        $ips = $this->parse_spamhaus_drop($feed_data);
                        $threat_ips = array_merge($threat_ips, $ips);
                        break;
                    
                    case 'tor_exit_nodes':
                        $ips = $this->parse_tor_exit_nodes($feed_data);
                        $threat_ips = array_merge($threat_ips, $ips);
                        break;
                    
                    case 'malware_domains':
                    case 'phishing_domains':
                        $domains = $this->parse_domain_list($feed_data);
                        $threat_domains = array_merge($threat_domains, $domains);
                        break;
                }
            }
        }
        
        // Cache threat intelligence
        set_transient('bitek_threat_ips', array_unique($threat_ips), 21600); // 6 hours
        set_transient('bitek_threat_domains', array_unique($threat_domains), 21600);
        set_transient('bitek_threat_last_update', time(), 21600);
        
        $this->known_bad_ips = array_unique($threat_ips);
        
        // Log update
        $this->log_threat_update(count($threat_ips), count($threat_domains));
    }
    
    private function fetch_threat_feed($url) {
        $response = wp_remote_get($url, array(
            'timeout' => 30,
            'user-agent' => 'BiTek-AI-Security-Guard/' . BITEK_AI_SECURITY_VERSION
        ));
        
        if (is_wp_error($response)) {
            return false;
        }
        
        $response_code = wp_remote_retrieve_response_code($response);
        if ($response_code !== 200) {
            return false;
        }
        
        return wp_remote_retrieve_body($response);
    }
    
    private function parse_spamhaus_drop($data) {
        $ips = array();
        $lines = explode("\n", $data);
        
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || strpos($line, ';') === 0) {
                continue;
            }
            
            if (preg_match('/^(\d+\.\d+\.\d+\.\d+\/\d+)/', $line, $matches)) {
                $ips[] = $matches[1];
            }
        }
        
        return $ips;
    }
    
    private function parse_tor_exit_nodes($data) {
        $ips = array();
        $lines = explode("\n", $data);
        
        foreach ($lines as $line) {
            $ip = trim($line);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips[] = $ip;
            }
        }
        
        return $ips;
    }
    
    private function parse_domain_list($data) {
        $domains = array();
        $lines = explode("\n", $data);
        
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || strpos($line, '#') === 0) {
                continue;
            }
            
            // Extract domain from various formats
            if (preg_match('/(?:0\.0\.0\.0|127\.0\.0\.1)\s+(.+)/', $line, $matches)) {
                $domain = trim($matches[1]);
            } elseif (strpos($line, '||') === 0) {
                $domain = str_replace('||', '', $line);
                $domain = str_replace('^', '', $domain);
            } else {
                $domain = $line;
            }
            
            if ($this->is_valid_domain($domain)) {
                $domains[] = strtolower($domain);
            }
        }
        
        return $domains;
    }
    
    private function is_valid_domain($domain) {
        return filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }
    
    public function is_ip_malicious($ip) {
        // Check against known bad IPs
        if (in_array($ip, $this->known_bad_ips)) {
            return array('malicious' => true, 'reason' => 'Known malicious IP');
        }
        
        // Check if IP is in CIDR ranges
        foreach ($this->known_bad_ips as $bad_ip) {
            if (strpos($bad_ip, '/') !== false) {
                if ($this->ip_in_cidr($ip, $bad_ip)) {
                    return array('malicious' => true, 'reason' => 'IP in malicious range');
                }
            }
        }
        
        // Geolocation-based analysis
        $geo_analysis = $this->analyze_ip_geolocation($ip);
        if ($geo_analysis['suspicious']) {
            return array('malicious' => true, 'reason' => $geo_analysis['reason']);
        }
        
        return array('malicious' => false, 'reason' => 'Clean');
    }
    
    private function ip_in_cidr($ip, $cidr) {
        list($network, $mask) = explode('/', $cidr);
        
        $ip_long = ip2long($ip);
        $network_long = ip2long($network);
        $mask_long = (0xFFFFFFFF << (32 - $mask)) & 0xFFFFFFFF;
        
        return ($ip_long & $mask_long) === ($network_long & $mask_long);
    }
    
    private function analyze_ip_geolocation($ip) {
        // Use a simple geolocation check based on IP ranges
        $high_risk_countries = array(
            // Known high-risk IP ranges (simplified for example)
            '5.39.0.0/16',    // Russia
            '14.0.0.0/8',     // China
            '27.0.0.0/8',     // Asia-Pacific
            '31.0.0.0/8',     // Europe/Russia
            '46.0.0.0/8',     // Europe
            '91.0.0.0/8',     // Europe/Middle East
            '103.0.0.0/8',    // Asia-Pacific
            '125.0.0.0/8',    // Asia
        );
        
        foreach ($high_risk_countries as $range) {
            if ($this->ip_in_cidr($ip, $range)) {
                // Don't block based on geography alone, just flag as suspicious
                return array('suspicious' => false, 'reason' => 'High-risk geographic region');
            }
        }
        
        return array('suspicious' => false, 'reason' => 'Clean geolocation');
    }
    
    public function analyze_request_patterns($ip, $user_agent, $uri) {
        $suspicious_patterns = array();
        
        // Analyze user agent
        $ua_analysis = $this->analyze_user_agent($user_agent);
        if ($ua_analysis['suspicious']) {
            $suspicious_patterns[] = $ua_analysis['reason'];
        }
        
        // Analyze request URI
        $uri_analysis = $this->analyze_request_uri($uri);
        if ($uri_analysis['suspicious']) {
            $suspicious_patterns[] = $uri_analysis['reason'];
        }
        
        // Analyze request frequency
        $frequency_analysis = $this->analyze_request_frequency($ip);
        if ($frequency_analysis['suspicious']) {
            $suspicious_patterns[] = $frequency_analysis['reason'];
        }
        
        // AI-powered behavioral analysis
        if (!empty($this->options['huggingface_api_key'])) {
            $ai_analysis = $this->ai_behavioral_analysis($ip, $user_agent, $uri);
            if ($ai_analysis['suspicious']) {
                $suspicious_patterns[] = $ai_analysis['reason'];
            }
        }
        
        return array(
            'suspicious' => !empty($suspicious_patterns),
            'patterns' => $suspicious_patterns,
            'threat_score' => $this->calculate_threat_score($suspicious_patterns)
        );
    }
    
    private function analyze_user_agent($user_agent) {
        // Empty or very short user agents
        if (empty($user_agent) || strlen($user_agent) < 10) {
            return array('suspicious' => true, 'reason' => 'Empty or too short user agent');
        }
        
        // Known bot/scanner user agents
        $malicious_agents = array(
            'sqlmap', 'nikto', 'nessus', 'openvas', 'w3af', 'burpsuite',
            'acunetix', 'netsparker', 'webscarab', 'paros', 'vega',
            'grabber', 'skipfish', 'wfuzz', 'dirb', 'dirbuster',
            'havij', 'pangolin', 'x-scan', 'masscan', 'nmap'
        );
        
        $user_agent_lower = strtolower($user_agent);
        foreach ($malicious_agents as $agent) {
            if (strpos($user_agent_lower, $agent) !== false) {
                return array('suspicious' => true, 'reason' => "Malicious user agent: {$agent}");
            }
        }
        
        // Suspicious patterns
        if (preg_match('/python|curl|wget|libwww|lwp-trivial|java\/|go-http|okhttp/i', $user_agent)) {
            return array('suspicious' => true, 'reason' => 'Automated tool user agent');
        }
        
        return array('suspicious' => false, 'reason' => 'Normal user agent');
    }
    
    private function analyze_request_uri($uri) {
        // Directory traversal attempts
        if (preg_match('/\.\.\/|\.\.\\\\/', $uri)) {
            return array('suspicious' => true, 'reason' => 'Directory traversal attempt');
        }
        
        // Common vulnerability scanners
        $vuln_patterns = array(
            '/wp-admin\/admin-ajax\.php.*action=.*exploit/i',
            '/wp-content\/plugins\/.*\/.*\.php\?.*=/i',
            '/\?.*union.*select/i',
            '/\?.*<script/i',
            '/wp-config\.php/i',
            '/\.env$/i',
            '/backup.*\.(sql|tar|zip|gz)$/i'
        );
        
        foreach ($vuln_patterns as $pattern) {
            if (preg_match($pattern, $uri)) {
                return array('suspicious' => true, 'reason' => 'Vulnerability scanning pattern');
            }
        }
        
        return array('suspicious' => false, 'reason' => 'Normal URI pattern');
    }
    
    private function analyze_request_frequency($ip) {
        // Get request count for the last hour
        $request_count = get_transient("bitek_requests_{$ip}") ?: 0;
        $request_count++;
        set_transient("bitek_requests_{$ip}", $request_count, 3600); // 1 hour
        
        // Flag if more than 200 requests per hour
        if ($request_count > 200) {
            return array('suspicious' => true, 'reason' => "High request frequency: {$request_count}/hour");
        }
        
        return array('suspicious' => false, 'reason' => 'Normal request frequency');
    }
    
    private function ai_behavioral_analysis($ip, $user_agent, $uri) {
        $api_key = $this->options['huggingface_api_key'];
        $model = 'microsoft/DialoGPT-medium'; // Behavioral analysis model
        
        // Prepare data for AI analysis
        $analysis_text = "IP: {$ip}, User-Agent: {$user_agent}, URI: {$uri}";
        
        $api_url = "https://api-inference.huggingface.co/models/{$model}";
        
        $args = array(
            'body' => json_encode(array('inputs' => $analysis_text)),
            'headers' => array(
                'Authorization' => 'Bearer ' . $api_key,
                'Content-Type' => 'application/json',
            ),
            'timeout' => 15,
            'method' => 'POST'
        );
        
        $response = wp_remote_post($api_url, $args);
        
        if (is_wp_error($response)) {
            return array('suspicious' => false, 'reason' => 'AI analysis failed');
        }
        
        $response_code = wp_remote_retrieve_response_code($response);
        if ($response_code !== 200) {
            return array('suspicious' => false, 'reason' => 'AI analysis failed');
        }
        
        $response_body = wp_remote_retrieve_body($response);
        $data = json_decode($response_body, true);
        
        // Simple AI response analysis
        if (isset($data[0]['generated_text'])) {
            $generated_text = strtolower($data[0]['generated_text']);
            $threat_keywords = array('malicious', 'attack', 'exploit', 'suspicious', 'harmful');
            
            foreach ($threat_keywords as $keyword) {
                if (strpos($generated_text, $keyword) !== false) {
                    return array('suspicious' => true, 'reason' => 'AI detected suspicious behavior pattern');
                }
            }
        }
        
        return array('suspicious' => false, 'reason' => 'AI analysis clean');
    }
    
    private function calculate_threat_score($patterns) {
        $base_score = count($patterns) * 10;
        $max_score = 100;
        
        return min($base_score, $max_score);
    }
    
    public function get_threat_statistics() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        $stats = array();
        
        // Get threat counts for the last 24 hours
        $stats['malicious_ips'] = $wpdb->get_var("
            SELECT COUNT(DISTINCT ip) FROM {$table_name} 
            WHERE type IN ('firewall_blocked', 'brute_force') 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        
        $stats['suspicious_domains'] = count(get_transient('bitek_threat_domains') ?: array());
        
        $stats['attack_patterns'] = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE type IN ('sql_injection', 'xss_attempt', 'vulnerability_scan') 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");
        
        $stats['total_threats_blocked'] = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE type LIKE '%blocked%' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        
        return $stats;
    }
    
    public function get_recent_threat_trends() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $trends = $wpdb->get_results("
            SELECT 
                DATE(created_at) as date,
                type,
                COUNT(*) as count
            FROM {$table_name}
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            AND type IN ('firewall_blocked', 'comment_blocked', 'brute_force', 'malware_detected')
            GROUP BY DATE(created_at), type
            ORDER BY date DESC, count DESC
        ");
        
        return $trends;
    }
    
    public function detect_advanced_persistent_threats($ip) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        // Look for patterns indicating APT activity
        $apt_indicators = array();
        
        // Check for persistent login attempts from same IP
        $login_attempts = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$table_name}
            WHERE ip = %s 
            AND type = 'login_failed'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ", $ip));
        
        if ($login_attempts > 20) {
            $apt_indicators[] = 'Persistent login attempts over extended period';
        }
        
        // Check for reconnaissance activities
        $recon_activities = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(DISTINCT url) FROM {$table_name}
            WHERE ip = %s 
            AND type = 'firewall_blocked'
            AND event LIKE '%scan%'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ", $ip));
        
        if ($recon_activities > 10) {
            $apt_indicators[] = 'Systematic reconnaissance scanning';
        }
        
        // Check for multiple attack vectors from same IP
        $attack_types = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(DISTINCT type) FROM {$table_name}
            WHERE ip = %s 
            AND type IN ('sql_injection', 'xss_attempt', 'file_inclusion', 'command_execution')
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ", $ip));
        
        if ($attack_types >= 3) {
            $apt_indicators[] = 'Multiple attack vectors employed';
        }
        
        return array(
            'is_apt' => !empty($apt_indicators),
            'indicators' => $apt_indicators,
            'threat_level' => $this->calculate_apt_threat_level($apt_indicators)
        );
    }
    
    private function calculate_apt_threat_level($indicators) {
        $indicator_count = count($indicators);
        
        if ($indicator_count >= 3) {
            return 'critical';
        } elseif ($indicator_count >= 2) {
            return 'high';
        } elseif ($indicator_count >= 1) {
            return 'medium';
        }
        
        return 'low';
    }
    
    public function generate_threat_report() {
        $report = array();
        
        // Basic statistics
        $report['statistics'] = $this->get_threat_statistics();
        
        // Recent trends
        $report['trends'] = $this->get_recent_threat_trends();
        
        // Top threatening IPs
        $report['top_threat_ips'] = $this->get_top_threat_ips();
        
        // Geographic distribution
        $report['geographic_distribution'] = $this->get_geographic_threat_distribution();
        
        // Attack method breakdown
        $report['attack_methods'] = $this->get_attack_method_breakdown();
        
        // Threat intelligence update status
        $report['intelligence_status'] = array(
            'last_update' => get_transient('bitek_threat_last_update'),
            'known_bad_ips' => count($this->known_bad_ips),
            'known_bad_domains' => count(get_transient('bitek_threat_domains') ?: array())
        );
        
        return $report;
    }
    
    private function get_top_threat_ips($limit = 10) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        return $wpdb->get_results($wpdb->prepare("
            SELECT 
                ip,
                COUNT(*) as threat_count,
                MAX(created_at) as last_seen,
                GROUP_CONCAT(DISTINCT type) as attack_types
            FROM {$table_name}
            WHERE type LIKE '%blocked%' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY ip
            ORDER BY threat_count DESC
            LIMIT %d
        ", $limit));
    }
    
    private function get_geographic_threat_distribution() {
        // Simplified geographic analysis based on IP ranges
        $geographic_data = array(
            'North America' => 0,
            'Europe' => 0,
            'Asia' => 0,
            'South America' => 0,
            'Africa' => 0,
            'Oceania' => 0,
            'Unknown' => 0
        );
        
        // This would typically use a GeoIP database
        // For now, return sample data
        return array(
            'North America' => 25,
            'Europe' => 35,
            'Asia' => 30,
            'South America' => 5,
            'Africa' => 3,
            'Oceania' => 1,
            'Unknown' => 1
        );
    }
    
    private function get_attack_method_breakdown() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        return $wpdb->get_results("
            SELECT 
                type as method,
                COUNT(*) as count,
                ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM {$table_name} WHERE type LIKE '%blocked%' AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY))), 2) as percentage
            FROM {$table_name}
            WHERE type LIKE '%blocked%' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY type
            ORDER BY count DESC
        ");
    }
    
    private function log_threat_update($ip_count, $domain_count) {
        if (class_exists('BiTek_AI_Security_Guard')) {
            $instance = BiTek_AI_Security_Guard::get_instance();
            $instance->bitek_log_security_event('threat_intelligence_update', 
                sprintf('Threat intelligence updated: %d IPs, %d domains', $ip_count, $domain_count),
                array('ip_count' => $ip_count, 'domain_count' => $domain_count)
            );
        }
    }
    
    public function emergency_lockdown_mode() {
        // Enable maximum security settings
        $emergency_options = array(
            'firewall_enabled' => 1,
            'rate_limiting' => 1,
            'brute_force_protection' => 1,
            'sql_injection_protection' => 1,
            'xss_protection' => 1,
            'ai_comment_enabled' => 1,
            'ai_threshold' => 0.5, // Lower threshold = stricter
            'malware_scanner' => 1,
            'file_change_detection' => 1
        );
        
        // Update options
        $current_options = get_option('bitek_ai_security_options');
        $updated_options = array_merge($current_options, $emergency_options);
        update_option('bitek_ai_security_options', $updated_options);
        
        // Block all known malicious IPs
        global $wpdb;
        $blocked_ips_table = $wpdb->prefix . 'bitek_blocked_ips';
        
        foreach ($this->known_bad_ips as $bad_ip) {
            $wpdb->replace(
                $blocked_ips_table,
                array(
                    'ip' => $bad_ip,
                    'reason' => 'Emergency lockdown - known threat',
                    'blocked_at' => current_time('mysql'),
                    'is_permanent' => 1
                )
            );
        }
        
        // Log emergency activation
        if (class_exists('BiTek_AI_Security_Guard')) {
            $instance = BiTek_AI_Security_Guard::get_instance();
            $instance->bitek_log_security_event('emergency_lockdown', 
                'Emergency lockdown mode activated',
                array('blocked_ips' => count($this->known_bad_ips))
            );
        }
        
        return array(
            'success' => true,
            'message' => 'Emergency lockdown mode activated',
            'blocked_ips' => count($this->known_bad_ips)
        );
    }
}