<?php

/**
 * Plugin Name: BiTek AI Security Guard
 * Plugin URI: https://github.com/bitek/ai-security-guard
 * Description: Production-ready AI-powered security suite with advanced firewall, real-time malware detection, intelligent comment filtering, and comprehensive threat protection using enterprise-grade AI models.
 * Version: 1.0.0
 * Author: BiTek Security
 * Author URI: https://bitek.dev
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: bitek-ai-security
 * Domain Path: /languages
 * Requires at least: 5.0
 * Tested up to: 6.4
 * Requires PHP: 7.4
 * Network: false
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('BITEK_AI_SECURITY_VERSION', '1.0.0');
define('BITEK_AI_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('BITEK_AI_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));
define('BITEK_AI_SECURITY_PLUGIN_FILE', __FILE__);
define('BITEK_AI_SECURITY_DB_VERSION', '1.0');
define('BITEK_AI_SECURITY_MIN_PHP_VERSION', '7.4');
define('BITEK_AI_SECURITY_MIN_WP_VERSION', '5.0');

/**
 * Main BiTek AI Security Guard Class
 */
class BiTek_AI_Security_Guard
{
    private static $instance = null;
    private $options;
    private $firewall;
    private $scanner;
    private $threat_detector;
    private $daily_stats;
    private $logs_page;
    private $is_initialized = false;

    // Performance tracking
    private $start_time;
    private $query_count;

    // Enhanced keyword database for comprehensive protection
    private $default_keywords = [
        // Gambling & Casino
        'casino',
        'betting',
        'gambling',
        'poker',
        'slots',
        'jackpot',
        'roulette',
        'blackjack',
        'aviator',
        'aviator game',
        'crash game',
        'mines game',
        'plinko',
        'sweet bonanza',
        'mostbet',
        '1xbet',
        'betway',
        'bet365',
        'stake',
        'bc.game',
        'roobet',
        'play smarter',
        'download version',
        'official app',
        'bonus code',
        'deposit bonus',

        // Cybersecurity Threats
        'malware',
        'virus',
        'trojan',
        'ransomware',
        'keylogger',
        'botnet',
        'rootkit',
        'phishing',
        'scam',
        'hack',
        'exploit',
        'vulnerability',
        'backdoor',
        'injection',
        'xss',
        'csrf',
        'sql injection',
        'code execution',
        'privilege escalation',

        // Adult Content
        'porn',
        'sex',
        'xxx',
        'adult',
        'escort',
        'cam girls',
        'dating site',
        'hookup',

        // Financial Scams
        'cryptocurrency',
        'bitcoin mining',
        'forex trading',
        'investment opportunity',
        'get rich quick',
        'passive income',
        'financial freedom',
        'trading bot',

        // Spam Patterns
        'click here',
        'buy now',
        'limited time',
        'act now',
        'make money',
        'work from home',
        'weight loss',
        'lose weight',
        'supplement',
        'pharmacy',
        'viagra',
        'cialis'
    ];

    public static function get_instance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        $this->start_time = microtime(true);
        $this->query_count = get_num_queries();

        // Check system requirements
        if (!$this->check_requirements()) {
            return;
        }

        $this->init();
    }

    private function check_requirements()
    {
        // Check PHP version
        if (version_compare(PHP_VERSION, BITEK_AI_SECURITY_MIN_PHP_VERSION, '<')) {
            add_action('admin_notices', function () {
                echo '<div class="notice notice-error"><p>';
                printf(
                    __('BiTek AI Security Guard requires PHP %s or higher. You are running PHP %s.', 'bitek-ai-security'),
                    BITEK_AI_SECURITY_MIN_PHP_VERSION,
                    PHP_VERSION
                );
                echo '</p></div>';
            });
            return false;
        }

        // Check WordPress version
        global $wp_version;
        if (version_compare($wp_version, BITEK_AI_SECURITY_MIN_WP_VERSION, '<')) {
            add_action('admin_notices', function () use ($wp_version) {
                echo '<div class="notice notice-error"><p>';
                printf(
                    __('BiTek AI Security Guard requires WordPress %s or higher. You are running WordPress %s.', 'bitek-ai-security'),
                    BITEK_AI_SECURITY_MIN_WP_VERSION,
                    $wp_version
                );
                echo '</p></div>';
            });
            return false;
        }

        // Check required PHP extensions
        $required_extensions = array('json', 'curl', 'mbstring');
        $missing_extensions = array();

        foreach ($required_extensions as $extension) {
            if (!extension_loaded($extension)) {
                $missing_extensions[] = $extension;
            }
        }

        if (!empty($missing_extensions)) {
            add_action('admin_notices', function () use ($missing_extensions) {
                echo '<div class="notice notice-error"><p>';
                printf(
                    __('BiTek AI Security Guard requires the following PHP extensions: %s', 'bitek-ai-security'),
                    implode(', ', $missing_extensions)
                );
                echo '</p></div>';
            });
            return false;
        }

        return true;
    }

    private function init()
    {
        // Load options early
        $this->options = get_option('bitek_ai_security_options', $this->bitek_get_default_options());

        // Load text domain
        add_action('plugins_loaded', array($this, 'bitek_load_textdomain'));

        // Initialize core security early
        add_action('init', array($this, 'bitek_init_security'), 1);

        // Initialize components after WordPress loads
        add_action('wp_loaded', array($this, 'init_components'));

        // Comment filtering
        add_filter('preprocess_comment', array($this, 'bitek_scan_comment'), 10, 1);

        // Admin hooks
        if (is_admin()) {
            $this->init_admin_hooks();
        }

        // Cron hooks for scheduled tasks
        add_action('bitek_daily_scan', array($this, 'bitek_perform_daily_scan'));
        add_action('bitek_cleanup_logs', array($this, 'bitek_cleanup_old_logs'));
        add_action('bitek_cleanup_stats', array($this, 'bitek_cleanup_old_stats'));

        // Activation/Deactivation hooks
        register_activation_hook(__FILE__, array($this, 'bitek_activate'));
        register_deactivation_hook(__FILE__, array($this, 'bitek_deactivate'));

        // Performance monitoring
        add_action('shutdown', array($this, 'track_performance'));
    }

    private function init_admin_hooks()
    {
        add_action('admin_menu', array($this, 'bitek_add_admin_menu'));
        add_action('admin_init', array($this, 'bitek_admin_init'));
        add_action('admin_enqueue_scripts', array($this, 'bitek_admin_scripts'));

        // AJAX handlers
        $ajax_actions = array(
            'bitek_get_dashboard_data',
            'bitek_run_scan',
            'bitek_test_api',
            'bitek_refresh_threats',
            'bitek_emergency_mode',
            'bitek_run_full_scan',
            'bitek_get_logs',
            'bitek_get_log_details',
            'bitek_block_ip',
            'bitek_clear_logs',
            'bitek_export_logs'
        );

        foreach ($ajax_actions as $action) {
            add_action("wp_ajax_{$action}", array($this, str_replace('bitek_', 'bitek_ajax_', $action)));
        }

        // Admin notices
        add_action('admin_notices', array($this, 'show_admin_notices'));
    }

    public function init_components()
    {
        if ($this->is_initialized) {
            return;
        }

        try {
            // Include component files
            $components = array(
                'class-firewall.php',
                'class-scanner.php',
                'class-threat-detector.php',
                'class-daily-stats.php',
                'class-logs-page.php'
            );

            foreach ($components as $component) {
                $file_path = BITEK_AI_SECURITY_PLUGIN_DIR . 'includes/' . $component;
                if (file_exists($file_path)) {
                    require_once $file_path;
                } else {
                    throw new Exception("Required component file not found: {$component}");
                }
            }

            // Initialize components
            $this->firewall = new BiTek_AI_Firewall($this->options);
            $this->scanner = new BiTek_AI_Scanner($this->options);
            $this->threat_detector = new BiTek_AI_Threat_Detector($this->options);
            $this->daily_stats = new BiTek_Daily_Stats();
            $this->logs_page = new BiTek_Security_Logs_Page($this->options);

            $this->is_initialized = true;
        } catch (Exception $e) {
            $this->log_error('Component initialization failed: ' . $e->getMessage());

            if (is_admin()) {
                add_action('admin_notices', function () use ($e) {
                    echo '<div class="notice notice-error"><p>';
                    printf(
                        __('BiTek AI Security Guard initialization failed: %s', 'bitek-ai-security'),
                        esc_html($e->getMessage())
                    );
                    echo '</p></div>';
                });
            }
        }
    }

    public function bitek_init_security()
    {
        // Initialize firewall protection early
        if (isset($this->options['firewall_enabled']) && $this->options['firewall_enabled']) {
            // Basic request validation before full component loading
            $this->basic_security_check();
        }

        // Initialize firewall after components are loaded
        add_action('wp_loaded', function () {
            if (isset($this->firewall) && $this->options['firewall_enabled']) {
                $this->firewall->init_protection();
            }
        });
    }

    private function basic_security_check()
    {
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Block obvious attack patterns immediately
        $immediate_block_patterns = array(
            '/\.\.\//i',                                    // Directory traversal
            '/<script[^>]*>/i',                            // XSS
            '/union\s+select/i',                           // SQL injection
            '/wp-config\.php/i',                           // Config file access
            '/eval\s*\(/i',                               // Code execution
            '/(base64_decode|exec|system|shell_exec)/i'    // Dangerous functions
        );

        foreach ($immediate_block_patterns as $pattern) {
            if (preg_match($pattern, $request_uri . ' ' . $user_agent)) {
                $this->emergency_block('Critical security pattern detected');
            }
        }
    }

    private function emergency_block($reason)
    {
        status_header(403);

        // Log the emergency block
        $this->bitek_log_security_event('emergency_block', $reason, array(
            'ip' => $this->get_client_ip(),
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ));

        // Clean output
        if (ob_get_level()) {
            ob_end_clean();
        }

        exit;
    }

    private function bitek_get_default_options()
    {
        return array(
            // Comment filtering
            'comment_filtering' => 1,
            'ai_comment_enabled' => 1,
            'keyword_filtering' => 1,
            'custom_keywords' => implode("\n", $this->default_keywords),
            'blocked_message' => esc_html__('Your comment contains unsafe or spam content and cannot be posted.', 'bitek-ai-security'),

            // AI Settings
            'huggingface_api_key' => '',
            'ai_model_comment' => 'unitary/toxic-bert',
            'ai_model_security' => 'microsoft/DialoGPT-medium',
            'ai_threshold' => 0.7,
            'ai_max_requests_per_hour' => 1000,

            // Firewall Settings
            'firewall_enabled' => 1,
            'block_malicious_ips' => 1,
            'rate_limiting' => 1,
            'brute_force_protection' => 1,
            'sql_injection_protection' => 1,
            'xss_protection' => 1,
            'whitelist_ips' => "127.0.0.1\n::1",

            // Scanner Settings
            'malware_scanner' => 1,
            'file_change_detection' => 1,
            'daily_scan' => 1,
            'scan_core_files' => 1,
            'scan_plugins' => 1,
            'scan_themes' => 1,
            'scan_uploads' => 1,

            // Logging & Monitoring
            'logging_enabled' => 1,
            'log_retention_days' => 30,
            'detailed_logging' => 0,
            'performance_monitoring' => 1,

            // Notifications
            'email_notifications' => 1,
            'admin_email' => get_option('admin_email'),
            'notification_threshold' => 'medium',
            'slack_webhook' => '',

            // Performance & Optimization
            'cache_enabled' => 1,
            'optimization_mode' => 'balanced',
            'max_execution_time' => 30,
            'memory_limit_check' => 1,

            // Advanced Security
            'xmlrpc_enabled' => 0,
            'file_editor_disabled' => 1,
            'hide_wp_version' => 1,
            'disable_file_mods' => 0,
            'force_ssl_admin' => 0,

            // Threat Intelligence
            'threat_feeds_enabled' => 1,
            'auto_update_threats' => 1,
            'threat_feed_sources' => 'malware_domains,phishing_domains,tor_exit_nodes',

            // Emergency Settings
            'emergency_mode' => 0,
            'lockdown_mode' => 0,
            'maintenance_mode' => 0
        );
    }

    public function bitek_scan_comment($commentdata)
    {
        // Skip for administrators
        if (current_user_can('manage_options')) {
            return $commentdata;
        }

        // Check if comment filtering is enabled
        if (!$this->options['comment_filtering']) {
            return $commentdata;
        }

        $comment_content = isset($commentdata['comment_content']) ? $commentdata['comment_content'] : '';
        $comment_author = isset($commentdata['comment_author']) ? $commentdata['comment_author'] : '';
        $comment_email = isset($commentdata['comment_author_email']) ? $commentdata['comment_author_email'] : '';
        $comment_url = isset($commentdata['comment_author_url']) ? $commentdata['comment_author_url'] : '';

        $scan_text = $comment_content . ' ' . $comment_author . ' ' . $comment_url;
        $client_ip = $this->get_client_ip();

        try {
            // Level 1: Fast keyword filtering
            if ($this->options['keyword_filtering']) {
                $blocked_reason = $this->bitek_check_keywords($scan_text);
                if ($blocked_reason) {
                    $this->bitek_log_security_event('comment_blocked', $blocked_reason, array(
                        'ip' => $client_ip,
                        'author' => $comment_author,
                        'email' => $comment_email,
                        'content_length' => strlen($comment_content),
                        'method' => 'keyword'
                    ));

                    wp_die(
                        esc_html($this->options['blocked_message']),
                        esc_html__('Comment Blocked', 'bitek-ai-security'),
                        array('response' => 403, 'back_link' => true)
                    );
                }
            }

            // Level 2: Advanced pattern detection
            $pattern_result = $this->bitek_advanced_pattern_check($scan_text, $client_ip);
            if ($pattern_result['blocked']) {
                $this->bitek_log_security_event('comment_blocked', $pattern_result['reason'], array(
                    'ip' => $client_ip,
                    'author' => $comment_author,
                    'email' => $comment_email,
                    'method' => 'pattern'
                ));

                wp_die(
                    esc_html($this->options['blocked_message']),
                    esc_html__('Comment Blocked', 'bitek-ai-security'),
                    array('response' => 403, 'back_link' => true)
                );
            }

            // Level 3: AI scanning (if enabled and API key available)
            if ($this->options['ai_comment_enabled'] && !empty($this->options['huggingface_api_key'])) {
                $ai_result = $this->bitek_scan_with_ai($scan_text, 'comment');
                if ($ai_result['blocked']) {
                    $this->bitek_log_security_event('ai_comment_blocked', $ai_result['reason'], array(
                        'ip' => $client_ip,
                        'author' => $comment_author,
                        'email' => $comment_email,
                        'confidence' => $ai_result['confidence'] ?? 0,
                        'method' => 'ai'
                    ));

                    wp_die(
                        esc_html($this->options['blocked_message']),
                        esc_html__('Comment Blocked', 'bitek-ai-security'),
                        array('response' => 403, 'back_link' => true)
                    );
                }
            }

            // Log successful comment scan
            if ($this->options['detailed_logging']) {
                $this->bitek_log_security_event('comment_scanned', 'Comment passed security scan', array(
                    'ip' => $client_ip,
                    'author' => $comment_author,
                    'content_length' => strlen($comment_content)
                ));
            }
        } catch (Exception $e) {
            $this->log_error('Comment scanning error: ' . $e->getMessage());

            // In case of error, allow comment but log the issue
            $this->bitek_log_security_event('comment_scan_error', 'Error during comment scan: ' . $e->getMessage(), array(
                'ip' => $client_ip,
                'author' => $comment_author
            ));
        }

        return $commentdata;
    }

    private function bitek_check_keywords($text)
    {
        $keywords = array_filter(array_map('trim', explode("\n", strtolower($this->options['custom_keywords']))));
        $text_lower = strtolower($text);

        // Check exact keyword matches
        foreach ($keywords as $keyword) {
            if (strpos($text_lower, $keyword) !== false) {
                return sprintf(esc_html__('Blocked keyword: %s', 'bitek-ai-security'), $keyword);
            }
        }

        return false;
    }

    private function bitek_advanced_pattern_check($text, $ip)
    {
        $text_lower = strtolower($text);

        // Suspicious patterns with weight scoring
        $patterns = array(
            // Gambling patterns
            '/\b(play|download|install)\s+(smarter|now|today|free)\b/i' => array(
                'weight' => 8,
                'reason' => 'Gambling promotion pattern'
            ),
            '/\b(aviator|crash|mines|plinko)\s+(game|app|download)\b/i' => array(
                'weight' => 9,
                'reason' => 'Casino game promotion'
            ),
            '/\b(bonus\s+code|promo\s+code|welcome\s+bonus)\b/i' => array(
                'weight' => 7,
                'reason' => 'Bonus promotion pattern'
            ),

            // Financial scam patterns
            '/\b(make\s+\$?\d+|earn\s+\$?\d+)\s+(daily|weekly|monthly)\b/i' => array(
                'weight' => 8,
                'reason' => 'Money making scam'
            ),
            '/\b(guaranteed\s+profit|100%\s+profit|risk\s+free)\b/i' => array(
                'weight' => 9,
                'reason' => 'Investment scam pattern'
            ),

            // Urgency tactics
            '/\b(limited\s+time|act\s+now|hurry\s+up|expires\s+soon)\b/i' => array(
                'weight' => 6,
                'reason' => 'Urgency manipulation'
            ),

            // Spam CTAs
            '/\b(click\s+here|visit\s+now|check\s+out|register\s+here)\b/i' => array(
                'weight' => 5,
                'reason' => 'Spam call-to-action'
            ),

            // Security threats
            '/\b(<script|javascript:|vbscript:|onload=|onerror=)\b/i' => array(
                'weight' => 10,
                'reason' => 'XSS attempt detected'
            ),
            '/\b(union\s+select|drop\s+table|insert\s+into|delete\s+from)\b/i' => array(
                'weight' => 10,
                'reason' => 'SQL injection attempt'
            ),

            // URL flooding
            '/https?:\/\/[^\s]+/i' => array(
                'weight' => 3,
                'reason' => 'Contains URL',
                'count_occurrences' => true
            )
        );

        $total_weight = 0;
        $matched_patterns = array();

        foreach ($patterns as $pattern => $config) {
            $matches = preg_match_all($pattern, $text);

            if ($matches > 0) {
                $weight = $config['weight'];

                // Apply multiplier for multiple occurrences if specified
                if (isset($config['count_occurrences']) && $config['count_occurrences']) {
                    $weight *= min($matches, 5); // Cap at 5x multiplier
                }

                $total_weight += $weight;
                $matched_patterns[] = $config['reason'];

                // Immediate block for critical patterns
                if ($weight >= 10) {
                    return array(
                        'blocked' => true,
                        'reason' => $config['reason'],
                        'weight' => $weight
                    );
                }
            }
        }

        // Check IP reputation for additional weight
        $ip_reputation = $this->check_ip_reputation($ip);
        $total_weight += $ip_reputation['weight'];

        // Block if total weight exceeds threshold
        if ($total_weight >= 15) {
            return array(
                'blocked' => true,
                'reason' => 'Multiple suspicious patterns detected: ' . implode(', ', $matched_patterns),
                'weight' => $total_weight
            );
        }

        return array('blocked' => false, 'weight' => $total_weight);
    }

    private function check_ip_reputation($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return array('weight' => 0, 'reason' => 'Invalid IP');
        }

        $weight = 0;
        $reasons = array();

        // Check recent blocks for this IP
        global $wpdb;
        $table_name = $wpdb->prefix . 'bitek_security_logs';

        $recent_blocks = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$table_name}
            WHERE ip = %s 
            AND type LIKE '%blocked%'
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ", $ip));

        if ($recent_blocks > 5) {
            $weight += 8;
            $reasons[] = 'High recent block count';
        } elseif ($recent_blocks > 2) {
            $weight += 4;
            $reasons[] = 'Moderate recent block count';
        }

        // Check if IP is in threat intelligence feeds
        if (isset($this->threat_detector)) {
            $threat_check = $this->threat_detector->is_ip_malicious($ip);
            if ($threat_check['malicious']) {
                $weight += 10;
                $reasons[] = $threat_check['reason'];
            }
        }

        return array(
            'weight' => $weight,
            'reason' => implode(', ', $reasons)
        );
    }

    private function bitek_scan_with_ai($text, $type = 'comment')
    {
        $api_key = sanitize_text_field($this->options['huggingface_api_key']);
        $model = $type === 'comment' ? $this->options['ai_model_comment'] : $this->options['ai_model_security'];
        $threshold = floatval($this->options['ai_threshold']);

        if (empty($api_key) || empty($text)) {
            return array('blocked' => false, 'reason' => 'No API key or empty text');
        }

        // Check API rate limits
        if (!$this->check_api_rate_limit()) {
            return array('blocked' => false, 'reason' => 'API rate limit exceeded');
        }

        $api_url = "https://api-inference.huggingface.co/models/{$model}";

        $args = array(
            'body' => wp_json_encode(array('inputs' => substr($text, 0, 512))), // Limit text length
            'headers' => array(
                'Authorization' => 'Bearer ' . $api_key,
                'Content-Type' => 'application/json',
                'User-Agent' => 'BiTek-AI-Security-Guard/' . BITEK_AI_SECURITY_VERSION
            ),
            'timeout' => 15,
            'method' => 'POST',
            'sslverify' => true
        );

        $response = wp_remote_post($api_url, $args);

        if (is_wp_error($response)) {
            $this->log_error('AI API Error: ' . $response->get_error_message());
            return array('blocked' => false, 'reason' => 'API Connection Error');
        }

        $response_code = wp_remote_retrieve_response_code($response);
        $response_body = wp_remote_retrieve_body($response);

        // Handle different response codes
        if ($response_code === 429) {
            $this->log_error('AI API rate limit exceeded');
            return array('blocked' => false, 'reason' => 'API Rate Limit');
        }

        if ($response_code !== 200) {
            $this->log_error("AI API returned code {$response_code}: {$response_body}");
            return array('blocked' => false, 'reason' => 'API Error');
        }

        $data = json_decode($response_body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->log_error('AI API returned invalid JSON');
            return array('blocked' => false, 'reason' => 'Invalid API Response');
        }

        $analysis_result = $this->bitek_extract_ai_result($data, $threshold);

        // Update API usage counter
        $this->update_api_usage_counter();

        return $analysis_result;
    }

    private function check_api_rate_limit()
    {
        $max_requests = intval($this->options['ai_max_requests_per_hour']);
        $current_hour = date('Y-m-d-H');
        $usage_key = "bitek_ai_usage_{$current_hour}";

        $current_usage = get_transient($usage_key) ?: 0;

        return $current_usage < $max_requests;
    }

    private function update_api_usage_counter()
    {
        $current_hour = date('Y-m-d-H');
        $usage_key = "bitek_ai_usage_{$current_hour}";

        $current_usage = get_transient($usage_key) ?: 0;
        set_transient($usage_key, $current_usage + 1, 3600);
    }

    private function bitek_extract_ai_result($data, $threshold)
    {
        $toxicity_score = 0;
        $confidence = 0;

        if (isset($data[0]) && is_array($data[0])) {
            foreach ($data[0] as $prediction) {
                if (isset($prediction['label']) && isset($prediction['score'])) {
                    $label = strtoupper($prediction['label']);
                    $score = floatval($prediction['score']);

                    // Check for various toxic/harmful labels
                    if (in_array($label, ['TOXIC', 'SPAM', 'HARMFUL', 'NEGATIVE', '1', 'TOXICITY'])) {
                        $toxicity_score = max($toxicity_score, $score);
                        $confidence = $score;
                    }
                }
            }
        } elseif (isset($data['score'])) {
            $toxicity_score = floatval($data['score']);
            $confidence = $toxicity_score;
        }

        if ($toxicity_score >= $threshold) {
            return array(
                'blocked' => true,
                'reason' => sprintf(esc_html__('AI detected harmful content (confidence: %.1f%%)', 'bitek-ai-security'), $confidence * 100),
                'confidence' => $confidence,
                'score' => $toxicity_score
            );
        }

        return array(
            'blocked' => false,
            'reason' => 'Content passed AI analysis',
            'confidence' => $confidence,
            'score' => $toxicity_score
        );
    }

    // Admin interface methods
    public function bitek_add_admin_menu()
    {
        $capability = 'manage_options';

        // Main menu
        add_menu_page(
            esc_html__('BiTek Security', 'bitek-ai-security'),
            esc_html__('BiTek Security', 'bitek-ai-security'),
            $capability,
            'bitek-security',
            array($this, 'bitek_dashboard_page'),
            'dashicons-shield-alt',
            30
        );

        // Submenus
        $submenus = array(
            array(
                'page_title' => esc_html__('Security Dashboard', 'bitek-ai-security'),
                'menu_title' => esc_html__('Dashboard', 'bitek-ai-security'),
                'menu_slug' => 'bitek-security',
                'callback' => array($this, 'bitek_dashboard_page')
            ),
            array(
                'page_title' => esc_html__('Security Logs', 'bitek-ai-security'),
                'menu_title' => esc_html__('Security Logs', 'bitek-ai-security'),
                'menu_slug' => 'bitek-security-logs',
                'callback' => array($this, 'bitek_logs_page')
            ),
            array(
                'page_title' => esc_html__('Security Settings', 'bitek-ai-security'),
                'menu_title' => esc_html__('Settings', 'bitek-ai-security'),
                'menu_slug' => 'bitek-security-settings',
                'callback' => array($this, 'bitek_settings_page')
            ),
            array(
                'page_title' => esc_html__('Security Tools', 'bitek-ai-security'),
                'menu_title' => esc_html__('Tools', 'bitek-ai-security'),
                'menu_slug' => 'bitek-security-tools',
                'callback' => array($this, 'bitek_tools_page')
            )
        );

        foreach ($submenus as $submenu) {
            add_submenu_page(
                'bitek-security',
                $submenu['page_title'],
                $submenu['menu_title'],
                $capability,
                $submenu['menu_slug'],
                $submenu['callback']
            );
        }
    }

    public function bitek_dashboard_page()
    {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'bitek-ai-security'));
        }

        try {
            $stats = isset($this->daily_stats) ? $this->daily_stats->get_dashboard_stats() : $this->get_fallback_stats();
            include BITEK_AI_SECURITY_PLUGIN_DIR . 'templates/dashboard.php';
        } catch (Exception $e) {
            $this->log_error('Dashboard error: ' . $e->getMessage());
            echo '<div class="wrap"><h1>Dashboard Error</h1><p>Unable to load dashboard. Please check the error logs.</p></div>';
        }
    }

    private function get_fallback_stats()
    {
        // Provide basic stats if components fail to load
        return array(
            'high_risk_events' => 0,
            'blocked_requests' => 0,
            'spam_comments' => 0,
            'blocked_ips' => 0,
            'ai_analyzed' => 0,
            'ai_confidence' => 0,
            'recent_events' => array()
        );
    }

    public function bitek_logs_page()
    {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'bitek-ai-security'));
        }

        if (isset($this->logs_page)) {
            $this->logs_page->render_logs_page();
        } else {
            echo '<div class="wrap"><h1>Logs Unavailable</h1><p>Security logs component is not loaded.</p></div>';
        }
    }

    public function bitek_settings_page()
    {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'bitek-ai-security'));
        }

        // Handle settings save
        if (isset($_POST['submit']) && wp_verify_nonce($_POST['_wpnonce'], 'bitek_settings_nonce')) {
            $this->save_settings($_POST['bitek_ai_security_options']);
        }

        include BITEK_AI_SECURITY_PLUGIN_DIR . 'templates/settings.php';
    }

    private function save_settings($new_options)
    {
        // Sanitize and validate options
        $sanitized_options = array();

        foreach ($new_options as $key => $value) {
            switch ($key) {
                case 'huggingface_api_key':
                    $sanitized_options[$key] = sanitize_text_field($value);
                    break;
                case 'custom_keywords':
                    $sanitized_options[$key] = sanitize_textarea_field($value);
                    break;
                case 'blocked_message':
                    $sanitized_options[$key] = sanitize_text_field($value);
                    break;
                case 'ai_threshold':
                    $sanitized_options[$key] = max(0.1, min(1.0, floatval($value)));
                    break;
                case 'log_retention_days':
                    $sanitized_options[$key] = max(1, min(365, intval($value)));
                    break;
                default:
                    if (is_numeric($value)) {
                        $sanitized_options[$key] = intval($value);
                    } else {
                        $sanitized_options[$key] = sanitize_text_field($value);
                    }
                    break;
            }
        }

        $this->options = array_merge($this->options, $sanitized_options);
        update_option('bitek_ai_security_options', $this->options);

        echo '<div class="notice notice-success"><p>' . esc_html__('Settings saved successfully!', 'bitek-ai-security') . '</p></div>';
    }

    public function bitek_tools_page()
    {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'bitek-ai-security'));
        }

        include BITEK_AI_SECURITY_PLUGIN_DIR . 'templates/tools.php';
    }

    // AJAX Handlers
    public function bitek_ajax_get_dashboard_data()
    {
        check_ajax_referer('bitek_ajax_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }

        try {
            $stats = isset($this->daily_stats) ? $this->daily_stats->get_dashboard_stats() : $this->get_fallback_stats();
            wp_send_json_success($stats);
        } catch (Exception $e) {
            $this->log_error('Dashboard AJAX error: ' . $e->getMessage());
            wp_send_json_error('Error loading dashboard data');
        }
    }

    public function bitek_ajax_test_api()
    {
        check_ajax_referer('bitek_ajax_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }

        try {
            $test_result = $this->bitek_scan_with_ai('This is a test message for API connectivity', 'comment');

            if (isset($test_result['reason']) && $test_result['reason'] !== 'No API key or empty text') {
                wp_send_json_success(array(
                    'message' => 'API connection successful',
                    'details' => $test_result
                ));
            } else {
                wp_send_json_error('API test failed: ' . $test_result['reason']);
            }
        } catch (Exception $e) {
            wp_send_json_error('API test failed: ' . $e->getMessage());
        }
    }

    public function bitek_ajax_run_scan()
    {
        check_ajax_referer('bitek_scan_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }

        try {
            if (isset($this->scanner)) {
                $scan_result = $this->scanner->run_full_scan();
                wp_send_json_success($scan_result);
            } else {
                wp_send_json_error('Scanner component not available');
            }
        } catch (Exception $e) {
            $this->log_error('Scan AJAX error: ' . $e->getMessage());
            wp_send_json_error('Scan failed: ' . $e->getMessage());
        }
    }

    // Utility Methods
    public function bitek_log_security_event($type, $message, $data = array())
    {
        if (!$this->options['logging_enabled']) {
            return false;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'bitek_security_logs';

        // Ensure table exists
        if ($wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") !== $table_name) {
            $this->bitek_create_database_tables();
        }

        $log_data = array(
            'type' => sanitize_text_field($type),
            'event' => sanitize_text_field($message),
            'ip' => $this->get_client_ip(),
            'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 255),
            'url' => $_SERVER['REQUEST_URI'] ?? '',
            'data' => wp_json_encode($data),
            'created_at' => current_time('mysql')
        );

        $result = $wpdb->insert(
            $table_name,
            $log_data,
            array('%s', '%s', '%s', '%s', '%s', '%s', '%s')
        );

        return $result !== false;
    }

    private function get_client_ip()
    {
        $ip_keys = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );

        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                $ip_list = $_SERVER[$key];

                if (strpos($ip_list, ',') !== false) {
                    $ip_array = explode(',', $ip_list);
                    $ip = trim($ip_array[0]);
                } else {
                    $ip = trim($ip_list);
                }

                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }

                // For local development, accept private IPs
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function log_error($message)
    {
        if ($this->options['logging_enabled']) {
            $this->bitek_log_security_event('error', $message);
        }

        // Also log to PHP error log for debugging
        error_log("BiTek AI Security: {$message}");
    }

    public function show_admin_notices()
    {
        // Show setup notice if API key is missing
        if (empty($this->options['huggingface_api_key']) && !get_user_meta(get_current_user_id(), 'bitek_dismissed_api_notice', true)) {
            echo '<div class="notice notice-info is-dismissible" data-notice="api_setup">';
            echo '<p><strong>' . esc_html__('BiTek AI Security:', 'bitek-ai-security') . '</strong> ';
            echo esc_html__('For enhanced AI-powered protection, please configure your HuggingFace API key in the settings.', 'bitek-ai-security');
            echo ' <a href="' . esc_url(admin_url('admin.php?page=bitek-security-settings')) . '">' . esc_html__('Configure Now', 'bitek-ai-security') . '</a></p>';
            echo '</div>';
        }

        // Show performance notice if site is slow
        if (isset($this->options['performance_monitoring'])) {
            $avg_response_time = get_transient('bitek_avg_response_time');
            if ($avg_response_time && $avg_response_time > 3000) {
                echo '<div class="notice notice-warning">';
                echo '<p><strong>' . esc_html__('BiTek AI Security:', 'bitek-ai-security') . '</strong> ';
                echo esc_html__('Site performance may be impacted. Consider optimizing security settings.', 'bitek-ai-security');
                echo '</p></div>';
            }
        }
    }

    public function track_performance()
    {
        if (!isset($this->options['performance_monitoring']) || !$this->options['performance_monitoring']) {
            return;
        }

        $execution_time = (microtime(true) - $this->start_time) * 1000;
        $memory_usage = memory_get_peak_usage(true);
        $query_count = get_num_queries() - $this->query_count;

        // Store performance metrics
        $performance_data = get_transient('bitek_performance_data') ?: array();
        $performance_data[] = array(
            'execution_time' => $execution_time,
            'memory_usage' => $memory_usage,
            'query_count' => $query_count,
            'timestamp' => time()
        );

        // Keep only last 100 measurements
        if (count($performance_data) > 100) {
            $performance_data = array_slice($performance_data, -100);
        }

        set_transient('bitek_performance_data', $performance_data, 3600);

        // Calculate averages
        $avg_execution_time = array_sum(array_column($performance_data, 'execution_time')) / count($performance_data);
        set_transient('bitek_avg_response_time', $avg_execution_time, 3600);

        // Alert if performance is degraded
        if ($execution_time > 5000 || $memory_usage > 134217728) { // 5 seconds or 128MB
            $this->bitek_log_security_event(
                'performance_alert',
                "Performance degraded: {$execution_time}ms execution, " . $this->format_bytes($memory_usage) . " memory",
                array(
                    'execution_time' => $execution_time,
                    'memory_usage' => $memory_usage,
                    'query_count' => $query_count
                )
            );
        }
    }

    private function format_bytes($size, $precision = 2)
    {
        $units = array('B', 'KB', 'MB', 'GB', 'TB');

        for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
            $size /= 1024;
        }

        return round($size, $precision) . ' ' . $units[$i];
    }

    // Scheduled task methods
    public function bitek_perform_daily_scan()
    {
        if (!$this->options['daily_scan']) {
            return;
        }

        try {
            if (isset($this->scanner)) {
                $results = $this->scanner->run_daily_scan();

                if ($results['threats_found'] > 0 && $this->options['email_notifications']) {
                    $this->send_security_alert($results);
                }
            }
        } catch (Exception $e) {
            $this->log_error('Daily scan failed: ' . $e->getMessage());
        }
    }

    public function bitek_cleanup_old_logs()
    {
        global $wpdb;

        $retention_days = intval($this->options['log_retention_days']);
        $table_name = $wpdb->prefix . 'bitek_security_logs';

        $deleted = $wpdb->query($wpdb->prepare("
            DELETE FROM {$table_name} 
            WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)
        ", $retention_days));

        if ($deleted > 0) {
            $this->bitek_log_security_event(
                'maintenance',
                "Cleaned up {$deleted} old log entries",
                array('deleted_count' => $deleted, 'retention_days' => $retention_days)
            );
        }
    }

    public function bitek_cleanup_old_stats()
    {
        if (isset($this->daily_stats)) {
            $this->daily_stats->cleanup_old_stats();
        }
    }

    private function send_security_alert($results)
    {
        $admin_email = $this->options['admin_email'] ?: get_option('admin_email');
        $site_name = get_bloginfo('name');
        $site_url = get_site_url();

        $subject = sprintf('[%s] Security Alert - %d Threats Detected', $site_name, $results['threats_found']);

        $message = sprintf(
            "Security Alert for %s\n\n" .
                "A scheduled security scan has detected %d threats on your website.\n\n" .
                "Scan Summary:\n" .
                "- Files scanned: %d\n" .
                "- Threats found: %d\n" .
                "- Scan duration: %s seconds\n\n" .
                "Please log into your WordPress admin panel immediately to review the detailed results:\n" .
                "%s\n\n" .
                "This is an automated message from BiTek AI Security Guard.\n" .
                "Website: %s\n" .
                "Time: %s",
            $site_name,
            $results['threats_found'],
            $results['files_scanned'],
            $results['threats_found'],
            $results['scan_time'],
            admin_url('admin.php?page=bitek-security-logs'),
            $site_url,
            current_time('mysql')
        );

        $headers = array('Content-Type: text/plain; charset=UTF-8');

        wp_mail($admin_email, $subject, $message, $headers);

        // Send to Slack if webhook is configured
        if (!empty($this->options['slack_webhook'])) {
            $this->send_slack_notification($results);
        }
    }

    private function send_slack_notification($results)
    {
        $webhook_url = $this->options['slack_webhook'];
        $site_name = get_bloginfo('name');

        $payload = array(
            'text' => sprintf(
                ':warning: Security Alert: %d threats detected on %s',
                $results['threats_found'],
                $site_name
            ),
            'attachments' => array(
                array(
                    'color' => 'danger',
                    'fields' => array(
                        array(
                            'title' => 'Files Scanned',
                            'value' => $results['files_scanned'],
                            'short' => true
                        ),
                        array(
                            'title' => 'Threats Found',
                            'value' => $results['threats_found'],
                            'short' => true
                        ),
                        array(
                            'title' => 'Scan Duration',
                            'value' => $results['scan_time'] . ' seconds',
                            'short' => true
                        )
                    ),
                    'actions' => array(
                        array(
                            'type' => 'button',
                            'text' => 'View Details',
                            'url' => admin_url('admin.php?page=bitek-security-logs')
                        )
                    )
                )
            )
        );

        wp_remote_post($webhook_url, array(
            'body' => wp_json_encode($payload),
            'headers' => array('Content-Type' => 'application/json'),
            'timeout' => 10
        ));
    }

    // Installation and activation methods
    public function bitek_activate()
    {
        // Check requirements again during activation
        if (!$this->check_requirements()) {
            deactivate_plugins(plugin_basename(__FILE__));
            wp_die(__('BiTek AI Security Guard activation failed due to unmet requirements.', 'bitek-ai-security'));
        }

        // Create database tables
        $this->bitek_create_database_tables();

        // Schedule cron events
        if (!wp_next_scheduled('bitek_daily_scan')) {
            wp_schedule_event(time(), 'daily', 'bitek_daily_scan');
        }

        if (!wp_next_scheduled('bitek_cleanup_logs')) {
            wp_schedule_event(time(), 'weekly', 'bitek_cleanup_logs');
        }

        if (!wp_next_scheduled('bitek_cleanup_stats')) {
            wp_schedule_event(time(), 'daily', 'bitek_cleanup_stats');
        }

        // Create default options
        add_option('bitek_ai_security_options', $this->bitek_get_default_options());

        // Create logs directory with security
        $this->create_secure_logs_directory();

        // Set activation flag
        update_option('bitek_ai_security_activated', time());

        // Log activation
        $this->bitek_log_security_event('system', 'BiTek AI Security Guard activated', array(
            'version' => BITEK_AI_SECURITY_VERSION,
            'php_version' => PHP_VERSION,
            'wp_version' => get_bloginfo('version')
        ));

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    public function bitek_deactivate()
    {
        // Clear scheduled events
        wp_clear_scheduled_hook('bitek_daily_scan');
        wp_clear_scheduled_hook('bitek_cleanup_logs');
        wp_clear_scheduled_hook('bitek_cleanup_stats');

        // Clear all transients
        $this->clear_all_transients();

        // Log deactivation
        $this->bitek_log_security_event('system', 'BiTek AI Security Guard deactivated');

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    private function create_secure_logs_directory()
    {
        $log_dir = BITEK_AI_SECURITY_PLUGIN_DIR . 'logs';

        if (!file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
        }

        // Create .htaccess for security
        $htaccess_content = "Order deny,allow\nDeny from all\n<Files ~ \"\\.(log|txt)$\">\nDeny from all\n</Files>";
        file_put_contents($log_dir . '/.htaccess', $htaccess_content);

        // Create index.php for additional security
        file_put_contents($log_dir . '/index.php', "<?php\n// Silence is golden\n");

        // Create web.config for IIS
        $webconfig_content = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n    <system.webServer>\n        <authorization>\n            <deny users=\"*\" />\n        </authorization>\n    </system.webServer>\n</configuration>";
        file_put_contents($log_dir . '/web.config', $webconfig_content);
    }

    private function clear_all_transients()
    {
        global $wpdb;

        // Clear BiTek-specific transients
        $wpdb->query("
            DELETE FROM {$wpdb->options}
            WHERE option_name LIKE '_transient_bitek_%'
            OR option_name LIKE '_transient_timeout_bitek_%'
        ");
    }

    private function bitek_create_database_tables()
    {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        $tables = array();

        // Security logs table
        $tables[] = "CREATE TABLE {$wpdb->prefix}bitek_security_logs (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            type varchar(50) NOT NULL DEFAULT 'unknown',
            event text NOT NULL,
            ip varchar(45) NOT NULL DEFAULT 'Unknown',
            user_agent text,
            url text,
            data longtext,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY type (type),
            KEY ip (ip),
            KEY created_at (created_at),
            KEY type_created (type, created_at)
        ) $charset_collate;";

        // Blocked IPs table
        $tables[] = "CREATE TABLE {$wpdb->prefix}bitek_blocked_ips (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip varchar(45) NOT NULL,
            reason text,
            blocked_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at datetime,
            is_permanent tinyint(1) DEFAULT 0,
            block_count int(11) DEFAULT 1,
            last_attempt datetime,
            PRIMARY KEY (id),
            UNIQUE KEY ip (ip),
            KEY blocked_at (blocked_at),
            KEY expires_at (expires_at)
        ) $charset_collate;";

        // File integrity table
        $tables[] = "CREATE TABLE {$wpdb->prefix}bitek_file_integrity (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path text NOT NULL,
            file_hash varchar(64) NOT NULL,
            file_size bigint(20) NOT NULL,
            last_modified datetime NOT NULL,
            checked_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status enum('clean','modified','suspicious') DEFAULT 'clean',
            PRIMARY KEY (id),
            KEY checked_at (checked_at),
            KEY status (status)
        ) $charset_collate;";

        // Performance metrics table
        $tables[] = "CREATE TABLE {$wpdb->prefix}bitek_performance_metrics (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            metric_type varchar(50) NOT NULL,
            metric_value decimal(10,4) NOT NULL,
            recorded_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            additional_data text,
            PRIMARY KEY (id),
            KEY metric_type (metric_type),
            KEY recorded_at (recorded_at)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        foreach ($tables as $table_sql) {
            dbDelta($table_sql);
        }

        // Update database version
        update_option('bitek_ai_security_db_version', BITEK_AI_SECURITY_DB_VERSION);
    }

    // Internationalization
    public function bitek_load_textdomain()
    {
        load_plugin_textdomain(
            'bitek-ai-security',
            false,
            dirname(plugin_basename(__FILE__)) . '/languages'
        );
    }

    // Admin scripts and styles
    public function bitek_admin_init()
    {
        register_setting('bitek_ai_security_group', 'bitek_ai_security_options');

        // Add settings sections and fields here if needed
        $this->register_settings_sections();
    }

    private function register_settings_sections()
    {
        // This method can be expanded to register WordPress Settings API sections
        // For now, we handle settings manually in the settings page
    }

    public function bitek_admin_scripts($hook)
    {
        // Only load on BiTek security pages
        if (strpos($hook, 'bitek-security') === false) {
            return;
        }

        // Enqueue styles
        wp_enqueue_style(
            'bitek-ai-security-admin',
            BITEK_AI_SECURITY_PLUGIN_URL . 'assets/admin.css',
            array(),
            BITEK_AI_SECURITY_VERSION
        );

        // Enqueue scripts
        wp_enqueue_script(
            'bitek-ai-security-admin',
            BITEK_AI_SECURITY_PLUGIN_URL . 'assets/admin.js',
            array('jquery'),
            BITEK_AI_SECURITY_VERSION,
            true
        );

        // Localize script with data
        wp_localize_script('bitek-ai-security-admin', 'bitekAjax', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('bitek_ajax_nonce'),
            'scanNonce' => wp_create_nonce('bitek_scan_nonce'),
            'emergencyNonce' => wp_create_nonce('bitek_emergency_nonce'),
            'settingsUrl' => admin_url('admin.php?page=bitek-security-settings'),
            'pluginVersion' => BITEK_AI_SECURITY_VERSION,
            'strings' => array(
                'confirmEmergencyMode' => __('Emergency mode will enable maximum security settings and may affect site functionality. Continue?', 'bitek-ai-security'),
                'confirmClearLogs' => __('Are you sure you want to clear all security logs? This action cannot be undone.', 'bitek-ai-security'),
                'scanCompleted' => __('Security scan completed successfully!', 'bitek-ai-security'),
                'scanFailed' => __('Security scan failed. Please try again.', 'bitek-ai-security'),
                'apiTestSuccess' => __('API connection successful!', 'bitek-ai-security'),
                'apiTestFailed' => __('API connection failed. Please check your settings.', 'bitek-ai-security')
            )
        ));

        // Enqueue WordPress media uploader if needed
        if (in_array($hook, array('bitek-security_page_bitek-security-settings'))) {
            wp_enqueue_media();
        }
    }

    // Additional AJAX handlers for remaining functionality
    public function bitek_ajax_run_full_scan()
    {
        check_ajax_referer('bitek_scan_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }

        try {
            // Set time limit for long-running scan
            if (!ini_get('safe_mode')) {
                set_time_limit(300); // 5 minutes
            }

            if (isset($this->scanner)) {
                $scan_result = $this->scanner->run_full_scan();
                wp_send_json_success($scan_result);
            } else {
                wp_send_json_error('Scanner component not available');
            }
        } catch (Exception $e) {
            $this->log_error('Full scan error: ' . $e->getMessage());
            wp_send_json_error('Full scan failed: ' . $e->getMessage());
        }
    }

    public function bitek_ajax_refresh_threats()
    {
        check_ajax_referer('bitek_ajax_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }

        try {
            if (isset($this->threat_detector)) {
                $this->threat_detector->update_threat_intelligence();
                wp_send_json_success('Threat intelligence updated successfully');
            } else {
                wp_send_json_error('Threat detector component not available');
            }
        } catch (Exception $e) {
            wp_send_json_error('Failed to update threats: ' . $e->getMessage());
        }
    }

    public function bitek_ajax_emergency_mode()
    {
        check_ajax_referer('bitek_emergency_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }

        try {
            // Enable emergency mode settings
            $emergency_options = array(
                'firewall_enabled' => 1,
                'rate_limiting' => 1,
                'brute_force_protection' => 1,
                'sql_injection_protection' => 1,
                'xss_protection' => 1,
                'ai_comment_enabled' => 1,
                'ai_threshold' => 0.5,
                'malware_scanner' => 1,
                'file_change_detection' => 1,
                'emergency_mode' => 1,
                'detailed_logging' => 1
            );

            $this->options = array_merge($this->options, $emergency_options);
            update_option('bitek_ai_security_options', $this->options);

            $this->bitek_log_security_event('system', 'Emergency lockdown mode activated', array(
                'activated_by' => get_current_user_id(),
                'user_ip' => $this->get_client_ip()
            ));

            wp_send_json_success('Emergency mode activated successfully');
        } catch (Exception $e) {
            wp_send_json_error('Failed to activate emergency mode: ' . $e->getMessage());
        }
    }

    // Placeholder methods for remaining AJAX handlers
    public function bitek_ajax_get_logs()
    {
        // Delegate to logs page component
        if (isset($this->logs_page)) {
            $this->logs_page->ajax_get_logs();
        } else {
            wp_send_json_error('Logs component not available');
        }
    }

    public function bitek_ajax_get_log_details()
    {
        // Delegate to logs page component
        if (isset($this->logs_page)) {
            $this->logs_page->ajax_get_log_details();
        } else {
            wp_send_json_error('Logs component not available');
        }
    }

    public function bitek_ajax_block_ip()
    {
        // Delegate to logs page component
        if (isset($this->logs_page)) {
            $this->logs_page->ajax_block_ip();
        } else {
            wp_send_json_error('Logs component not available');
        }
    }

    public function bitek_ajax_clear_logs()
    {
        // Delegate to logs page component
        if (isset($this->logs_page)) {
            $this->logs_page->ajax_clear_logs();
        } else {
            wp_send_json_error('Logs component not available');
        }
    }

    public function bitek_ajax_export_logs()
    {
        // Delegate to logs page component
        if (isset($this->logs_page)) {
            $this->logs_page->ajax_export_logs();
        } else {
            wp_die('Logs component not available');
        }
    }

    // Health check and system status
    public function get_system_status()
    {
        return array(
            'wordpress_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'plugin_version' => BITEK_AI_SECURITY_VERSION,
            'database_version' => get_option('bitek_ai_security_db_version'),
            'memory_limit' => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time'),
            'components_loaded' => array(
                'firewall' => isset($this->firewall),
                'scanner' => isset($this->scanner),
                'threat_detector' => isset($this->threat_detector),
                'daily_stats' => isset($this->daily_stats),
                'logs_page' => isset($this->logs_page)
            ),
            'options_count' => count($this->options),
            'last_scan' => get_option('bitek_last_scan_time'),
            'api_configured' => !empty($this->options['huggingface_api_key'])
        );
    }
}

// Initialize the plugin
function bitek_ai_security_guard_init()
{
    BiTek_AI_Security_Guard::get_instance();
}

// Hook into plugins_loaded with high priority to ensure early initialization
add_action('plugins_loaded', 'bitek_ai_security_guard_init', 1);

// Uninstall hook
register_uninstall_hook(__FILE__, 'bitek_ai_security_uninstall');

function bitek_ai_security_uninstall()
{
    global $wpdb;

    // Remove options
    delete_option('bitek_ai_security_options');
    delete_option('bitek_ai_security_db_version');
    delete_option('bitek_ai_security_activated');
    delete_option('bitek_last_scan_time');

    // Remove user meta
    delete_metadata('user', 0, 'bitek_dismissed_api_notice', '', true);
    delete_metadata('user', 0, 'bitek_last_login_ip', '', true);
    delete_metadata('user', 0, 'bitek_last_login_time', '', true);

    // Remove database tables
    $tables = array(
        $wpdb->prefix . 'bitek_security_logs',
        $wpdb->prefix . 'bitek_blocked_ips',
        $wpdb->prefix . 'bitek_file_integrity',
        $wpdb->prefix . 'bitek_performance_metrics'
    );

    foreach ($tables as $table) {
        $wpdb->query("DROP TABLE IF EXISTS $table");
    }

    // Remove all transients
    $wpdb->query("
        DELETE FROM {$wpdb->options}
        WHERE option_name LIKE '_transient_bitek_%'
        OR option_name LIKE '_transient_timeout_bitek_%'
    ");

    // Remove log files and directory
    $log_dir = plugin_dir_path(__FILE__) . 'logs';
    if (file_exists($log_dir)) {
        $files = glob($log_dir . '/*');
        foreach ($files as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        rmdir($log_dir);
    }

    // Clear scheduled events
    wp_clear_scheduled_hook('bitek_daily_scan');
    wp_clear_scheduled_hook('bitek_cleanup_logs');
    wp_clear_scheduled_hook('bitek_cleanup_stats');

    // Clear any cached data
    if (function_exists('wp_cache_flush')) {
        wp_cache_flush();
    }
}

// Development and debugging helpers (only in debug mode)
if (defined('WP_DEBUG') && WP_DEBUG) {

    // Add debug information to admin footer
    add_action('admin_footer', function () {
        if (current_user_can('manage_options') && isset($_GET['page']) && strpos($_GET['page'], 'bitek-security') !== false) {
            $instance = BiTek_AI_Security_Guard::get_instance();
            $status = $instance->get_system_status();

            echo '<div style="margin-top: 20px; padding: 10px; background: #f1f1f1; border: 1px solid #ccc;">';
            echo '<strong>BiTek Debug Info:</strong><br>';
            echo 'Components Loaded: ' . wp_json_encode($status['components_loaded']) . '<br>';
            echo 'Memory Usage: ' . number_format(memory_get_usage(true) / 1024 / 1024, 2) . ' MB<br>';
            echo 'Database Queries: ' . get_num_queries() . '<br>';
            echo '</div>';
        }
    });

    // Add WP-CLI commands if WP-CLI is available
    if (defined('WP_CLI') && WP_CLI) {
        require_once __DIR__ . '/includes/class-wp-cli-commands.php';
    }
}
