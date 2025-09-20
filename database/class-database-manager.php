<?php
/**
 * SecureAura Database Manager
 *
 * Handles all database operations for the plugin
 *
 * @package    SecureAura
 * @subpackage SecureAura/database
 * @since      3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * SecureAura Database Manager Class
 *
 * This class manages all database operations including:
 * - CRUD operations for security data
 * - Event logging
 * - Data cleanup and maintenance
 * - Performance optimization
 *
 * @since      3.0.0
 * @package    SecureAura
 * @subpackage SecureAura/database
 * @author     Bitekservices
 */
class Secure_Aura_Database_Manager {

    /**
     * WordPress database instance.
     *
     * @since    3.0.0
     * @access   private
     * @var      wpdb    $wpdb    WordPress database instance.
     */
    private $wpdb;

    /**
     * Database table names.
     *
     * @since    3.0.0
     * @access   private
     * @var      array    $tables    Array of table names.
     */
    private $tables;

    /**
     * Database charset and collation.
     *
     * @since    3.0.0
     * @access   private
     * @var      string    $charset_collate    Database charset and collation.
     */
    private $charset_collate;

    /**
     * Initialize the database manager.
     *
     * @since    3.0.0
     */
    public function __construct() {
        global $wpdb;
        
        $this->wpdb = $wpdb;
        $this->charset_collate = $this->wpdb->get_charset_collate();
        
        // Initialize table names
        $this->tables = [
            'logs' => $this->wpdb->prefix . SECURE_AURA_TABLE_LOGS,
            'threats' => $this->wpdb->prefix . SECURE_AURA_TABLE_THREATS,
            'behavioral' => $this->wpdb->prefix . SECURE_AURA_TABLE_BEHAVIORAL,
            'file_integrity' => $this->wpdb->prefix . SECURE_AURA_TABLE_FILE_INTEGRITY,
            'blocked_ips' => $this->wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS,
            'whitelist' => $this->wpdb->prefix . SECURE_AURA_TABLE_WHITELIST,
            'quarantine' => $this->wpdb->prefix . SECURE_AURA_TABLE_QUARANTINE,
            'incident_reports' => $this->wpdb->prefix . SECURE_AURA_TABLE_INCIDENT_REPORTS,
            'compliance_logs' => $this->wpdb->prefix . SECURE_AURA_TABLE_COMPLIANCE_LOGS,
            'performance_metrics' => $this->wpdb->prefix . SECURE_AURA_TABLE_PERFORMANCE_METRICS,
        ];
    }

    /**
     * Log security event.
     *
     * @since    3.0.0
     * @param    string $event_type    Type of event.
     * @param    array  $event_data    Event data.
     * @param    string $severity      Event severity (low, medium, high, critical).
     * @param    string $ip_address    IP address (optional).
     * @return   int|false             Insert ID on success, false on failure.
     */
    public function log_event($event_type, $event_data = [], $severity = 'medium', $ip_address = null) {
        if ($ip_address === null) {
            $ip_address = $this->get_client_ip();
        }
        
        $result = $this->wpdb->insert(
            $this->tables['logs'],
            [
                'event_type' => sanitize_text_field($event_type),
                'ip_address' => sanitize_text_field($ip_address),
                'user_id' => get_current_user_id(),
                'event_data' => wp_json_encode($event_data),
                'severity' => sanitize_text_field($severity),
                'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
                'request_uri' => substr($_SERVER['REQUEST_URI'] ?? '', 0, 500),
                'response_action' => $this->determine_response_action($event_type, $severity),
                'created_at' => current_time('mysql'),
            ],
            ['%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s']
        );
        
        if ($result) {
            return $this->wpdb->insert_id;
        }
        
        return false;
    }

    /**
     * Create threat record.
     *
     * @since    3.0.0
     * @param    array $threat_data Threat data.
     * @return   int|false          Insert ID on success, false on failure.
     */
    public function create_threat($threat_data) {
        $defaults = [
            'threat_type' => 'unknown',
            'severity' => 'medium',
            'status' => 'active',
            'file_path' => '',
            'file_hash' => '',
            'threat_signature' => '',
            'detection_method' => 'manual',
            'false_positive' => 0,
            'quarantined' => 0,
            'detection_count' => 1,
            'first_detected' => current_time('mysql'),
            'last_detected' => current_time('mysql'),
            'created_at' => current_time('mysql'),
        ];
        
        $threat_data = wp_parse_args($threat_data, $defaults);
        
        // Sanitize data
        $sanitized_data = [
            'threat_type' => sanitize_text_field($threat_data['threat_type']),
            'severity' => sanitize_text_field($threat_data['severity']),
            'status' => sanitize_text_field($threat_data['status']),
            'file_path' => sanitize_text_field($threat_data['file_path']),
            'file_hash' => sanitize_text_field($threat_data['file_hash']),
            'threat_signature' => sanitize_textarea_field($threat_data['threat_signature']),
            'detection_method' => sanitize_text_field($threat_data['detection_method']),
            'false_positive' => intval($threat_data['false_positive']),
            'quarantined' => intval($threat_data['quarantined']),
            'detection_count' => intval($threat_data['detection_count']),
            'first_detected' => $threat_data['first_detected'],
            'last_detected' => $threat_data['last_detected'],
            'created_at' => $threat_data['created_at'],
        ];
        
        $result = $this->wpdb->insert(
            $this->tables['threats'],
            $sanitized_data,
            ['%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%s', '%s', '%s']
        );
        
        if ($result) {
            // Log threat creation
            $this->log_event('threat_created', [
                'threat_id' => $this->wpdb->insert_id,
                'threat_type' => $sanitized_data['threat_type'],
                'file_path' => $sanitized_data['file_path'],
            ], $sanitized_data['severity']);
            
            return $this->wpdb->insert_id;
        }
        
        return false;
    }

    /**
     * Update threat record.
     *
     * @since    3.0.0
     * @param    int   $threat_id   Threat ID.
     * @param    array $update_data Data to update.
     * @return   bool               True on success, false on failure.
     */
    public function update_threat($threat_id, $update_data) {
        $threat_id = intval($threat_id);
        
        if ($threat_id <= 0) {
            return false;
        }
        
        // Add updated_at timestamp
        $update_data['updated_at'] = current_time('mysql');
        
        // Sanitize update data
        $sanitized_data = [];
        foreach ($update_data as $key => $value) {
            switch ($key) {
                case 'threat_type':
                case 'severity':
                case 'status':
                case 'file_path':
                case 'file_hash':
                case 'detection_method':
                    $sanitized_data[$key] = sanitize_text_field($value);
                    break;
                case 'threat_signature':
                    $sanitized_data[$key] = sanitize_textarea_field($value);
                    break;
                case 'false_positive':
                case 'quarantined':
                case 'detection_count':
                    $sanitized_data[$key] = intval($value);
                    break;
                case 'first_detected':
                case 'last_detected':
                case 'updated_at':
                    $sanitized_data[$key] = $value;
                    break;
            }
        }
        
        $result = $this->wpdb->update(
            $this->tables['threats'],
            $sanitized_data,
            ['id' => $threat_id],
            array_fill(0, count($sanitized_data), '%s'),
            ['%d']
        );
        
        if ($result !== false) {
            // Log threat update
            $this->log_event('threat_updated', [
                'threat_id' => $threat_id,
                'updated_fields' => array_keys($sanitized_data),
            ], 'low');
            
            return true;
        }
        
        return false;
    }

    /**
     * Get threat by ID.
     *
     * @since    3.0.0
     * @param    int $threat_id Threat ID.
     * @return   object|null    Threat object or null if not found.
     */
    public function get_threat($threat_id) {
        $threat_id = intval($threat_id);
        
        if ($threat_id <= 0) {
            return null;
        }
        
        return $this->wpdb->get_row($this->wpdb->prepare(
            "SELECT * FROM {$this->tables['threats']} WHERE id = %d",
            $threat_id
        ));
    }

    /**
     * Get threats with filters.
     *
     * @since    3.0.0
     * @param    array $args Query arguments.
     * @return   array       Array of threat objects.
     */
    public function get_threats($args = []) {
        $defaults = [
            'status' => '',
            'threat_type' => '',
            'severity' => '',
            'limit' => 50,
            'offset' => 0,
            'order_by' => 'last_detected',
            'order' => 'DESC',
            'date_from' => '',
            'date_to' => '',
        ];
        
        $args = wp_parse_args($args, $defaults);
        
        $where_clauses = ['1=1'];
        $where_values = [];
        
        if (!empty($args['status'])) {
            $where_clauses[] = 'status = %s';
            $where_values[] = $args['status'];
        }
        
        if (!empty($args['threat_type'])) {
            $where_clauses[] = 'threat_type = %s';
            $where_values[] = $args['threat_type'];
        }
        
        if (!empty($args['severity'])) {
            $where_clauses[] = 'severity = %s';
            $where_values[] = $args['severity'];
        }
        
        if (!empty($args['date_from'])) {
            $where_clauses[] = 'created_at >= %s';
            $where_values[] = $args['date_from'];
        }
        
        if (!empty($args['date_to'])) {
            $where_clauses[] = 'created_at <= %s';
            $where_values[] = $args['date_to'];
        }
        
        $where_sql = implode(' AND ', $where_clauses);
        $order_by = sanitize_sql_orderby($args['order_by']);
        $order = in_array(strtoupper($args['order']), ['ASC', 'DESC']) ? strtoupper($args['order']) : 'DESC';
        $limit = intval($args['limit']);
        $offset = intval($args['offset']);
        
        $sql = "SELECT * FROM {$this->tables['threats']} 
                WHERE {$where_sql} 
                ORDER BY {$order_by} {$order} 
                LIMIT {$limit} OFFSET {$offset}";
        
        if (!empty($where_values)) {
            return $this->wpdb->get_results($this->wpdb->prepare($sql, $where_values));
        } else {
            return $this->wpdb->get_results($sql);
        }
    }

    /**
     * Block IP address.
     *
     * @since    3.0.0
     * @param    string $ip_address IP address to block.
     * @param    array  $block_data Block data.
     * @return   int|false          Insert ID on success, false on failure.
     */
    public function block_ip($ip_address, $block_data = []) {
        // Validate IP address
        if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        // Check if IP is already blocked
        if ($this->is_ip_blocked($ip_address)) {
            return false;
        }
        
        $defaults = [
            'reason' => __('Blocked by security system', 'secure-aura'),
            'blocked_by_user_id' => get_current_user_id(),
            'is_active' => 1,
            'is_permanent' => 0,
            'expires_at' => null,
            'threat_type' => 'suspicious_activity',
            'block_count' => 1,
        ];
        
        $block_data = wp_parse_args($block_data, $defaults);
        
        $result = $this->wpdb->insert(
            $this->tables['blocked_ips'],
            [
                'ip_address' => $ip_address,
                'reason' => sanitize_text_field($block_data['reason']),
                'blocked_by_user_id' => intval($block_data['blocked_by_user_id']),
                'is_active' => intval($block_data['is_active']),
                'is_permanent' => intval($block_data['is_permanent']),
                'expires_at' => $block_data['expires_at'],
                'threat_type' => sanitize_text_field($block_data['threat_type']),
                'block_count' => intval($block_data['block_count']),
                'blocked_at' => current_time('mysql'),
            ],
            ['%s', '%s', '%d', '%d', '%d', '%s', '%s', '%d', '%s']
        );
        
        if ($result) {
            // Log IP block
            $this->log_event('ip_blocked', [
                'ip_address' => $ip_address,
                'reason' => $block_data['reason'],
                'is_permanent' => $block_data['is_permanent'],
            ], 'medium');
            
            return $this->wpdb->insert_id;
        }
        
        return false;
    }

    /**
     * Unblock IP address.
     *
     * @since    3.0.0
     * @param    string $ip_address IP address to unblock.
     * @return   bool               True on success, false on failure.
     */
    public function unblock_ip($ip_address) {
        if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        $result = $this->wpdb->update(
            $this->tables['blocked_ips'],
            [
                'is_active' => 0,
                'unblocked_at' => current_time('mysql'),
                'unblocked_by_user_id' => get_current_user_id(),
            ],
            [
                'ip_address' => $ip_address,
                'is_active' => 1,
            ],
            ['%d', '%s', '%d'],
            ['%s', '%d']
        );
        
        if ($result) {
            // Log IP unblock
            $this->log_event('ip_unblocked', [
                'ip_address' => $ip_address,
            ], 'low');
            
            return true;
        }
        
        return false;
    }

    /**
     * Check if IP is blocked.
     *
     * @since    3.0.0
     * @param    string $ip_address IP address to check.
     * @return   bool               True if blocked, false otherwise.
     */
    public function is_ip_blocked($ip_address) {
        if (!filter_var($ip_address, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        $count = $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->tables['blocked_ips']} 
             WHERE ip_address = %s AND is_active = 1 
             AND (expires_at IS NULL OR expires_at > NOW())",
            $ip_address
        ));
        
        return intval($count) > 0;
    }

    /**
     * Get blocked IPs.
     *
     * @since    3.0.0
     * @param    array $args Query arguments.
     * @return   array       Array of blocked IP objects.
     */
    public function get_blocked_ips($args = []) {
        $defaults = [
            'is_active' => 1,
            'limit' => 100,
            'offset' => 0,
            'order_by' => 'blocked_at',
            'order' => 'DESC',
        ];
        
        $args = wp_parse_args($args, $defaults);
        
        $where_clauses = [];
        $where_values = [];
        
        if ($args['is_active'] !== '') {
            $where_clauses[] = 'is_active = %d';
            $where_values[] = intval($args['is_active']);
        }
        
        $where_sql = !empty($where_clauses) ? 'WHERE ' . implode(' AND ', $where_clauses) : '';
        $order_by = sanitize_sql_orderby($args['order_by']);
        $order = in_array(strtoupper($args['order']), ['ASC', 'DESC']) ? strtoupper($args['order']) : 'DESC';
        $limit = intval($args['limit']);
        $offset = intval($args['offset']);
        
        $sql = "SELECT * FROM {$this->tables['blocked_ips']} 
                {$where_sql} 
                ORDER BY {$order_by} {$order} 
                LIMIT {$limit} OFFSET {$offset}";
        
        if (!empty($where_values)) {
            return $this->wpdb->get_results($this->wpdb->prepare($sql, $where_values));
        } else {
            return $this->wpdb->get_results($sql);
        }
    }

    /**
     * Add to whitelist.
     *
     * @since    3.0.0
     * @param    string $entry_type  Type of entry (ip, domain, email, etc.).
     * @param    string $entry_value Entry value.
     * @param    array  $data        Additional data.
     * @return   int|false           Insert ID on success, false on failure.
     */
    public function add_to_whitelist($entry_type, $entry_value, $data = []) {
        $defaults = [
            'whitelist_reason' => __('Added by admin', 'secure-aura'),
            'added_by_user_id' => get_current_user_id(),
            'is_active' => 1,
            'expires_at' => null,
            'usage_count' => 0,
            'tags' => '',
            'notes' => '',
        ];
        
        $data = wp_parse_args($data, $defaults);
        
        // Check if entry already exists
        $existing = $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT id FROM {$this->tables['whitelist']} 
             WHERE entry_type = %s AND entry_value = %s AND is_active = 1",
            $entry_type,
            $entry_value
        ));
        
        if ($existing) {
            return false; // Already whitelisted
        }
        
        $result = $this->wpdb->insert(
            $this->tables['whitelist'],
            [
                'entry_type' => sanitize_text_field($entry_type),
                'entry_value' => sanitize_text_field($entry_value),
                'whitelist_reason' => sanitize_text_field($data['whitelist_reason']),
                'added_by_user_id' => intval($data['added_by_user_id']),
                'is_active' => intval($data['is_active']),
                'expires_at' => $data['expires_at'],
                'usage_count' => intval($data['usage_count']),
                'tags' => sanitize_text_field($data['tags']),
                'notes' => sanitize_textarea_field($data['notes']),
                'created_at' => current_time('mysql'),
            ],
            ['%s', '%s', '%s', '%d', '%d', '%s', '%d', '%s', '%s', '%s']
        );
        
        if ($result) {
            // Log whitelist addition
            $this->log_event('whitelist_added', [
                'entry_type' => $entry_type,
                'entry_value' => $entry_value,
                'reason' => $data['whitelist_reason'],
            ], 'low');
            
            return $this->wpdb->insert_id;
        }
        
        return false;
    }

    /**
     * Check if entry is whitelisted.
     *
     * @since    3.0.0
     * @param    string $entry_type  Entry type.
     * @param    string $entry_value Entry value.
     * @return   bool                True if whitelisted, false otherwise.
     */
    public function is_whitelisted($entry_type, $entry_value) {
        $count = $this->wpdb->get_var($this->wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->tables['whitelist']} 
             WHERE entry_type = %s AND entry_value = %s AND is_active = 1 
             AND (expires_at IS NULL OR expires_at > NOW())",
            $entry_type,
            $entry_value
        ));
        
        if (intval($count) > 0) {
            // Update usage count
            $this->wpdb->query($this->wpdb->prepare(
                "UPDATE {$this->tables['whitelist']} 
                 SET usage_count = usage_count + 1, last_used = NOW() 
                 WHERE entry_type = %s AND entry_value = %s AND is_active = 1",
                $entry_type,
                $entry_value
            ));
            
            return true;
        }
        
        return false;
    }

    /**
     * Record behavioral data.
     *
     * @since    3.0.0
     * @param    array $behavioral_data Behavioral data.
     * @return   int|false              Insert ID on success, false on failure.
     */
    public function record_behavioral_data($behavioral_data) {
        $defaults = [
            'ip_address' => $this->get_client_ip(),
            'user_id' => get_current_user_id(),
            'session_id' => '',
            'page_url' => $_SERVER['REQUEST_URI'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'action_type' => 'page_view',
            'action_data' => [],
            'risk_level' => 'low',
            'anomaly_score' => 0.0,
            'is_bot' => 0,
            'bot_confidence' => 0.0,
            'device_fingerprint' => '',
            'geolocation_data' => [],
        ];
        
        $behavioral_data = wp_parse_args($behavioral_data, $defaults);
        
        $result = $this->wpdb->insert(
            $this->tables['behavioral'],
            [
                'ip_address' => sanitize_text_field($behavioral_data['ip_address']),
                'user_id' => intval($behavioral_data['user_id']),
                'session_id' => sanitize_text_field($behavioral_data['session_id']),
                'page_url' => sanitize_text_field($behavioral_data['page_url']),
                'user_agent' => substr($behavioral_data['user_agent'], 0, 500),
                'action_type' => sanitize_text_field($behavioral_data['action_type']),
                'action_data' => wp_json_encode($behavioral_data['action_data']),
                'risk_level' => sanitize_text_field($behavioral_data['risk_level']),
                'anomaly_score' => floatval($behavioral_data['anomaly_score']),
                'is_bot' => intval($behavioral_data['is_bot']),
                'bot_confidence' => floatval($behavioral_data['bot_confidence']),
                'device_fingerprint' => sanitize_text_field($behavioral_data['device_fingerprint']),
                'geolocation_data' => wp_json_encode($behavioral_data['geolocation_data']),
                'timestamp' => current_time('mysql'),
            ],
            ['%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%f', '%d', '%f', '%s', '%s', '%s']
        );
        
        return $result ? $this->wpdb->insert_id : false;
    }

    /**
     * Get security logs.
     *
     * @since    3.0.0
     * @param    array $args Query arguments.
     * @return   array       Array of log objects.
     */
    public function get_logs($args = []) {
        $defaults = [
            'event_type' => '',
            'severity' => '',
            'ip_address' => '',
            'user_id' => '',
            'limit' => 100,
            'offset' => 0,
            'order_by' => 'created_at',
            'order' => 'DESC',
            'date_from' => '',
            'date_to' => '',
        ];
        
        $args = wp_parse_args($args, $defaults);
        
        $where_clauses = ['1=1'];
        $where_values = [];
        
        if (!empty($args['event_type'])) {
            $where_clauses[] = 'event_type = %s';
            $where_values[] = $args['event_type'];
        }
        
        if (!empty($args['severity'])) {
            $where_clauses[] = 'severity = %s';
            $where_values[] = $args['severity'];
        }
        
        if (!empty($args['ip_address'])) {
            $where_clauses[] = 'ip_address = %s';
            $where_values[] = $args['ip_address'];
        }
        
        if (!empty($args['user_id'])) {
            $where_clauses[] = 'user_id = %d';
            $where_values[] = intval($args['user_id']);
        }
        
        if (!empty($args['date_from'])) {
            $where_clauses[] = 'created_at >= %s';
            $where_values[] = $args['date_from'];
        }
        
        if (!empty($args['date_to'])) {
            $where_clauses[] = 'created_at <= %s';
            $where_values[] = $args['date_to'];
        }
        
        $where_sql = implode(' AND ', $where_clauses);
        $order_by = sanitize_sql_orderby($args['order_by']);
        $order = in_array(strtoupper($args['order']), ['ASC', 'DESC']) ? strtoupper($args['order']) : 'DESC';
        $limit = intval($args['limit']);
        $offset = intval($args['offset']);
        
        $sql = "SELECT * FROM {$this->tables['logs']} 
                WHERE {$where_sql} 
                ORDER BY {$order_by} {$order} 
                LIMIT {$limit} OFFSET {$offset}";
        
        if (!empty($where_values)) {
            return $this->wpdb->get_results($this->wpdb->prepare($sql, $where_values));
        } else {
            return $this->wpdb->get_results($sql);
        }
    }

    /**
     * Get statistics.
     *
     * @since    3.0.0
     * @param    string $period Time period (today, week, month, all).
     * @return   array          Statistics array.
     */
    public function get_statistics($period = 'all') {
        $date_condition = $this->get_date_condition($period);
        
        // Get threat statistics
        $threat_stats = $this->wpdb->get_row("
            SELECT 
                COUNT(*) as total_threats,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_threats,
                SUM(CASE WHEN quarantined = 1 THEN 1 ELSE 0 END) as quarantined_threats,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_threats
            FROM {$this->tables['threats']} 
            {$date_condition}
        ");
        
        // Get blocked IP statistics
        $ip_stats = $this->wpdb->get_row("
            SELECT 
                COUNT(*) as total_blocked_ips,
                SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_blocked_ips,
                SUM(CASE WHEN is_permanent = 1 THEN 1 ELSE 0 END) as permanent_blocks
            FROM {$this->tables['blocked_ips']} 
            {$date_condition}
        ");
        
        // Get event statistics
        $event_stats = $this->wpdb->get_row("
            SELECT 
                COUNT(*) as total_events,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_events,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_events,
                SUM(CASE WHEN response_action = 'block' THEN 1 ELSE 0 END) as blocked_events
            FROM {$this->tables['logs']} 
            {$date_condition}
        ");
        
        return [
            'threats' => (array) $threat_stats,
            'blocked_ips' => (array) $ip_stats,
            'events' => (array) $event_stats,
            'period' => $period,
            'generated_at' => current_time('mysql'),
        ];
    }

    /**
     * Clean up old data.
     *
     * @since    3.0.0
     * @param    int $retention_days Number of days to retain data.
     * @return   array               Cleanup results.
     */
    public function cleanup_old_data($retention_days = 90) {
        $cutoff_date = date('Y-m-d H:i:s', strtotime("-{$retention_days} days"));
        $results = [];
        
        // Clean up old logs
        $logs_deleted = $this->wpdb->query($this->wpdb->prepare(
            "DELETE FROM {$this->tables['logs']} WHERE created_at < %s AND severity NOT IN ('critical', 'high')",
            $cutoff_date
        ));
        $results['logs_deleted'] = $logs_deleted;
        
        // Clean up expired IP blocks
        $expired_blocks = $this->wpdb->query(
            "UPDATE {$this->tables['blocked_ips']} 
             SET is_active = 0 
             WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_active = 1"
        );
        $results['expired_blocks_deactivated'] = $expired_blocks;
        
        // Clean up old behavioral data
        $behavioral_deleted = $this->wpdb->query($this->wpdb->prepare(
            "DELETE FROM {$this->tables['behavioral']} WHERE timestamp < %s",
            $cutoff_date
        ));
        $results['behavioral_deleted'] = $behavioral_deleted;
        
        // Clean up resolved threats older than retention period
        $resolved_threats_deleted = $this->wpdb->query($this->wpdb->prepare(
            "DELETE FROM {$this->tables['threats']} 
             WHERE status = 'resolved' AND updated_at < %s",
            $cutoff_date
        ));
        $results['resolved_threats_deleted'] = $resolved_threats_deleted;
        
        // Log cleanup activity
        $this->log_event('data_cleanup_completed', [
            'retention_days' => $retention_days,
            'cleanup_results' => $results,
        ], 'low');
        
        return $results;
    }

    /**
     * Optimize database tables.
     *
     * @since    3.0.0
     * @return   array Optimization results.
     */
    public function optimize_tables() {
        $results = [];
        
        foreach ($this->tables as $table_key => $table_name) {
            // Optimize table
            $optimize_result = $this->wpdb->query("OPTIMIZE TABLE {$table_name}");
            
            // Analyze table
            $analyze_result = $this->wpdb->query("ANALYZE TABLE {$table_name}");
            
            $results[$table_key] = [
                'optimize' => $optimize_result !== false,
                'analyze' => $analyze_result !== false,
            ];
        }
        
        return $results;
    }

    /**
     * Get database size information.
     *
     * @since    3.0.0
     * @return   array Database size information.
     */
    public function get_database_size_info() {
        $total_size = 0;
        $table_sizes = [];
        
        foreach ($this->tables as $table_key => $table_name) {
            $size_info = $this->wpdb->get_row($this->wpdb->prepare(
                "SELECT 
                    table_name,
                    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb,
                    table_rows
                FROM information_schema.TABLES 
                WHERE table_schema = %s AND table_name = %s",
                DB_NAME,
                $table_name
            ));
            
            if ($size_info) {
                $table_sizes[$table_key] = [
                    'name' => $table_name,
                    'size_mb' => floatval($size_info->size_mb),
                    'rows' => intval($size_info->table_rows),
                ];
                $total_size += floatval($size_info->size_mb);
            }
        }
        
        return [
            'total_size_mb' => $total_size,
            'tables' => $table_sizes,
        ];
    }

    /**
     * Helper Methods
     */

    /**
     * Get client IP address.
     *
     * @since    3.0.0
     * @return   string Client IP address.
     */
    private function get_client_ip() {
        $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    /**
     * Determine response action based on event type and severity.
     *
     * @since    3.0.0
     * @param    string $event_type Event type.
     * @param    string $severity   Event severity.
     * @return   string             Response action.
     */
    private function determine_response_action($event_type, $severity) {
        $critical_events = [
            'malware_detected',
            'critical_vulnerability',
            'data_breach_attempt',
            'admin_compromise',
        ];
        
        $block_events = [
            'brute_force_attempt',
            'sql_injection_attempt',
            'xss_attempt',
            'file_upload_threat',
        ];
        
        if (in_array($event_type, $critical_events) || $severity === 'critical') {
            return 'quarantine';
        } elseif (in_array($event_type, $block_events) || $severity === 'high') {
            return 'block';
        } elseif ($severity === 'medium') {
            return 'monitor';
        } else {
            return 'log';
        }
    }

    /**
     * Get date condition for SQL queries.
     *
     * @since    3.0.0
     * @param    string $period Time period.
     * @return   string         SQL WHERE condition.
     */
    private function get_date_condition($period) {
        switch ($period) {
            case 'today':
                return "WHERE DATE(created_at) = CURDATE()";
            case 'week':
                return "WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
            case 'month':
                return "WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
            default:
                return "";
        }
    }

    /**
     * Validate and sanitize data before database operations.
     *
     * @since    3.0.0
     * @param    array  $data       Data to validate.
     * @param    array  $rules      Validation rules.
     * @return   array              Validation result.
     */
    private function validate_data($data, $rules) {
        $errors = [];
        $sanitized_data = [];
        
        foreach ($rules as $field => $rule) {
            $value = $data[$field] ?? null;
            
            // Required field check
            if (isset($rule['required']) && $rule['required'] && empty($value)) {
                $errors[] = sprintf(__('Field %s is required.', 'secure-aura'), $field);
                continue;
            }
            
            // Type validation and sanitization
            if (!empty($value)) {
                switch ($rule['type']) {
                    case 'email':
                        if (!is_email($value)) {
                            $errors[] = sprintf(__('Field %s must be a valid email.', 'secure-aura'), $field);
                        } else {
                            $sanitized_data[$field] = sanitize_email($value);
                        }
                        break;
                        
                    case 'ip':
                        if (!filter_var($value, FILTER_VALIDATE_IP)) {
                            $errors[] = sprintf(__('Field %s must be a valid IP address.', 'secure-aura'), $field);
                        } else {
                            $sanitized_data[$field] = sanitize_text_field($value);
                        }
                        break;
                        
                    case 'url':
                        if (!filter_var($value, FILTER_VALIDATE_URL)) {
                            $errors[] = sprintf(__('Field %s must be a valid URL.', 'secure-aura'), $field);
                        } else {
                            $sanitized_data[$field] = esc_url_raw($value);
                        }
                        break;
                        
                    case 'integer':
                        if (!is_numeric($value)) {
                            $errors[] = sprintf(__('Field %s must be a number.', 'secure-aura'), $field);
                        } else {
                            $sanitized_data[$field] = intval($value);
                        }
                        break;
                        
                    case 'float':
                        if (!is_numeric($value)) {
                            $errors[] = sprintf(__('Field %s must be a number.', 'secure-aura'), $field);
                        } else {
                            $sanitized_data[$field] = floatval($value);
                        }
                        break;
                        
                    case 'boolean':
                        $sanitized_data[$field] = (bool) $value;
                        break;
                        
                    case 'text':
                        $sanitized_data[$field] = sanitize_text_field($value);
                        break;
                        
                    case 'textarea':
                        $sanitized_data[$field] = sanitize_textarea_field($value);
                        break;
                        
                    case 'json':
                        $decoded = json_decode($value, true);
                        if (json_last_error() !== JSON_ERROR_NONE) {
                            $errors[] = sprintf(__('Field %s must contain valid JSON.', 'secure-aura'), $field);
                        } else {
                            $sanitized_data[$field] = wp_json_encode($decoded);
                        }
                        break;
                        
                    default:
                        $sanitized_data[$field] = sanitize_text_field($value);
                        break;
                }
            }
            
            // Length validation
            if (isset($rule['max_length']) && strlen($sanitized_data[$field] ?? '') > $rule['max_length']) {
                $errors[] = sprintf(
                    __('Field %s cannot be longer than %d characters.', 'secure-aura'),
                    $field,
                    $rule['max_length']
                );
            }
            
            // Custom validation
            if (isset($rule['validation']) && is_callable($rule['validation'])) {
                $custom_result = call_user_func($rule['validation'], $sanitized_data[$field] ?? null);
                if ($custom_result !== true) {
                    $errors[] = is_string($custom_result) ? $custom_result : sprintf(__('Field %s is invalid.', 'secure-aura'), $field);
                }
            }
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'data' => $sanitized_data,
        ];
    }

    /**
     * Export security data.
     *
     * @since    3.0.0
     * @param    array $options Export options.
     * @return   array          Export result.
     */
    public function export_security_data($options = []) {
        $defaults = [
            'include_logs' => true,
            'include_threats' => true,
            'include_blocked_ips' => true,
            'include_behavioral' => false,
            'date_from' => '',
            'date_to' => '',
            'format' => 'json', // json, csv
            'limit' => 10000,
        ];
        
        $options = wp_parse_args($options, $defaults);
        $export_data = [];
        
        // Build date condition
        $date_condition = '';
        if (!empty($options['date_from']) && !empty($options['date_to'])) {
            $date_condition = $this->wpdb->prepare(
                "WHERE created_at BETWEEN %s AND %s",
                $options['date_from'],
                $options['date_to']
            );
        }
        
        // Export logs
        if ($options['include_logs']) {
            $logs = $this->wpdb->get_results(
                "SELECT * FROM {$this->tables['logs']} {$date_condition} 
                 ORDER BY created_at DESC LIMIT {$options['limit']}"
            );
            $export_data['logs'] = $logs;
        }
        
        // Export threats
        if ($options['include_threats']) {
            $threats = $this->wpdb->get_results(
                "SELECT * FROM {$this->tables['threats']} {$date_condition} 
                 ORDER BY created_at DESC LIMIT {$options['limit']}"
            );
            $export_data['threats'] = $threats;
        }
        
        // Export blocked IPs
        if ($options['include_blocked_ips']) {
            $blocked_ips = $this->wpdb->get_results(
                "SELECT * FROM {$this->tables['blocked_ips']} {$date_condition} 
                 ORDER BY blocked_at DESC LIMIT {$options['limit']}"
            );
            $export_data['blocked_ips'] = $blocked_ips;
        }
        
        // Export behavioral data
        if ($options['include_behavioral']) {
            $behavioral = $this->wpdb->get_results(
                "SELECT * FROM {$this->tables['behavioral']} {$date_condition} 
                 ORDER BY timestamp DESC LIMIT {$options['limit']}"
            );
            $export_data['behavioral'] = $behavioral;
        }
        
        // Add metadata
        $export_data['metadata'] = [
            'export_date' => current_time('mysql'),
            'site_url' => home_url(),
            'plugin_version' => SECURE_AURA_VERSION,
            'options' => $options,
        ];
        
        return [
            'success' => true,
            'data' => $export_data,
            'format' => $options['format'],
        ];
    }

    /**
     * Import security data.
     *
     * @since    3.0.0
     * @param    array $import_data Data to import.
     * @param    array $options     Import options.
     * @return   array              Import result.
     */
    public function import_security_data($import_data, $options = []) {
        $defaults = [
            'overwrite_existing' => false,
            'validate_data' => true,
            'dry_run' => false,
        ];
        
        $options = wp_parse_args($options, $defaults);
        $results = [
            'imported' => 0,
            'skipped' => 0,
            'errors' => [],
        ];
        
        if (empty($import_data) || !is_array($import_data)) {
            return [
                'success' => false,
                'message' => __('Invalid import data provided.', 'secure-aura'),
            ];
        }
        
        // Start transaction
        $this->wpdb->query('START TRANSACTION');
        
        try {
            // Import logs
            if (isset($import_data['logs']) && is_array($import_data['logs'])) {
                foreach ($import_data['logs'] as $log) {
                    if ($this->import_log_entry($log, $options)) {
                        $results['imported']++;
                    } else {
                        $results['skipped']++;
                    }
                }
            }
            
            // Import threats
            if (isset($import_data['threats']) && is_array($import_data['threats'])) {
                foreach ($import_data['threats'] as $threat) {
                    if ($this->import_threat_entry($threat, $options)) {
                        $results['imported']++;
                    } else {
                        $results['skipped']++;
                    }
                }
            }
            
            // Import blocked IPs
            if (isset($import_data['blocked_ips']) && is_array($import_data['blocked_ips'])) {
                foreach ($import_data['blocked_ips'] as $blocked_ip) {
                    if ($this->import_blocked_ip_entry($blocked_ip, $options)) {
                        $results['imported']++;
                    } else {
                        $results['skipped']++;
                    }
                }
            }
            
            if ($options['dry_run']) {
                $this->wpdb->query('ROLLBACK');
                $results['message'] = __('Dry run completed successfully. No data was actually imported.', 'secure-aura');
            } else {
                $this->wpdb->query('COMMIT');
                $results['message'] = sprintf(
                    __('Import completed. %d entries imported, %d skipped.', 'secure-aura'),
                    $results['imported'],
                    $results['skipped']
                );
            }
            
            return array_merge($results, ['success' => true]);
            
        } catch (Exception $e) {
            $this->wpdb->query('ROLLBACK');
            
            return [
                'success' => false,
                'message' => __('Import failed: ', 'secure-aura') . $e->getMessage(),
                'results' => $results,
            ];
        }
    }

    /**
     * Import log entry.
     *
     * @since    3.0.0
     * @param    array $log_data Log data.
     * @param    array $options  Import options.
     * @return   bool            True on success, false on failure.
     */
    private function import_log_entry($log_data, $options) {
        // Validate required fields
        $required_fields = ['event_type', 'ip_address', 'severity'];
        foreach ($required_fields as $field) {
            if (empty($log_data[$field])) {
                return false;
            }
        }
        
        // Check if entry already exists (if not overwriting)
        if (!$options['overwrite_existing']) {
            $existing = $this->wpdb->get_var($this->wpdb->prepare(
                "SELECT id FROM {$this->tables['logs']} 
                 WHERE event_type = %s AND ip_address = %s AND created_at = %s",
                $log_data['event_type'],
                $log_data['ip_address'],
                $log_data['created_at'] ?? current_time('mysql')
            ));
            
            if ($existing) {
                return false; // Skip existing entry
            }
        }
        
        $insert_data = [
            'event_type' => sanitize_text_field($log_data['event_type']),
            'ip_address' => sanitize_text_field($log_data['ip_address']),
            'user_id' => intval($log_data['user_id'] ?? 0),
            'event_data' => wp_json_encode($log_data['event_data'] ?? []),
            'severity' => sanitize_text_field($log_data['severity']),
            'user_agent' => substr($log_data['user_agent'] ?? '', 0, 500),
            'request_uri' => substr($log_data['request_uri'] ?? '', 0, 500),
            'response_action' => sanitize_text_field($log_data['response_action'] ?? 'log'),
            'created_at' => $log_data['created_at'] ?? current_time('mysql'),
        ];
        
        $result = $this->wpdb->insert(
            $this->tables['logs'],
            $insert_data,
            ['%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s']
        );
        
        return $result !== false;
    }

    /**
     * Import threat entry.
     *
     * @since    3.0.0
     * @param    array $threat_data Threat data.
     * @param    array $options     Import options.
     * @return   bool               True on success, false on failure.
     */
    private function import_threat_entry($threat_data, $options) {
        // Validate required fields
        if (empty($threat_data['threat_type']) || empty($threat_data['file_path'])) {
            return false;
        }
        
        // Check if threat already exists
        if (!$options['overwrite_existing']) {
            $existing = $this->wpdb->get_var($this->wpdb->prepare(
                "SELECT id FROM {$this->tables['threats']} 
                 WHERE file_path = %s AND threat_type = %s",
                $threat_data['file_path'],
                $threat_data['threat_type']
            ));
            
            if ($existing) {
                return false;
            }
        }
        
        $insert_data = [
            'threat_type' => sanitize_text_field($threat_data['threat_type']),
            'severity' => sanitize_text_field($threat_data['severity'] ?? 'medium'),
            'status' => sanitize_text_field($threat_data['status'] ?? 'active'),
            'file_path' => sanitize_text_field($threat_data['file_path']),
            'file_hash' => sanitize_text_field($threat_data['file_hash'] ?? ''),
            'threat_signature' => sanitize_textarea_field($threat_data['threat_signature'] ?? ''),
            'detection_method' => sanitize_text_field($threat_data['detection_method'] ?? 'import'),
            'false_positive' => intval($threat_data['false_positive'] ?? 0),
            'quarantined' => intval($threat_data['quarantined'] ?? 0),
            'detection_count' => intval($threat_data['detection_count'] ?? 1),
            'first_detected' => $threat_data['first_detected'] ?? current_time('mysql'),
            'last_detected' => $threat_data['last_detected'] ?? current_time('mysql'),
            'created_at' => $threat_data['created_at'] ?? current_time('mysql'),
        ];
        
        $result = $this->wpdb->insert(
            $this->tables['threats'],
            $insert_data,
            ['%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%d', '%s', '%s', '%s']
        );
        
        return $result !== false;
    }

    /**
     * Import blocked IP entry.
     *
     * @since    3.0.0
     * @param    array $ip_data Blocked IP data.
     * @param    array $options Import options.
     * @return   bool           True on success, false on failure.
     */
    private function import_blocked_ip_entry($ip_data, $options) {
        // Validate IP address
        if (empty($ip_data['ip_address']) || !filter_var($ip_data['ip_address'], FILTER_VALIDATE_IP)) {
            return false;
        }
        
        // Check if IP is already blocked
        if (!$options['overwrite_existing'] && $this->is_ip_blocked($ip_data['ip_address'])) {
            return false;
        }
        
        $insert_data = [
            'ip_address' => $ip_data['ip_address'],
            'reason' => sanitize_text_field($ip_data['reason'] ?? 'Imported block'),
            'blocked_by_user_id' => intval($ip_data['blocked_by_user_id'] ?? 0),
            'is_active' => intval($ip_data['is_active'] ?? 1),
            'is_permanent' => intval($ip_data['is_permanent'] ?? 0),
            'expires_at' => $ip_data['expires_at'] ?? null,
            'threat_type' => sanitize_text_field($ip_data['threat_type'] ?? 'imported'),
            'block_count' => intval($ip_data['block_count'] ?? 1),
            'blocked_at' => $ip_data['blocked_at'] ?? current_time('mysql'),
        ];
        
        $result = $this->wpdb->insert(
            $this->tables['blocked_ips'],
            $insert_data,
            ['%s', '%s', '%d', '%d', '%d', '%s', '%s', '%d', '%s']
        );
        
        return $result !== false;
    }

    /**
     * Get threat trends data for charts.
     *
     * @since    3.0.0
     * @param    int $days Number of days to analyze.
     * @return   array     Trend data.
     */
    public function get_threat_trends($days = 30) {
        $trends = [];
        
        for ($i = $days - 1; $i >= 0; $i--) {
            $date = date('Y-m-d', strtotime("-{$i} days"));
            
            $daily_stats = $this->wpdb->get_row($this->wpdb->prepare(
                "SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as total_threats,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_threats,
                    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_threats,
                    SUM(CASE WHEN quarantined = 1 THEN 1 ELSE 0 END) as quarantined_threats
                FROM {$this->tables['threats']} 
                WHERE DATE(created_at) = %s
                GROUP BY DATE(created_at)",
                $date
            ));
            
            $trends[] = [
                'date' => $date,
                'total_threats' => intval($daily_stats->total_threats ?? 0),
                'critical_threats' => intval($daily_stats->critical_threats ?? 0),
                'high_threats' => intval($daily_stats->high_threats ?? 0),
                'quarantined_threats' => intval($daily_stats->quarantined_threats ?? 0),
            ];
        }
        
        return $trends;
    }

    /**
     * Backup security data.
     *
     * @since    3.0.0
     * @param    string $backup_path Backup file path.
     * @return   array               Backup result.
     */
    public function backup_security_data($backup_path = null) {
        if (!$backup_path) {
            $backup_path = SECURE_AURA_BACKUPS_DIR . 'security_backup_' . date('Y-m-d_H-i-s') . '.json';
        }
        
        // Ensure backup directory exists
        $backup_dir = dirname($backup_path);
        if (!file_exists($backup_dir)) {
            wp_mkdir_p($backup_dir);
        }
        
        try {
            // Export all security data
            $export_result = $this->export_security_data([
                'include_logs' => true,
                'include_threats' => true,
                'include_blocked_ips' => true,
                'include_behavioral' => true,
                'limit' => 50000, // Higher limit for backups
            ]);
            
            if (!$export_result['success']) {
                throw new Exception(__('Failed to export security data for backup.', 'secure-aura'));
            }
            
            // Write to file
            $json_data = wp_json_encode($export_result['data'], JSON_PRETTY_PRINT);
            $bytes_written = file_put_contents($backup_path, $json_data);
            
            if ($bytes_written === false) {
                throw new Exception(__('Failed to write backup file.', 'secure-aura'));
            }
            
            // Log backup creation
            $this->log_event('security_backup_created', [
                'backup_path' => $backup_path,
                'backup_size' => $bytes_written,
                'records_backed_up' => [
                    'logs' => count($export_result['data']['logs'] ?? []),
                    'threats' => count($export_result['data']['threats'] ?? []),
                    'blocked_ips' => count($export_result['data']['blocked_ips'] ?? []),
                    'behavioral' => count($export_result['data']['behavioral'] ?? []),
                ],
            ], 'low');
            
            return [
                'success' => true,
                'backup_path' => $backup_path,
                'backup_size' => $bytes_written,
                'message' => __('Security data backup created successfully.', 'secure-aura'),
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => __('Backup failed: ', 'secure-aura') . $e->getMessage(),
            ];
        }
    }

    /**
     * Get performance metrics.
     *
     * @since    3.0.0
     * @return   array Performance metrics.
     */
    public function get_performance_metrics() {
        $metrics = [];
        
        // Query execution times
        foreach ($this->tables as $table_key => $table_name) {
            $start_time = microtime(true);
            $this->wpdb->get_var("SELECT COUNT(*) FROM {$table_name}");
            $end_time = microtime(true);
            
            $metrics['query_times'][$table_key] = [
                'table' => $table_name,
                'execution_time_ms' => round(($end_time - $start_time) * 1000, 2),
            ];
        }
        
        // Database size information
        $metrics['database_size'] = $this->get_database_size_info();
        
        // Index information
        $metrics['index_usage'] = $this->get_index_usage_stats();
        
        return $metrics;
    }

    /**
     * Get index usage statistics.
     *
     * @since    3.0.0
     * @return   array Index usage statistics.
     */
    private function get_index_usage_stats() {
        $index_stats = [];
        
        foreach ($this->tables as $table_key => $table_name) {
            $indexes = $this->wpdb->get_results($this->wpdb->prepare(
                "SHOW INDEX FROM %s",
                $table_name
            ), ARRAY_A);
            
            $index_stats[$table_key] = [
                'table' => $table_name,
                'index_count' => count($indexes),
                'indexes' => $indexes,
            ];
        }
        
        return $index_stats;
    }

    /**
     * Cleanup method.
     *
     * @since    3.0.0
     */
    public function cleanup() {
        // Close any open database connections if needed
        // This is handled automatically by WordPress
    }
}

?>