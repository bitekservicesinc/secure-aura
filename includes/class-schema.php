<?php
/**
 * SecureAura Database Schema
 *
 * Handles creation and management of database tables
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
 * SecureAura Database Schema Class
 *
 * This class manages all database operations including:
 * - Table creation
 * - Schema updates
 * - Index optimization
 * - Data migration
 *
 * @since      3.0.0
 * @package    SecureAura
 * @subpackage SecureAura/database
 * @author     Bitekservices
 */
class Secure_Aura_Schema {

    /**
     * Database version for tracking schema changes.
     *
     * @since    3.0.0
     * @access   private
     * @var      string    $db_version    Current database schema version.
     */
    private $db_version;

    /**
     * WordPress database instance.
     *
     * @since    3.0.0
     * @access   private
     * @var      wpdb    $wpdb    WordPress database instance.
     */
    private $wpdb;

    /**
     * Database charset and collation.
     *
     * @since    3.0.0
     * @access   private
     * @var      string    $charset_collate    Database charset and collation.
     */
    private $charset_collate;

    /**
     * Initialize the schema manager.
     *
     * @since    3.0.0
     */
    public function __construct() {
        global $wpdb;
        
        $this->wpdb = $wpdb;
        $this->db_version = SECURE_AURA_DB_VERSION;
        $this->charset_collate = $this->wpdb->get_charset_collate();
    }

    /**
     * Create all plugin tables.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    public function create_tables() {
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        
        $tables_created = 0;
        $total_tables = 10;
        
        try {
            // Create core security tables
            if ($this->create_logs_table()) $tables_created++;
            if ($this->create_threats_table()) $tables_created++;
            if ($this->create_behavioral_table()) $tables_created++;
            if ($this->create_file_integrity_table()) $tables_created++;
            if ($this->create_blocked_ips_table()) $tables_created++;
            if ($this->create_whitelist_table()) $tables_created++;
            if ($this->create_quarantine_table()) $tables_created++;
            if ($this->create_incident_reports_table()) $tables_created++;
            if ($this->create_compliance_logs_table()) $tables_created++;
            if ($this->create_performance_metrics_table()) $tables_created++;
            
            // Create indexes for better performance
            $this->create_indexes();
            
            // Update database version
            update_option('secure_aura_db_version', $this->db_version);
            
            return $tables_created === $total_tables;
            
        } catch (Exception $e) {
            error_log('SecureAura Schema Error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Create security logs table.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    private function create_logs_table() {
        $table_name = $this->wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            timestamp datetime DEFAULT CURRENT_TIMESTAMP,
            event_type varchar(50) NOT NULL,
            severity enum('info','low','medium','high','critical','emergency') DEFAULT 'medium',
            source_ip varchar(45),
            user_id bigint(20) unsigned,
            event_data longtext,
            ai_analysis longtext,
            threat_score decimal(4,3) DEFAULT 0.000,
            geolocation varchar(100),
            user_agent text,
            request_uri text,
            response_action varchar(50),
            blocked_reason varchar(255),
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_timestamp (timestamp),
            KEY idx_event_type (event_type),
            KEY idx_severity (severity),
            KEY idx_source_ip (source_ip),
            KEY idx_user_id (user_id),
            KEY idx_threat_score (threat_score),
            KEY idx_response_action (response_action),
            KEY idx_created_at (created_at),
            KEY idx_composite_search (event_type, severity, timestamp)
        ) {$this->charset_collate};";
        
        $result = dbDelta($sql);
        return !empty($result);
    }

    /**
     * Create threat intelligence table.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    private function create_threats_table() {
        $table_name = $this->wpdb->prefix . SECURE_AURA_TABLE_THREATS;
        
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            threat_type varchar(50) NOT NULL,
            indicator_value varchar(500) NOT NULL,
            indicator_type enum('ip','domain','hash','url','email','file_hash','user_agent','pattern') NOT NULL,
            confidence_score decimal(4,3) DEFAULT 0.500,
            threat_level enum('low','medium','high','critical') DEFAULT 'medium',
            first_seen datetime DEFAULT CURRENT_TIMESTAMP,
            last_seen datetime DEFAULT CURRENT_TIMESTAMP,
            last_updated datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            source varchar(100),
            source_url varchar(500),
            tags text,
            metadata longtext,
            is_active boolean DEFAULT TRUE,
            is_whitelisted boolean DEFAULT FALSE,
            false_positive_count int(11) DEFAULT 0,
            detection_count int(11) DEFAULT 0,
            geo_country varchar(2),
            geo_region varchar(100),
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY idx_unique_indicator (indicator_value, indicator_type),
            KEY idx_threat_type (threat_type),
            KEY idx_indicator_type (indicator_type),
            KEY idx_confidence_score (confidence_score),
            KEY idx_threat_level (threat_level),
            KEY idx_last_seen (last_seen),
            KEY idx_is_active (is_active),
            KEY idx_source (source),
            KEY idx_geo_country (geo_country),
            KEY idx_detection_count (detection_count),
            KEY idx_composite_threat (threat_type, indicator_type, is_active)
        ) {$this->charset_collate};";
        
        $result = dbDelta($sql);
        return !empty($result);
    }

    /**
     * Create behavioral analysis table.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    private function create_behavioral_table() {
        $table_name = $this->wpdb->prefix . SECURE_AURA_TABLE_BEHAVIORAL;
        
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_identifier varchar(255) NOT NULL,
            session_id varchar(255),
            ip_address varchar(45),
            user_agent_hash varchar(64),
            behavior_pattern longtext,
            anomaly_score decimal(4,3) DEFAULT 0.000,
            risk_level enum('low','medium','high','critical') DEFAULT 'low',
            timestamp datetime DEFAULT CURRENT_TIMESTAMP,
            actions_taken text,
            false_positive boolean DEFAULT FALSE,
            device_fingerprint varchar(64),
            geolocation varchar(100),
            page_visits int(11) DEFAULT 0,
            failed_login_attempts int(11) DEFAULT 0,
            suspicious_actions int(11) DEFAULT 0,
            time_on_site int(11) DEFAULT 0,
            is_bot boolean DEFAULT FALSE,
            bot_confidence decimal(4,3) DEFAULT 0.000,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_user_identifier (user_identifier),
            KEY idx_session_id (session_id),
            KEY idx_ip_address (ip_address),
            KEY idx_anomaly_score (anomaly_score),
            KEY idx_risk_level (risk_level),
            KEY idx_timestamp (timestamp),
            KEY idx_is_bot (is_bot),
            KEY idx_bot_confidence (bot_confidence),
            KEY idx_composite_behavior (user_identifier, anomaly_score, timestamp)
        ) {$this->charset_collate};";
        
        $result = dbDelta($sql);
        return !empty($result);
    }

    /**
     * Create file integrity monitoring table.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    private function create_file_integrity_table() {
        $table_name = $this->wpdb->prefix . SECURE_AURA_TABLE_FILE_INTEGRITY;
        
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            file_path varchar(1000) NOT NULL,
            file_hash varchar(128) NOT NULL,
            file_size bigint(20) unsigned,
            file_permissions varchar(10),
            last_modified datetime,
            last_checked datetime DEFAULT CURRENT_TIMESTAMP,
            status enum('clean','modified','suspicious','infected','quarantined','deleted') DEFAULT 'clean',
            change_type enum('none','content','permissions','size','timestamp') DEFAULT 'none',
            change_details longtext,
            threat_type varchar(50),
            quarantine_path varchar(1000),
            backup_path varchar(1000),
            scan_result longtext,
            false_positive boolean DEFAULT FALSE,
            whitelist_reason varchar(255),
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY idx_unique_file_path (file_path(767)),
            KEY idx_file_hash (file_hash),
            KEY idx_status (status),
            KEY idx_change_type (change_type),
            KEY idx_last_checked (last_checked),
            KEY idx_last_modified (last_modified),
            KEY idx_threat_type (threat_type),
            KEY idx_false_positive (false_positive),
            KEY idx_composite_integrity (status, change_type, last_checked)
        ) {$this->charset_collate};";
        
        $result = dbDelta($sql);
        return !empty($result);
    }

    /**
     * Create blocked IPs table.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    private function create_blocked_ips_table() {
        $table_name = $this->wpdb->prefix . SECURE_AURA_TABLE_BLOCKED_IPS;
        
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            ip_range varchar(50),
            block_reason varchar(255),
            threat_type varchar(50),
            confidence_score decimal(4,3) DEFAULT 1.000,
            blocked_at datetime DEFAULT CURRENT_TIMESTAMP,
            expires_at datetime NULL,
            is_permanent boolean DEFAULT FALSE,
            is_manual boolean DEFAULT FALSE,
            blocked_by_user_id bigint(20) unsigned,
            attempt_count int(11) DEFAULT 1,
            last_attempt datetime DEFAULT CURRENT_TIMESTAMP,
            geo_country varchar(2),
            geo_region varchar(100),
            asn varchar(20),
            organization varchar(255),
            is_tor boolean DEFAULT FALSE,
            is_vpn boolean DEFAULT FALSE,
            is_proxy boolean DEFAULT FALSE,
            user_agent_hash varchar(64),
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY idx_unique_ip (ip_address),
            KEY idx_expires_at (expires_at),
            KEY idx_is_permanent (is_permanent),
            KEY idx_blocked_at (blocked_at),
            KEY idx_threat_type (threat_type),
            KEY idx_geo_country (geo_country),
            KEY idx_is_tor (is_tor),
            KEY idx_is_vpn (is_vpn),
            KEY idx_attempt_count (attempt_count),
            KEY idx_composite_block (is_permanent, expires_at, blocked_at)
        ) {$this->charset_collate};";
        
        $result = dbDelta($sql);
        return !empty($result);
    }

    /**
     * Create whitelist table.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    private function create_whitelist_table() {
        $table_name = $this->wpdb->prefix . SECURE_AURA_TABLE_WHITELIST;
        
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            entry_type enum('ip','ip_range','domain','email','user_agent','file_hash','url_pattern') NOT NULL,
            entry_value varchar(500) NOT NULL,
            whitelist_reason varchar(255),
            added_by_user_id bigint(20) unsigned,
            is_active boolean DEFAULT TRUE,
            expires_at datetime NULL,
            usage_count int(11) DEFAULT 0,
            last_used datetime NULL,
            tags varchar(255),
            notes text,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY idx_unique_whitelist (entry_type, entry_value),
            KEY idx_entry_type (entry_type),
            KEY idx_is_active (is_active),
            KEY idx_expires_at (expires_at),
            KEY idx_added_by_user_id (added_by_user_id),
            KEY idx_usage_count (usage_count),
            KEY idx_composite_whitelist (entry_type, is_active, expires_at)
        ) {$this->charset_collate};";
        
        $result = dbDelta($sql);
        return !empty($result);
    }

    /**
     * Create quarantine table.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    private function create_quarantine_table() {
        $table_name = $this->wpdb->prefix . SECURE_AURA_TABLE_QUARANTINE;
        
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            original_path varchar(1000) NOT NULL,
            quarantine_path varchar(1000) NOT NULL,
            file_hash varchar(128),
            file_size bigint(20) unsigned,
            threat_type varchar(50),
            threat_name varchar(255),
            detection_method varchar(100),
            confidence_score decimal(4,3) DEFAULT 1.000,
            quarantined_at datetime DEFAULT CURRENT_TIMESTAMP,
            detected_by varchar(100),
            scan_details longtext,
            restoration_possible boolean DEFAULT TRUE,
            restoration_notes text,
            false_positive boolean DEFAULT FALSE,
            reviewed_by_user_id bigint(20) unsigned NULL,
            reviewed_at datetime NULL,
            action_taken enum('quarantined','deleted','restored','ignored') DEFAULT 'quarantined',
            auto_delete_at datetime NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_original_path (original_path(767)),
            KEY idx_quarantine_path (quarantine_path(767)),
            KEY idx_file_hash (file_hash),
            KEY idx_threat_type (threat_type),
            KEY idx_quarantined_at (quarantined_at),
            KEY idx_action_taken (action_taken),
            KEY idx_false_positive (false_positive),
            KEY idx_auto_delete_at (auto_delete_at),
            KEY idx_composite_quarantine (threat_type, action_taken, quarantined_at)
        ) {$this->charset_collate};";
        
        $result = dbDelta($sql);
        return !empty($result);
    }

    /**
     * Create incident reports table.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    private function create_incident_reports_table() {
        $table_name = $this->wpdb->prefix . SECURE_AURA_TABLE_INCIDENT_REPORTS;
        
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            incident_id varchar(64) NOT NULL,
            incident_type varchar(50) NOT NULL,
            severity enum('low','medium','high','critical','emergency') DEFAULT 'medium',
            status enum('open','investigating','contained','resolved','closed') DEFAULT 'open',
            title varchar(255) NOT NULL,
            description text,
            affected_resources longtext,
            attack_vector varchar(100),
            threat_actor varchar(255),
            indicators_of_compromise longtext,
            timeline longtext,
            response_actions longtext,
            lessons_learned text,
            assigned_to_user_id bigint(20) unsigned NULL,
            reported_by_user_id bigint(20) unsigned NULL,
            occurred_at datetime NOT NULL,
            detected_at datetime DEFAULT CURRENT_TIMESTAMP,
            contained_at datetime NULL,
            resolved_at datetime NULL,
            estimated_impact varchar(255),
            actual_impact varchar(255),
            compliance_requirements text,
            external_notification_required boolean DEFAULT FALSE,
            external_notifications_sent boolean DEFAULT FALSE,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY idx_unique_incident_id (incident_id),
            KEY idx_incident_type (incident_type),
            KEY idx_severity (severity),
            KEY idx_status (status),
            KEY idx_occurred_at (occurred_at),
            KEY idx_detected_at (detected_at),
            KEY idx_assigned_to_user_id (assigned_to_user_id),
            KEY idx_threat_actor (threat_actor),
            KEY idx_composite_incident (incident_type, severity, status)
        ) {$this->charset_collate};";
        
        $result = dbDelta($sql);
        return !empty($result);
    }

    /**
     * Create compliance logs table.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    private function create_compliance_logs_table() {
        $table_name = $this->wpdb->prefix . SECURE_AURA_TABLE_COMPLIANCE_LOGS;
        
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            compliance_standard varchar(50) NOT NULL,
            control_id varchar(100) NOT NULL,
            control_name varchar(255) NOT NULL,
            compliance_status enum('compliant','non_compliant','partial','not_applicable') DEFAULT 'not_applicable',
            assessment_date datetime DEFAULT CURRENT_TIMESTAMP,
            evidence_collected longtext,
            gaps_identified text,
            remediation_actions text,
            remediation_deadline datetime NULL,
            remediation_status enum('not_started','in_progress','completed','overdue') DEFAULT 'not_started',
            assessed_by_user_id bigint(20) unsigned NULL,
            approved_by_user_id bigint(20) unsigned NULL,
            next_assessment_date datetime NULL,
            risk_rating enum('low','medium','high','critical') DEFAULT 'medium',
            business_impact varchar(255),
            technical_details longtext,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_compliance_standard (compliance_standard),
            KEY idx_control_id (control_id),
            KEY idx_compliance_status (compliance_status),
            KEY idx_assessment_date (assessment_date),
            KEY idx_next_assessment_date (next_assessment_date),
            KEY idx_risk_rating (risk_rating),
            KEY idx_remediation_status (remediation_status),
            KEY idx_composite_compliance (compliance_standard, compliance_status, assessment_date)
        ) {$this->charset_collate};";
        
        $result = dbDelta($sql);
        return !empty($result);
    }

    /**
     * Create performance metrics table.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    private function create_performance_metrics_table() {
        $table_name = $this->wpdb->prefix . SECURE_AURA_TABLE_PERFORMANCE_METRICS;
        
        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            metric_type varchar(50) NOT NULL,
            metric_name varchar(100) NOT NULL,
            metric_value decimal(15,6) NOT NULL,
            metric_unit varchar(20),
            threshold_warning decimal(15,6),
            threshold_critical decimal(15,6),
            status enum('normal','warning','critical') DEFAULT 'normal',
            measurement_time datetime DEFAULT CURRENT_TIMESTAMP,
            server_info varchar(255),
            plugin_version varchar(20),
            additional_data longtext,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_metric_type (metric_type),
            KEY idx_metric_name (metric_name),
            KEY idx_status (status),
            KEY idx_measurement_time (measurement_time),
            KEY idx_plugin_version (plugin_version),
            KEY idx_composite_metrics (metric_type, metric_name, measurement_time)
        ) {$this->charset_collate};";
        
        $result = dbDelta($sql);
        return !empty($result);
    }

    /**
     * Create database indexes for performance optimization.
     *
     * @since    3.0.0
     */
    private function create_indexes() {
        // Additional composite indexes for complex queries
        $additional_indexes = [
            // Logs table advanced indexes
            "CREATE INDEX IF NOT EXISTS idx_logs_security_analysis ON {$this->wpdb->prefix}" . SECURE_AURA_TABLE_LOGS . " (event_type, severity, threat_score, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_logs_ip_timeline ON {$this->wpdb->prefix}" . SECURE_AURA_TABLE_LOGS . " (source_ip, timestamp, event_type)",
            
            // Threats table advanced indexes
            "CREATE INDEX IF NOT EXISTS idx_threats_active_high_confidence ON {$this->wpdb->prefix}" . SECURE_AURA_TABLE_THREATS . " (is_active, confidence_score, threat_level)",
            "CREATE INDEX IF NOT EXISTS idx_threats_recent_detections ON {$this->wpdb->prefix}" . SECURE_AURA_TABLE_THREATS . " (last_seen, detection_count, threat_type)",
            
            // Behavioral table advanced indexes
            "CREATE INDEX IF NOT EXISTS idx_behavioral_risk_analysis ON {$this->wpdb->prefix}" . SECURE_AURA_TABLE_BEHAVIORAL . " (risk_level, anomaly_score, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_behavioral_bot_detection ON {$this->wpdb->prefix}" . SECURE_AURA_TABLE_BEHAVIORAL . " (is_bot, bot_confidence, timestamp)",
            
            // File integrity advanced indexes
            "CREATE INDEX IF NOT EXISTS idx_file_integrity_threat_status ON {$this->wpdb->prefix}" . SECURE_AURA_TABLE_FILE_INTEGRITY . " (status, threat_type, last_checked)",
            
            // Blocked IPs advanced indexes
            "CREATE INDEX IF NOT EXISTS idx_blocked_ips_geo_analysis ON {$this->wpdb->prefix}" . SECURE_AURA_TABLE_BLOCKED_IPS . " (geo_country, threat_type, blocked_at)",
            "CREATE INDEX IF NOT EXISTS idx_blocked_ips_proxy_detection ON {$this->wpdb->prefix}" . SECURE_AURA_TABLE_BLOCKED_IPS . " (is_tor, is_vpn, is_proxy, blocked_at)",
        ];
        
        foreach ($additional_indexes as $index_sql) {
            $this->wpdb->query($index_sql);
        }
    }

    /**
     * Update database schema if needed.
     *
     * @since    3.0.0
     * @return   bool    True if update was successful, false otherwise.
     */
    public function update_schema() {
        $current_db_version = get_option('secure_aura_db_version', '0');
        
        if (version_compare($current_db_version, $this->db_version, '<')) {
            // Perform schema updates
            $this->perform_schema_migrations($current_db_version);
            
            // Update version
            update_option('secure_aura_db_version', $this->db_version);
            
            return true;
        }
        
        return false;
    }

    /**
     * Perform schema migrations based on version.
     *
     * @since    3.0.0
     * @param    string $from_version Current database version.
     */
    private function perform_schema_migrations($from_version) {
        // Example migration from version 2.x to 3.0.0
        if (version_compare($from_version, '3.0.0', '<')) {
            $this->migrate_to_v3();
        }
        
        // Add more migrations as needed
    }

    /**
     * Migration to version 3.0.0.
     *
     * @since    3.0.0
     */
    private function migrate_to_v3() {
        // Add new columns to existing tables
        $migrations = [
            "ALTER TABLE {$this->wpdb->prefix}" . SECURE_AURA_TABLE_LOGS . " ADD COLUMN IF NOT EXISTS ai_analysis longtext AFTER event_data",
            "ALTER TABLE {$this->wpdb->prefix}" . SECURE_AURA_TABLE_LOGS . " ADD COLUMN IF NOT EXISTS threat_score decimal(4,3) DEFAULT 0.000 AFTER ai_analysis",
            "ALTER TABLE {$this->wpdb->prefix}" . SECURE_AURA_TABLE_THREATS . " ADD COLUMN IF NOT EXISTS geo_country varchar(2) AFTER detection_count",
            "ALTER TABLE {$this->wpdb->prefix}" . SECURE_AURA_TABLE_THREATS . " ADD COLUMN IF NOT EXISTS geo_region varchar(100) AFTER geo_country",
        ];
        
        foreach ($migrations as $migration_sql) {
            $this->wpdb->query($migration_sql);
        }
    }

    /**
     * Drop all plugin tables.
     *
     * @since    3.0.0
     * @return   bool    True on success, false on failure.
     */
    public function drop_tables() {
        $tables = [
            SECURE_AURA_TABLE_LOGS,
            SECURE_AURA_TABLE_THREATS,
            SECURE_AURA_TABLE_BEHAVIORAL,
            SECURE_AURA_TABLE_FILE_INTEGRITY,
            SECURE_AURA_TABLE_BLOCKED_IPS,
            SECURE_AURA_TABLE_WHITELIST,
            SECURE_AURA_TABLE_QUARANTINE,
            SECURE_AURA_TABLE_INCIDENT_REPORTS,
            SECURE_AURA_TABLE_COMPLIANCE_LOGS,
            SECURE_AURA_TABLE_PERFORMANCE_METRICS,
        ];
        
        foreach ($tables as $table) {
            $table_name = $this->wpdb->prefix . $table;
            $this->wpdb->query("DROP TABLE IF EXISTS {$table_name}");
        }
        
        // Remove database version option
        delete_option('secure_aura_db_version');
        
        return true;
    }

    /**
     * Optimize database tables.
     *
     * @since    3.0.0
     * @return   array    Optimization results.
     */
    public function optimize_tables() {
        $tables = [
            SECURE_AURA_TABLE_LOGS,
            SECURE_AURA_TABLE_THREATS,
            SECURE_AURA_TABLE_BEHAVIORAL,
            SECURE_AURA_TABLE_FILE_INTEGRITY,
            SECURE_AURA_TABLE_BLOCKED_IPS,
            SECURE_AURA_TABLE_WHITELIST,
            SECURE_AURA_TABLE_QUARANTINE,
            SECURE_AURA_TABLE_INCIDENT_REPORTS,
            SECURE_AURA_TABLE_COMPLIANCE_LOGS,
            SECURE_AURA_TABLE_PERFORMANCE_METRICS,
        ];
        
        $results = [];
        
        foreach ($tables as $table) {
            $table_name = $this->wpdb->prefix . $table;
            
            // Optimize table
            $optimize_result = $this->wpdb->query("OPTIMIZE TABLE {$table_name}");
            
            // Analyze table
            $analyze_result = $this->wpdb->query("ANALYZE TABLE {$table_name}");
            
            $results[$table] = [
                'optimize' => $optimize_result !== false,
                'analyze' => $analyze_result !== false,
                'size' => $this->get_table_size($table_name),
            ];
        }
        
        return $results;
    }

    /**
     * Get table size information.
     *
     * @since    3.0.0
     * @param    string $table_name Table name.
     * @return   array  Table size information.
     */
    private function get_table_size($table_name) {
        $result = $this->wpdb->get_row("
            SELECT 
                table_rows as rows,
                data_length as data_size,
                index_length as index_size,
                (data_length + index_length) as total_size
            FROM information_schema.tables 
            WHERE table_schema = DATABASE() 
            AND table_name = '{$table_name}'
        ");
        
        return $result ? (array) $result : [];
    }

    /**
     * Get database statistics.
     *
     * @since    3.0.0
     * @return   array    Database statistics.
     */
    public function get_database_stats() {
        $stats = [
            'total_tables' => 0,
            'total_rows' => 0,
            'total_size' => 0,
            'tables' => [],
        ];
        
        $tables = [
            SECURE_AURA_TABLE_LOGS,
            SECURE_AURA_TABLE_THREATS,
            SECURE_AURA_TABLE_BEHAVIORAL,
            SECURE_AURA_TABLE_FILE_INTEGRITY,
            SECURE_AURA_TABLE_BLOCKED_IPS,
            SECURE_AURA_TABLE_WHITELIST,
            SECURE_AURA_TABLE_QUARANTINE,
            SECURE_AURA_TABLE_INCIDENT_REPORTS,
            SECURE_AURA_TABLE_COMPLIANCE_LOGS,
            SECURE_AURA_TABLE_PERFORMANCE_METRICS,
        ];
        
        foreach ($tables as $table) {
            $table_name = $this->wpdb->prefix . $table;
            $table_stats = $this->get_table_size($table_name);
            
            if (!empty($table_stats)) {
                $stats['tables'][$table] = $table_stats;
                $stats['total_tables']++;
                $stats['total_rows'] += intval($table_stats['rows'] ?? 0);
                $stats['total_size'] += intval($table_stats['total_size'] ?? 0);
            }
        }
        
        return $stats;
    }

    /**
     * Clean up old data based on retention policies.
     *
     * @since    3.0.0
     * @param    int $retention_days Number of days to retain data.
     * @return   array Cleanup results.
     */
    public function cleanup_old_data($retention_days = 90) {
        $cutoff_date = date('Y-m-d H:i:s', strtotime("-{$retention_days} days"));
        $results = [];
        
        // Clean up old logs
        $logs_deleted = $this->wpdb->query($this->wpdb->prepare("
            DELETE FROM {$this->wpdb->prefix}" . SECURE_AURA_TABLE_LOGS . " 
            WHERE created_at < %s AND severity NOT IN ('critical', 'emergency')
        ", $cutoff_date));
        
        $results['logs_deleted'] = $logs_deleted;
        
        // Clean up old behavioral data
        $behavioral_deleted = $this->wpdb->query($this->wpdb->prepare("
            DELETE FROM {$this->wpdb->prefix}" . SECURE_AURA_TABLE_BEHAVIORAL . " 
            WHERE created_at < %s AND risk_level = 'low'
        ", $cutoff_date));
        
        $results['behavioral_deleted'] = $behavioral_deleted;
        
        // Clean up expired blocked IPs
        $blocked_ips_deleted = $this->wpdb->query("
            DELETE FROM {$this->wpdb->prefix}" . SECURE_AURA_TABLE_BLOCKED_IPS . " 
            WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_permanent = 0
        ");
        
        $results['blocked_ips_deleted'] = $blocked_ips_deleted;
        
        // Clean up old performance metrics
        $metrics_deleted = $this->wpdb->query($this->wpdb->prepare("
            DELETE FROM {$this->wpdb->prefix}" . SECURE_AURA_TABLE_PERFORMANCE_METRICS . " 
            WHERE created_at < %s
        ", $cutoff_date));
        
        $results['metrics_deleted'] = $metrics_deleted;
        
        return $results;
    }

    /**
     * Verify database integrity.
     *
     * @since    3.0.0
     * @return   array    Integrity check results.
     */
    public function verify_integrity() {
        $results = [
            'tables_exist' => true,
            'indexes_exist' => true,
            'foreign_keys_valid' => true,
            'data_consistency' => true,
            'issues' => [],
        ];
        
        // Check if all tables exist
        $required_tables = [
            SECURE_AURA_TABLE_LOGS,
            SECURE_AURA_TABLE_THREATS,
            SECURE_AURA_TABLE_BEHAVIORAL,
            SECURE_AURA_TABLE_FILE_INTEGRITY,
            SECURE_AURA_TABLE_BLOCKED_IPS,
            SECURE_AURA_TABLE_WHITELIST,
            SECURE_AURA_TABLE_QUARANTINE,
            SECURE_AURA_TABLE_INCIDENT_REPORTS,
            SECURE_AURA_TABLE_COMPLIANCE_LOGS,
            SECURE_AURA_TABLE_PERFORMANCE_METRICS,
        ];
        
        foreach ($required_tables as $table) {
            $table_name = $this->wpdb->prefix . $table;
            if ($this->wpdb->get_var("SHOW TABLES LIKE '{$table_name}'") !== $table_name) {
                $results['tables_exist'] = false;
                $results['issues'][] = "Missing table: {$table}";
            }
        }
        
        return $results;
    }
}