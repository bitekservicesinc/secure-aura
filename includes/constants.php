<?php
/**
 * SecureAura Constants
 *
 * Define all plugin constants used throughout the application
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
 * Database and Schema Constants
 */
define('SECURE_AURA_DB_VERSION', '3.0.0');
define('SECURE_AURA_TABLES_PREFIX', 'secure_aura_');

// Table names (without WordPress prefix)
define('SECURE_AURA_TABLE_LOGS', 'secure_aura_logs');
define('SECURE_AURA_TABLE_THREATS', 'secure_aura_threats');
define('SECURE_AURA_TABLE_BEHAVIORAL', 'secure_aura_behavioral');
define('SECURE_AURA_TABLE_FILE_INTEGRITY', 'secure_aura_file_integrity');
define('SECURE_AURA_TABLE_BLOCKED_IPS', 'secure_aura_blocked_ips');
define('SECURE_AURA_TABLE_WHITELIST', 'secure_aura_whitelist');
define('SECURE_AURA_TABLE_QUARANTINE', 'secure_aura_quarantine');
define('SECURE_AURA_TABLE_INCIDENT_REPORTS', 'secure_aura_incident_reports');
define('SECURE_AURA_TABLE_COMPLIANCE_LOGS', 'secure_aura_compliance_logs');
define('SECURE_AURA_TABLE_PERFORMANCE_METRICS', 'secure_aura_performance_metrics');

/**
 * Security Level Constants
 */
define('SECURE_AURA_LEVEL_DISABLED', 0);
define('SECURE_AURA_LEVEL_BASIC', 1);
define('SECURE_AURA_LEVEL_ENHANCED', 2);
define('SECURE_AURA_LEVEL_QUANTUM', 3);
define('SECURE_AURA_LEVEL_MILITARY', 4);
define('SECURE_AURA_LEVEL_FORTRESS', 5);

/**
 * Threat Severity Levels
 */
define('SECURE_AURA_SEVERITY_INFO', 'info');
define('SECURE_AURA_SEVERITY_LOW', 'low');
define('SECURE_AURA_SEVERITY_MEDIUM', 'medium');
define('SECURE_AURA_SEVERITY_HIGH', 'high');
define('SECURE_AURA_SEVERITY_CRITICAL', 'critical');
define('SECURE_AURA_SEVERITY_EMERGENCY', 'emergency');

/**
 * Event Types
 */
define('SECURE_AURA_EVENT_LOGIN_SUCCESS', 'login_success');
define('SECURE_AURA_EVENT_LOGIN_FAILED', 'login_failed');
define('SECURE_AURA_EVENT_BRUTE_FORCE', 'brute_force_attempt');
define('SECURE_AURA_EVENT_MALWARE_DETECTED', 'malware_detected');
define('SECURE_AURA_EVENT_SUSPICIOUS_ACTIVITY', 'suspicious_activity');
define('SECURE_AURA_EVENT_FILE_CHANGED', 'file_changed');
define('SECURE_AURA_EVENT_UNAUTHORIZED_ACCESS', 'unauthorized_access');
define('SECURE_AURA_EVENT_SQL_INJECTION', 'sql_injection_attempt');
define('SECURE_AURA_EVENT_XSS_ATTEMPT', 'xss_attempt');
define('SECURE_AURA_EVENT_CSRF_ATTEMPT', 'csrf_attempt');
define('SECURE_AURA_EVENT_DIRECTORY_TRAVERSAL', 'directory_traversal');
define('SECURE_AURA_EVENT_UPLOAD_THREAT', 'malicious_upload');
define('SECURE_AURA_EVENT_VULNERABILITY_SCAN', 'vulnerability_scan');
define('SECURE_AURA_EVENT_CONFIGURATION_CHANGE', 'configuration_change');
define('SECURE_AURA_EVENT_EMERGENCY_MODE', 'emergency_mode_activated');

/**
 * AI Model Types
 */
define('SECURE_AURA_AI_THREAT_DETECTION', 'threat_detection');
define('SECURE_AURA_AI_BEHAVIORAL_ANALYSIS', 'behavioral_analysis');
define('SECURE_AURA_AI_MALWARE_DETECTION', 'malware_detection');
define('SECURE_AURA_AI_BOT_DETECTION', 'bot_detection');
define('SECURE_AURA_AI_ZERO_DAY_DETECTION', 'zero_day_detection');
define('SECURE_AURA_AI_PREDICTIVE_BLOCKING', 'predictive_blocking');

/**
 * Response Actions
 */
define('SECURE_AURA_ACTION_ALLOW', 'allow');
define('SECURE_AURA_ACTION_BLOCK', 'block');
define('SECURE_AURA_ACTION_CHALLENGE', 'challenge');
define('SECURE_AURA_ACTION_CAPTCHA', 'captcha');
define('SECURE_AURA_ACTION_RATE_LIMIT', 'rate_limit');
define('SECURE_AURA_ACTION_QUARANTINE', 'quarantine');
define('SECURE_AURA_ACTION_LOG_ONLY', 'log_only');
define('SECURE_AURA_ACTION_REDIRECT', 'redirect');
define('SECURE_AURA_ACTION_HONEYPOT', 'honeypot');

/**
 * Firewall Rules
 */
define('SECURE_AURA_RULE_TYPE_IP', 'ip');
define('SECURE_AURA_RULE_TYPE_COUNTRY', 'country');
define('SECURE_AURA_RULE_TYPE_USER_AGENT', 'user_agent');
define('SECURE_AURA_RULE_TYPE_REFERER', 'referer');
define('SECURE_AURA_RULE_TYPE_URL_PATTERN', 'url_pattern');
define('SECURE_AURA_RULE_TYPE_REQUEST_METHOD', 'request_method');
define('SECURE_AURA_RULE_TYPE_RATE_LIMIT', 'rate_limit');
define('SECURE_AURA_RULE_TYPE_BEHAVIORAL', 'behavioral');

/**
 * Scan Types
 */
define('SECURE_AURA_SCAN_QUICK', 'quick');
define('SECURE_AURA_SCAN_FULL', 'full');
define('SECURE_AURA_SCAN_DEEP', 'deep');
define('SECURE_AURA_SCAN_MALWARE', 'malware');
define('SECURE_AURA_SCAN_VULNERABILITY', 'vulnerability');
define('SECURE_AURA_SCAN_INTEGRITY', 'integrity');
define('SECURE_AURA_SCAN_REAL_TIME', 'real_time');

/**
 * File Status Constants
 */
define('SECURE_AURA_FILE_CLEAN', 'clean');
define('SECURE_AURA_FILE_SUSPICIOUS', 'suspicious');
define('SECURE_AURA_FILE_INFECTED', 'infected');
define('SECURE_AURA_FILE_QUARANTINED', 'quarantined');
define('SECURE_AURA_FILE_CHANGED', 'changed');
define('SECURE_AURA_FILE_ADDED', 'added');
define('SECURE_AURA_FILE_DELETED', 'deleted');

/**
 * Compliance Standards
 */
define('SECURE_AURA_COMPLIANCE_GDPR', 'gdpr');
define('SECURE_AURA_COMPLIANCE_HIPAA', 'hipaa');
define('SECURE_AURA_COMPLIANCE_PCI_DSS', 'pci_dss');
define('SECURE_AURA_COMPLIANCE_SOC2', 'soc2');
define('SECURE_AURA_COMPLIANCE_ISO27001', 'iso27001');
define('SECURE_AURA_COMPLIANCE_NIST', 'nist');

/**
 * Notification Types
 */
define('SECURE_AURA_NOTIFY_EMAIL', 'email');
define('SECURE_AURA_NOTIFY_SMS', 'sms');
define('SECURE_AURA_NOTIFY_SLACK', 'slack');
define('SECURE_AURA_NOTIFY_WEBHOOK', 'webhook');
define('SECURE_AURA_NOTIFY_PUSH', 'push');
define('SECURE_AURA_NOTIFY_DASHBOARD', 'dashboard');

/**
 * Cache Types
 */
define('SECURE_AURA_CACHE_THREATS', 'threats');
define('SECURE_AURA_CACHE_RULES', 'rules');
define('SECURE_AURA_CACHE_GEOIP', 'geoip');
define('SECURE_AURA_CACHE_AI_MODELS', 'ai_models');
define('SECURE_AURA_CACHE_SIGNATURES', 'signatures');

/**
 * API Endpoints
 */
define('SECURE_AURA_API_BASE', 'secure-aura/v1');
define('SECURE_AURA_API_THREAT_INTEL', 'threat-intelligence');
define('SECURE_AURA_API_SCAN', 'scan');
define('SECURE_AURA_API_MONITORING', 'monitoring');
define('SECURE_AURA_API_FIREWALL', 'firewall');
define('SECURE_AURA_API_REPORTS', 'reports');

/**
 * Rate Limiting
 */
define('SECURE_AURA_RATE_LIMIT_LOGIN', 'login');
define('SECURE_AURA_RATE_LIMIT_API', 'api');
define('SECURE_AURA_RATE_LIMIT_SCAN', 'scan');
define('SECURE_AURA_RATE_LIMIT_GLOBAL', 'global');

/**
 * Time Constants (in seconds)
 */
define('SECURE_AURA_MINUTE', 60);
define('SECURE_AURA_HOUR', 3600);
define('SECURE_AURA_DAY', 86400);
define('SECURE_AURA_WEEK', 604800);
define('SECURE_AURA_MONTH', 2592000);

/**
 * Default Configuration Values
 */
define('SECURE_AURA_DEFAULT_SCAN_TIMEOUT', 300); // 5 minutes
define('SECURE_AURA_DEFAULT_THREAT_SCORE_THRESHOLD', 0.7);
define('SECURE_AURA_DEFAULT_BEHAVIORAL_ANOMALY_THRESHOLD', 0.8);
define('SECURE_AURA_DEFAULT_RATE_LIMIT_REQUESTS', 100);
define('SECURE_AURA_DEFAULT_RATE_LIMIT_WINDOW', 300); // 5 minutes
define('SECURE_AURA_DEFAULT_LOG_RETENTION_DAYS', 90);
define('SECURE_AURA_DEFAULT_BACKUP_RETENTION_DAYS', 30);

/**
 * Feature Flags
 */
define('SECURE_AURA_FEATURE_QUANTUM_FIREWALL', 'quantum_firewall');
define('SECURE_AURA_FEATURE_AI_THREAT_ENGINE', 'ai_threat_engine');
define('SECURE_AURA_FEATURE_BEHAVIORAL_MONITOR', 'behavioral_monitor');
define('SECURE_AURA_FEATURE_REAL_TIME_SCAN', 'real_time_scan');
define('SECURE_AURA_FEATURE_THREAT_INTELLIGENCE', 'threat_intelligence');
define('SECURE_AURA_FEATURE_GEO_BLOCKING', 'geo_blocking');
define('SECURE_AURA_FEATURE_BOT_DETECTION', 'bot_detection');
define('SECURE_AURA_FEATURE_ZERO_DAY_PROTECTION', 'zero_day_protection');
define('SECURE_AURA_FEATURE_INCIDENT_RESPONSE', 'incident_response');
define('SECURE_AURA_FEATURE_COMPLIANCE_MONITORING', 'compliance_monitoring');

/**
 * Error Codes
 */
define('SECURE_AURA_ERROR_GENERAL', 1000);
define('SECURE_AURA_ERROR_DATABASE', 1001);
define('SECURE_AURA_ERROR_FILE_SYSTEM', 1002);
define('SECURE_AURA_ERROR_NETWORK', 1003);
define('SECURE_AURA_ERROR_AUTHENTICATION', 1004);
define('SECURE_AURA_ERROR_AUTHORIZATION', 1005);
define('SECURE_AURA_ERROR_VALIDATION', 1006);
define('SECURE_AURA_ERROR_CONFIGURATION', 1007);
define('SECURE_AURA_ERROR_AI_MODEL', 1008);
define('SECURE_AURA_ERROR_THREAT_INTEL', 1009);

/**
 * Hook Priorities
 */
define('SECURE_AURA_PRIORITY_HIGHEST', 1);
define('SECURE_AURA_PRIORITY_HIGH', 5);
define('SECURE_AURA_PRIORITY_NORMAL', 10);
define('SECURE_AURA_PRIORITY_LOW', 15);
define('SECURE_AURA_PRIORITY_LOWEST', 20);

/**
 * File System Paths
 */
define('SECURE_AURA_UPLOADS_DIR', wp_upload_dir()['basedir'] . '/secure-aura/');
define('SECURE_AURA_LOGS_DIR', SECURE_AURA_UPLOADS_DIR . 'logs/');
define('SECURE_AURA_CACHE_DIR', SECURE_AURA_UPLOADS_DIR . 'cache/');
define('SECURE_AURA_QUARANTINE_DIR', SECURE_AURA_UPLOADS_DIR . 'quarantine/');
define('SECURE_AURA_BACKUPS_DIR', SECURE_AURA_UPLOADS_DIR . 'backups/');
define('SECURE_AURA_REPORTS_DIR', SECURE_AURA_UPLOADS_DIR . 'reports/');

/**
 * External Service URLs
 */
define('SECURE_AURA_THREAT_INTEL_URL', 'https://api.secureaura.pro/threat-intelligence/');
define('SECURE_AURA_AI_MODELS_URL', 'https://models.secureaura.pro/');
define('SECURE_AURA_GEOIP_URL', 'https://geoip.secureaura.pro/');
define('SECURE_AURA_UPDATE_SERVER', 'https://updates.secureaura.pro/');
define('SECURE_AURA_LICENSE_SERVER', 'https://license.secureaura.pro/');

/**
 * User Capability Constants
 */
define('SECURE_AURA_CAP_MANAGE_SECURITY', 'secure_aura_manage_security');
define('SECURE_AURA_CAP_VIEW_LOGS', 'secure_aura_view_logs');
define('SECURE_AURA_CAP_MANAGE_FIREWALL', 'secure_aura_manage_firewall');
define('SECURE_AURA_CAP_RUN_SCANS', 'secure_aura_run_scans');
define('SECURE_AURA_CAP_MANAGE_THREATS', 'secure_aura_manage_threats');
define('SECURE_AURA_CAP_VIEW_REPORTS', 'secure_aura_view_reports');

/**
 * Cron Job Names
 */
define('SECURE_AURA_CRON_THREAT_INTEL_UPDATE', 'secure_aura_update_threat_intel');
define('SECURE_AURA_CRON_FULL_SCAN', 'secure_aura_full_scan');
define('SECURE_AURA_CRON_LOG_CLEANUP', 'secure_aura_log_cleanup');
define('SECURE_AURA_CRON_CACHE_CLEANUP', 'secure_aura_cache_cleanup');
define('SECURE_AURA_CRON_BACKUP_CLEANUP', 'secure_aura_backup_cleanup');
define('SECURE_AURA_CRON_PERFORMANCE_CHECK', 'secure_aura_performance_check');
define('SECURE_AURA_CRON_INTEGRITY_CHECK', 'secure_aura_integrity_check');

/**
 * Memory and Performance Limits
 */
define('SECURE_AURA_MAX_MEMORY_USAGE', '256M');
define('SECURE_AURA_MAX_EXECUTION_TIME', 300);
define('SECURE_AURA_MAX_FILE_SIZE_SCAN', 50 * 1024 * 1024); // 50MB
define('SECURE_AURA_MAX_FILES_PER_SCAN', 10000);
define('SECURE_AURA_MAX_LOG_ENTRIES_PER_PAGE', 100);

/**
 * Encryption and Hashing
 */
define('SECURE_AURA_ENCRYPTION_METHOD', 'AES-256-CBC');
define('SECURE_AURA_HASH_ALGORITHM', 'sha256');
define('SECURE_AURA_PASSWORD_HASH_ALGORITHM', PASSWORD_ARGON2ID);

/**
 * Regular Expression Patterns
 */
define('SECURE_AURA_REGEX_IP', '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/');
define('SECURE_AURA_REGEX_EMAIL', '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/');
define('SECURE_AURA_REGEX_URL', '/^https?:\/\/[^\s\/$.?#].[^\s]*$/');
define('SECURE_AURA_REGEX_HASH', '/^[a-f0-9]{32,64}$/i');

/**
 * License Types
 */
define('SECURE_AURA_LICENSE_FREE', 'free');
define('SECURE_AURA_LICENSE_PRO', 'pro');
define('SECURE_AURA_LICENSE_ENTERPRISE', 'enterprise');
define('SECURE_AURA_LICENSE_DEVELOPER', 'developer');

/**
 * Plugin Environment
 */
define('SECURE_AURA_ENV_DEVELOPMENT', 'development');
define('SECURE_AURA_ENV_STAGING', 'staging');
define('SECURE_AURA_ENV_PRODUCTION', 'production');

// Determine current environment
if (!defined('SECURE_AURA_ENVIRONMENT')) {
    if (defined('WP_DEBUG') && WP_DEBUG) {
        define('SECURE_AURA_ENVIRONMENT', SECURE_AURA_ENV_DEVELOPMENT);
    } elseif (strpos(home_url(), 'staging') !== false || strpos(home_url(), 'dev') !== false) {
        define('SECURE_AURA_ENVIRONMENT', SECURE_AURA_ENV_STAGING);
    } else {
        define('SECURE_AURA_ENVIRONMENT', SECURE_AURA_ENV_PRODUCTION);
    }
}

/**
 * Debug and Logging Levels
 */
define('SECURE_AURA_LOG_LEVEL_ERROR', 1);
define('SECURE_AURA_LOG_LEVEL_WARNING', 2);
define('SECURE_AURA_LOG_LEVEL_INFO', 3);
define('SECURE_AURA_LOG_LEVEL_DEBUG', 4);
define('SECURE_AURA_LOG_LEVEL_TRACE', 5);

/**
 * Default log level based on environment
 */
if (!defined('SECURE_AURA_LOG_LEVEL')) {
    switch (SECURE_AURA_ENVIRONMENT) {
        case SECURE_AURA_ENV_DEVELOPMENT:
            define('SECURE_AURA_LOG_LEVEL', SECURE_AURA_LOG_LEVEL_DEBUG);
            break;
        case SECURE_AURA_ENV_STAGING:
            define('SECURE_AURA_LOG_LEVEL', SECURE_AURA_LOG_LEVEL_INFO);
            break;
        case SECURE_AURA_ENV_PRODUCTION:
        default:
            define('SECURE_AURA_LOG_LEVEL', SECURE_AURA_LOG_LEVEL_WARNING);
            break;
    }
}

/**
 * Feature availability based on license
 */
function secure_aura_get_license_features() {
    return [
        SECURE_AURA_LICENSE_FREE => [
            SECURE_AURA_FEATURE_QUANTUM_FIREWALL => false,
            SECURE_AURA_FEATURE_AI_THREAT_ENGINE => false,
            SECURE_AURA_FEATURE_BEHAVIORAL_MONITOR => false,
            SECURE_AURA_FEATURE_REAL_TIME_SCAN => true,
            SECURE_AURA_FEATURE_THREAT_INTELLIGENCE => false,
            SECURE_AURA_FEATURE_GEO_BLOCKING => false,
            SECURE_AURA_FEATURE_BOT_DETECTION => true,
            SECURE_AURA_FEATURE_ZERO_DAY_PROTECTION => false,
            SECURE_AURA_FEATURE_INCIDENT_RESPONSE => false,
            SECURE_AURA_FEATURE_COMPLIANCE_MONITORING => false
        ],
        SECURE_AURA_LICENSE_PRO => [
            SECURE_AURA_FEATURE_QUANTUM_FIREWALL => true,
            SECURE_AURA_FEATURE_AI_THREAT_ENGINE => true,
            SECURE_AURA_FEATURE_BEHAVIORAL_MONITOR => true,
            SECURE_AURA_FEATURE_REAL_TIME_SCAN => true,
            SECURE_AURA_FEATURE_THREAT_INTELLIGENCE => true,
            SECURE_AURA_FEATURE_GEO_BLOCKING => true,
            SECURE_AURA_FEATURE_BOT_DETECTION => true,
            SECURE_AURA_FEATURE_ZERO_DAY_PROTECTION => true,
            SECURE_AURA_FEATURE_INCIDENT_RESPONSE => true,
            SECURE_AURA_FEATURE_COMPLIANCE_MONITORING => false
        ],
        SECURE_AURA_LICENSE_ENTERPRISE => [
            SECURE_AURA_FEATURE_QUANTUM_FIREWALL => true,
            SECURE_AURA_FEATURE_AI_THREAT_ENGINE => true,
            SECURE_AURA_FEATURE_BEHAVIORAL_MONITOR => true,
            SECURE_AURA_FEATURE_REAL_TIME_SCAN => true,
            SECURE_AURA_FEATURE_THREAT_INTELLIGENCE => true,
            SECURE_AURA_FEATURE_GEO_BLOCKING => true,
            SECURE_AURA_FEATURE_BOT_DETECTION => true,
            SECURE_AURA_FEATURE_ZERO_DAY_PROTECTION => true,
            SECURE_AURA_FEATURE_INCIDENT_RESPONSE => true,
            SECURE_AURA_FEATURE_COMPLIANCE_MONITORING => true
        ]
    ];
}