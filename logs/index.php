<?php
/**
 * Logs directory protection
 * Prevents direct access to log files
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Access denied.');
}

// Additional protection - redirect to home if accessed directly
header('HTTP/1.0 403 Forbidden');
exit('Directory access is forbidden.');