<?php
/**
 * Security protection file
 * Prevents direct access to the plugin directory
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Access denied.');
}

// If someone tries to access this directory directly, redirect to home
if (!defined('WP_CONTENT_DIR')) {
    header('Location: /');
    exit;
}