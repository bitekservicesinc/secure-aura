<?php
/**
 * Email Notifications Handler
 *
 *
 * Handles all email notifications for the plugin
 *
 * @package    SecureAura
 * @subpackage SecureAura/includes
 * @since      3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

class Secure_Aura_Email_Notifications {
    
    /**
     * Plugin settings
     *
     * @var array
     */
    private $settings;
    
    /**
     * Notification email address
     *
     * @var string
     */
    private $notification_email;
    
    /**
     * Email templates directory
     *
     * @var string
     */
    private $templates_dir;
    
    /**
     * Initialize the email notifications
     *
     * @since 3.0.0
     */
    public function __construct() {
        $this->settings = get_option('secure_aura_settings', []);
        $this->notification_email = get_option('secure_aura_notification_email', get_option('admin_email'));
        $this->templates_dir = SECURE_AURA_PLUGIN_DIR . 'templates/emails/';
        
        // Set email content type to HTML
        add_filter('wp_mail_content_type', [$this, 'set_html_content_type']);
    }
    
    /**
     * Set email content type to HTML
     *
     * @since 3.0.0
     * @return string Content type
     */
    public function set_html_content_type() {
        return 'text/html';
    }
    
    /**
     * Send threat alert email
     *
     * @since 3.0.0
     * @param array $threat Threat details
     * @param int $threat_count Total threats found
     * @return bool True if email sent successfully
     */
    public function send_threat_alert($threat, $threat_count = 1) {
        // Check if threat notifications are enabled
        if (empty($this->settings['notify_on_threat'])) {
            return false;
        }
        
        $site_name = get_bloginfo('name');
        $site_url = get_site_url();
        $scan_date = current_time('mysql');
        
        // Get email template
        ob_start();
        include $this->templates_dir . 'threat-alert.php';
        $message = ob_get_clean();
        
        // Email subject
        $subject = sprintf(
            __('[%s] Security Alert: Threat Detected!', 'secure-aura'),
            $site_name
        );
        
        // Email headers
        $headers = [
            'From: SecureAura <' . get_option('admin_email') . '>',
            'Reply-To: ' . get_option('admin_email'),
        ];
        
        // Send email
        $sent = wp_mail($this->notification_email, $subject, $message, $headers);
        
        // Log notification
        $this->log_notification('threat_alert', $sent, [
            'threat_type' => $threat['type'] ?? 'unknown',
            'threat_count' => $threat_count,
        ]);
        
        return $sent;
    }
    
    /**
     * Send scan report email
     *
     * @since 3.0.0
     * @param array $scan_results Scan results data
     * @return bool True if email sent successfully
     */
    public function send_scan_report($scan_results) {
        // Check if scan notifications are enabled
        if (empty($this->settings['notify_on_scan'])) {
            return false;
        }
        
        // Only send if threats found or it's a scheduled report
        if (empty($scan_results['threats_found']) && empty($scan_results['scheduled'])) {
            return false;
        }
        
        $site_name = get_bloginfo('name');
        $site_url = get_site_url();
        $scan_date = $scan_results['completed_at'] ?? current_time('mysql');
        $files_scanned = $scan_results['files_scanned'] ?? 0;
        $threats_found = $scan_results['threats_found'] ?? 0;
        $scan_duration = $this->format_duration($scan_results['duration'] ?? 0);
        
        // Get email template
        ob_start();
        include $this->templates_dir . 'scan-report.php';
        $message = ob_get_clean();
        
        // Email subject
        if ($threats_found > 0) {
            $subject = sprintf(
                __('[%s] Security Scan: %d Threat(s) Found', 'secure-aura'),
                $site_name,
                $threats_found
            );
        } else {
            $subject = sprintf(
                __('[%s] Security Scan Complete: All Clear', 'secure-aura'),
                $site_name
            );
        }
        
        // Email headers
        $headers = [
            'From: SecureAura <' . get_option('admin_email') . '>',
            'Reply-To: ' . get_option('admin_email'),
        ];
        
        // Send email
        $sent = wp_mail($this->notification_email, $subject, $message, $headers);
        
        // Log notification
        $this->log_notification('scan_report', $sent, [
            'files_scanned' => $files_scanned,
            'threats_found' => $threats_found,
        ]);
        
        return $sent;
    }
    
    /**
     * Send incident report email
     *
     * @since 3.0.0
     * @param array $incident Incident details
     * @return bool True if email sent successfully
     */
    public function send_incident_report($incident) {
        $site_name = get_bloginfo('name');
        $site_url = get_site_url();
        
        // Build email message
        $message = $this->build_incident_email($incident, $site_name, $site_url);
        
        // Email subject
        $subject = sprintf(
            __('[%s] Security Incident Report: %s', 'secure-aura'),
            $site_name,
            $incident['title'] ?? __('Critical Event', 'secure-aura')
        );
        
        // Email headers
        $headers = [
            'From: SecureAura <' . get_option('admin_email') . '>',
            'Reply-To: ' . get_option('admin_email'),
        ];
        
        // Send email
        $sent = wp_mail($this->notification_email, $subject, $message, $headers);
        
        // Log notification
        $this->log_notification('incident_report', $sent, [
            'incident_type' => $incident['type'] ?? 'unknown',
        ]);
        
        return $sent;
    }
    
    /**
     * Send plugin update notification
     *
     * @since 3.0.0
     * @param string $new_version New version number
     * @return bool True if email sent successfully
     */
    public function send_update_notification($new_version) {
        // Check if update notifications are enabled
        if (empty($this->settings['notify_on_update'])) {
            return false;
        }
        
        $site_name = get_bloginfo('name');
        $current_version = SECURE_AURA_VERSION;
        
        $message = '
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #667eea; color: white; padding: 20px; text-align: center; }
                .content { padding: 30px; background: #f9f9f9; }
                .button { display: inline-block; padding: 12px 24px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>' . __('SecureAura Update Available', 'secure-aura') . '</h1>
                </div>
                <div class="content">
                    <h2>' . __('New Version Available', 'secure-aura') . '</h2>
                    <p>' . sprintf(__('SecureAura version %s is now available for %s.', 'secure-aura'), $new_version, $site_name) . '</p>
                    <p>' . sprintf(__('You are currently running version %s.', 'secure-aura'), $current_version) . '</p>
                    <p>' . __('This update includes important security improvements and new features.', 'secure-aura') . '</p>
                    <a href="' . admin_url('update-core.php') . '" class="button">' . __('Update Now', 'secure-aura') . '</a>
                    <h3>' . __('What\'s New:', 'secure-aura') . '</h3>
                    <ul>
                        <li>' . __('Enhanced threat detection', 'secure-aura') . '</li>
                        <li>' . __('Performance improvements', 'secure-aura') . '</li>
                        <li>' . __('Bug fixes and security patches', 'secure-aura') . '</li>
                    </ul>
                </div>
                <div class="footer">
                    <p>' . __('This is an automated notification from SecureAura', 'secure-aura') . '</p>
                </div>
            </div>
        </body>
        </html>';
        
        $subject = sprintf(
            __('[%s] SecureAura Update Available: Version %s', 'secure-aura'),
            $site_name,
            $new_version
        );
        
        $headers = [
            'From: SecureAura <' . get_option('admin_email') . '>',
        ];
        
        $sent = wp_mail($this->notification_email, $subject, $message, $headers);
        
        $this->log_notification('update_notification', $sent, [
            'new_version' => $new_version,
        ]);
        
        return $sent;
    }
    
    /**
     * Send emergency mode notification
     *
     * @since 3.0.0
     * @param bool $enabled Whether emergency mode was enabled or disabled
     * @return bool True if email sent successfully
     */
    public function send_emergency_mode_notification($enabled) {
        $site_name = get_bloginfo('name');
        
        $status = $enabled ? __('Enabled', 'secure-aura') : __('Disabled', 'secure-aura');
        $color = $enabled ? '#dc2626' : '#10b981';
        
        $message = '
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: ' . $color . '; color: white; padding: 20px; text-align: center; }
                .content { padding: 30px; background: #f9f9f9; }
                .alert-box { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>' . sprintf(__('Emergency Mode %s', 'secure-aura'), $status) . '</h1>
                </div>
                <div class="content">
                    <p>' . sprintf(__('Emergency mode has been %s on %s.', 'secure-aura'), strtolower($status), $site_name) . '</p>';
        
        if ($enabled) {
            $message .= '
                    <div class="alert-box">
                        <strong>' . __('What This Means:', 'secure-aura') . '</strong>
                        <ul>
                            <li>' . __('All non-admin traffic is blocked', 'secure-aura') . '</li>
                            <li>' . __('Maximum security settings are active', 'secure-aura') . '</li>
                            <li>' . __('Your site is in lockdown mode', 'secure-aura') . '</li>
                        </ul>
                    </div>';
        } else {
            $message .= '
                    <p>' . __('Normal operations have resumed. All security settings are back to their previous state.', 'secure-aura') . '</p>';
        }
        
        $message .= '
                    <p><a href="' . admin_url('admin.php?page=secure-aura') . '">' . __('View Dashboard', 'secure-aura') . '</a></p>
                </div>
            </div>
        </body>
        </html>';
        
        $subject = sprintf(
            __('[%s] Emergency Mode %s', 'secure-aura'),
            $site_name,
            $status
        );
        
        $headers = [
            'From: SecureAura <' . get_option('admin_email') . '>',
        ];
        
        return wp_mail($this->notification_email, $subject, $message, $headers);
    }
    
    /**
     * Send blocked IP notification
     *
     * @since 3.0.0
     * @param string $ip_address IP address that was blocked
     * @param string $reason Reason for blocking
     * @return bool True if email sent successfully
     */
    public function send_blocked_ip_notification($ip_address, $reason) {
        $site_name = get_bloginfo('name');
        
        $message = sprintf(
            __('IP address %s has been blocked on %s. Reason: %s', 'secure-aura'),
            $ip_address,
            $site_name,
            $reason
        );
        
        $subject = sprintf(
            __('[%s] IP Address Blocked', 'secure-aura'),
            $site_name
        );
        
        return wp_mail($this->notification_email, $subject, $message);
    }
    
    /**
     * Build incident report email
     *
     * @since 3.0.0
     * @param array $incident Incident details
     * @param string $site_name Site name
     * @param string $site_url Site URL
     * @return string Email HTML
     */
    private function build_incident_email($incident, $site_name, $site_url) {
        $severity_colors = [
            'critical' => '#dc2626',
            'high' => '#f59e0b',
            'medium' => '#fbbf24',
            'low' => '#3b82f6',
        ];
        
        $severity = $incident['severity'] ?? 'medium';
        $color = $severity_colors[$severity] ?? '#6b7280';
        
        return '
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: ' . $color . '; color: white; padding: 20px; text-align: center; }
                .content { padding: 30px; background: #f9f9f9; }
                .detail-row { padding: 10px 0; border-bottom: 1px solid #ddd; }
                .label { font-weight: bold; display: inline-block; width: 150px; }
                .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>' . __('Security Incident Report', 'secure-aura') . '</h1>
                </div>
                <div class="content">
                    <h2>' . esc_html($incident['title'] ?? __('Security Incident', 'secure-aura')) . '</h2>
                    <div class="detail-row">
                        <span class="label">' . __('Severity:', 'secure-aura') . '</span>
                        <span>' . esc_html(ucfirst($severity)) . '</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">' . __('Type:', 'secure-aura') . '</span>
                        <span>' . esc_html($incident['type'] ?? __('Unknown', 'secure-aura')) . '</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">' . __('Detected At:', 'secure-aura') . '</span>
                        <span>' . esc_html($incident['detected_at'] ?? current_time('mysql')) . '</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">' . __('Description:', 'secure-aura') . '</span>
                        <span>' . esc_html($incident['description'] ?? '') . '</span>
                    </div>
                    <p style="margin-top: 30px;">
                        <a href="' . admin_url('admin.php?page=secure-aura&tab=incidents') . '" style="background: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                            ' . __('View Incident Details', 'secure-aura') . '
                        </a>
                    </p>
                </div>
                <div class="footer">
                    <p>' . __('This is an automated security notification from SecureAura', 'secure-aura') . '</p>
                </div>
            </div>
        </body>
        </html>';
    }
    
    /**
     * Format duration in human-readable format
     *
     * @since 3.0.0
     * @param int $seconds Duration in seconds
     * @return string Formatted duration
     */
    private function format_duration($seconds) {
        if ($seconds < 60) {
            return sprintf(__('%d seconds', 'secure-aura'), $seconds);
        } elseif ($seconds < 3600) {
            $minutes = floor($seconds / 60);
            $secs = $seconds % 60;
            return sprintf(__('%d minutes, %d seconds', 'secure-aura'), $minutes, $secs);
        } else {
            $hours = floor($seconds / 3600);
            $minutes = floor(($seconds % 3600) / 60);
            return sprintf(__('%d hours, %d minutes', 'secure-aura'), $hours, $minutes);
        }
    }
    
    /**
     * Log notification attempt
     *
     * @since 3.0.0
     * @param string $type Notification type
     * @param bool $success Whether email was sent successfully
     * @param array $meta Additional metadata
     */
    private function log_notification($type, $success, $meta = []) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $wpdb->insert($table_name, [
            'event_type' => 'email_notification',
            'severity' => 'info',
            'event_data' => json_encode([
                'notification_type' => $type,
                'success' => $success,
                'recipient' => $this->notification_email,
                'meta' => $meta,
            ]),
            'created_at' => current_time('mysql'),
        ]);
    }
    
    /**
     * Update notification email address
     *
     * @since 3.0.0
     * @param string $email New email address
     * @return bool True if updated successfully
     */
    public function update_notification_email($email) {
        if (is_email($email)) {
            $this->notification_email = $email;
            update_option('secure_aura_notification_email', $email);
            return true;
        }
        return false;
    }
    
    /**
     * Test email notification
     *
     * @since 3.0.0
     * @return bool True if test email sent successfully
     */
    public function send_test_email() {
        $site_name = get_bloginfo('name');
        
        $message = '
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
        </head>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2>' . __('Test Email from SecureAura', 'secure-aura') . '</h2>
            <p>' . __('This is a test email to confirm that email notifications are working correctly.', 'secure-aura') . '</p>
            <p>' . sprintf(__('Site: %s', 'secure-aura'), $site_name) . '</p>
            <p>' . sprintf(__('Sent at: %s', 'secure-aura'), current_time('mysql')) . '</p>
            <p>' . __('If you received this email, your notification settings are configured correctly.', 'secure-aura') . '</p>
        </body>
        </html>';
        
        $subject = sprintf(
            __('[%s] SecureAura Test Email', 'secure-aura'),
            $site_name
        );
        
        return wp_mail($this->notification_email, $subject, $message);
    }
}