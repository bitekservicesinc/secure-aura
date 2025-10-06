<?php
/**
 * Threat Alert Email Template
 *
 * This template is used for sending threat alert notifications
 *
 * @package    SecureAura
 * @subpackage SecureAura/templates/emails
 * @since      3.0.0
 * 
 * Available variables:
 * @var string $site_name    Site name
 * @var string $site_url     Site URL
 * @var array  $threat       Threat details
 * @var string $scan_date    Scan date/time
 * @var int    $threat_count Total threats found
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php _e('Security Threat Detected', 'secure-aura'); ?> - <?php echo esc_html($site_name); ?></title>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: #f3f4f6;
            color: #1f2937;
        }
        .email-container {
            max-width: 600px;
            margin: 40px auto;
            background: #ffffff;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .email-header {
            background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
            color: #ffffff;
            padding: 40px 30px;
            text-align: center;
        }
        .email-header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 700;
        }
        .alert-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 48px;
        }
        .email-body {
            padding: 40px 30px;
        }
        .alert-summary {
            background: #fef2f2;
            border-left: 4px solid #dc2626;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 6px;
        }
        .alert-summary h2 {
            margin: 0 0 15px 0;
            font-size: 20px;
            color: #991b1b;
        }
        .alert-summary p {
            margin: 0;
            font-size: 15px;
            color: #7f1d1d;
            line-height: 1.6;
        }
        .threat-details {
            background: #f9fafb;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
        }
        .threat-details h3 {
            margin: 0 0 20px 0;
            font-size: 18px;
            color: #1f2937;
        }
        .detail-row {
            display: flex;
            padding: 12px 0;
            border-bottom: 1px solid #e5e7eb;
        }
        .detail-row:last-child {
            border-bottom: none;
        }
        .detail-label {
            flex: 0 0 140px;
            font-weight: 600;
            color: #4b5563;
            font-size: 14px;
        }
        .detail-value {
            flex: 1;
            color: #1f2937;
            font-size: 14px;
            word-break: break-all;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-critical {
            background: #fee2e2;
            color: #991b1b;
        }
        .severity-high {
            background: #fef3c7;
            color: #92400e;
        }
        .severity-medium {
            background: #fef3c7;
            color: #78350f;
        }
        .severity-low {
            background: #dbeafe;
            color: #1e40af;
        }
        .action-buttons {
            text-align: center;
            margin: 30px 0;
        }
        .button {
            display: inline-block;
            padding: 14px 32px;
            background: #667eea;
            color: #ffffff !important;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 15px;
            margin: 0 5px;
            transition: background 0.3s;
        }
        .button:hover {
            background: #5568d3;
        }
        .button-secondary {
            background: #6b7280;
        }
        .button-secondary:hover {
            background: #4b5563;
        }
        .recommendations {
            background: #fffbeb;
            border-left: 4px solid #f59e0b;
            padding: 20px;
            margin: 30px 0;
            border-radius: 6px;
        }
        .recommendations h3 {
            margin: 0 0 15px 0;
            font-size: 16px;
            color: #92400e;
        }
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin: 8px 0;
            color: #78350f;
            font-size: 14px;
            line-height: 1.6;
        }
        .email-footer {
            background: #f9fafb;
            padding: 30px;
            text-align: center;
            border-top: 1px solid #e5e7eb;
        }
        .email-footer p {
            margin: 8px 0;
            font-size: 13px;
            color: #6b7280;
        }
        .email-footer a {
            color: #667eea;
            text-decoration: none;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin: 30px 0;
        }
        .stat-box {
            background: #f9fafb;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #e5e7eb;
        }
        .stat-number {
            font-size: 32px;
            font-weight: 700;
            color: #dc2626;
            margin: 0;
        }
        .stat-label {
            font-size: 13px;
            color: #6b7280;
            margin: 5px 0 0 0;
        }
    </style>
</head>
<body>
    <div class="email-container">
        <!-- Header -->
        <div class="email-header">
            <div class="alert-icon">⚠️</div>
            <h1><?php _e('Security Threat Detected!', 'secure-aura'); ?></h1>
        </div>
        
        <!-- Body -->
        <div class="email-body">
            <!-- Alert Summary -->
            <div class="alert-summary">
                <h2><?php _e('Immediate Action Required', 'secure-aura'); ?></h2>
                <p>
                    <?php printf(
                        _n(
                            'SecureAura has detected %d security threat on your website <strong>%s</strong>. Please review and take action immediately to protect your site.',
                            'SecureAura has detected %d security threats on your website <strong>%s</strong>. Please review and take action immediately to protect your site.',
                            $threat_count,
                            'secure-aura'
                        ),
                        $threat_count,
                        $site_name
                    ); ?>
                </p>
            </div>
            
            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-box">
                    <p class="stat-number"><?php echo esc_html($threat_count); ?></p>
                    <p class="stat-label"><?php _e('Threats Found', 'secure-aura'); ?></p>
                </div>
                <div class="stat-box">
                    <p class="stat-number" style="color: #f59e0b;">
                        <?php echo esc_html(ucfirst($threat['severity'] ?? 'medium')); ?>
                    </p>
                    <p class="stat-label"><?php _e('Severity Level', 'secure-aura'); ?></p>
                </div>
                <div class="stat-box">
                    <p class="stat-number" style="color: #667eea; font-size: 20px;">
                        <?php echo esc_html(date_i18n('H:i', strtotime($scan_date))); ?>
                    </p>
                    <p class="stat-label"><?php _e('Detected At', 'secure-aura'); ?></p>
                </div>
            </div>
            
            <!-- Threat Details -->
            <div class="threat-details">
                <h3><?php _e('Threat Information', 'secure-aura'); ?></h3>
                
                <div class="detail-row">
                    <div class="detail-label"><?php _e('Threat Type:', 'secure-aura'); ?></div>
                    <div class="detail-value"><?php echo esc_html($threat['type'] ?? __('Unknown', 'secure-aura')); ?></div>
                </div>
                
                <div class="detail-row">
                    <div class="detail-label"><?php _e('Severity:', 'secure-aura'); ?></div>
                    <div class="detail-value">
                        <span class="severity-badge severity-<?php echo esc_attr(strtolower($threat['severity'] ?? 'medium')); ?>">
                            <?php echo esc_html(ucfirst($threat['severity'] ?? 'medium')); ?>
                        </span>
                    </div>
                </div>
                
                <div class="detail-row">
                    <div class="detail-label"><?php _e('Affected File:', 'secure-aura'); ?></div>
                    <div class="detail-value">
                        <code><?php echo esc_html($threat['file_path'] ?? __('Multiple files', 'secure-aura')); ?></code>
                    </div>
                </div>
                
                <div class="detail-row">
                    <div class="detail-label"><?php _e('Detection Time:', 'secure-aura'); ?></div>
                    <div class="detail-value"><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($scan_date))); ?></div>
                </div>
                
                <?php if (!empty($threat['description'])) : ?>
                <div class="detail-row">
                    <div class="detail-label"><?php _e('Description:', 'secure-aura'); ?></div>
                    <div class="detail-value"><?php echo esc_html($threat['description']); ?></div>
                </div>
                <?php endif; ?>
            </div>
            
            <!-- Recommendations -->
            <div class="recommendations">
                <h3><?php _e('Recommended Actions', 'secure-aura'); ?></h3>
                <ul>
                    <li><?php _e('Review the threat details in your SecureAura dashboard', 'secure-aura'); ?></li>
                    <li><?php _e('Quarantine or remove the infected files immediately', 'secure-aura'); ?></li>
                    <li><?php _e('Check for any unauthorized changes to your site', 'secure-aura'); ?></li>
                    <li><?php _e('Update all WordPress core, themes, and plugins', 'secure-aura'); ?></li>
                    <li><?php _e('Change your WordPress admin passwords', 'secure-aura'); ?></li>
                    <li><?php _e('Run a full security scan after taking action', 'secure-aura'); ?></li>
                </ul>
            </div>
            
            <!-- Action Buttons -->
            <div class="action-buttons">
                <a href="<?php echo esc_url(admin_url('admin.php?page=secure-aura')); ?>" class="button">
                    <?php _e('View Dashboard', 'secure-aura'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=secure-aura&tab=threats')); ?>" class="button button-secondary">
                    <?php _e('View Threats', 'secure-aura'); ?>
                </a>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="email-footer">
            <p><strong><?php _e('SecureAura Security Plugin', 'secure-aura'); ?></strong></p>
            <p>
                <?php printf(
                    __('Protecting %s', 'secure-aura'),
                    '<a href="' . esc_url($site_url) . '">' . esc_html($site_name) . '</a>'
                ); ?>
            </p>
            <p>
                <?php printf(
                    __('To manage notification settings, visit %s', 'secure-aura'),
                    '<a href="' . esc_url(admin_url('admin.php?page=secure-aura-settings')) . '">' . __('Settings', 'secure-aura') . '</a>'
                ); ?>
            </p>
            <p style="margin-top: 20px; font-size: 12px;">
                <?php _e('This is an automated security alert. Please do not reply to this email.', 'secure-aura'); ?>
            </p>
        </div>
    </div>
</body>
</html>