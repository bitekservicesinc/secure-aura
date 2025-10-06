<?php
/**
 * Scan Report Email Template
 * 
 * This template is used for sending scan completion reports
 *
 * @package    SecureAura
 * @subpackage SecureAura/templates/emails
 * @since      3.0.0
 * 
 * Available variables:
 * @var string $site_name       Site name
 * @var string $site_url        Site URL
 * @var array  $scan_results    Scan results data
 * @var string $scan_date       Scan date/time
 * @var int    $files_scanned   Number of files scanned
 * @var int    $threats_found   Number of threats found
 * @var string $scan_duration   Scan duration
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

$has_threats = ($threats_found > 0);
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php _e('Security Scan Report', 'secure-aura'); ?> - <?php echo esc_html($site_name); ?></title>
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
            background: linear-gradient(135deg, 
                <?php echo $has_threats ? '#dc2626 0%, #991b1b 100%' : '#667eea 0%, #764ba2 100%'; ?>);
            color: #ffffff;
            padding: 40px 30px;
            text-align: center;
        }
        .email-header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 700;
        }
        .scan-icon {
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
        .scan-summary {
            background: <?php echo $has_threats ? '#fef2f2' : '#ecfdf5'; ?>;
            border-left: 4px solid <?php echo $has_threats ? '#dc2626' : '#10b981'; ?>;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 6px;
        }
        .scan-summary h2 {
            margin: 0 0 15px 0;
            font-size: 20px;
            color: <?php echo $has_threats ? '#991b1b' : '#065f46'; ?>;
        }
        .scan-summary p {
            margin: 0;
            font-size: 15px;
            color: <?php echo $has_threats ? '#7f1d1d' : '#047857'; ?>;
            line-height: 1.6;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin: 30px 0;
        }
        .stat-box {
            background: #f9fafb;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            border: 2px solid #e5e7eb;
        }
        .stat-number {
            font-size: 36px;
            font-weight: 700;
            margin: 0;
        }
        .stat-number.success {
            color: #10b981;
        }
        .stat-number.danger {
            color: #dc2626;
        }
        .stat-number.info {
            color: #667eea;
        }
        .stat-label {
            font-size: 13px;
            color: #6b7280;
            margin: 8px 0 0 0;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .scan-details {
            background: #f9fafb;
            border-radius: 8px;
            padding: 25px;
            margin: 30px 0;
        }
        .scan-details h3 {
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
            flex: 0 0 150px;
            font-weight: 600;
            color: #4b5563;
            font-size: 14px;
        }
        .detail-value {
            flex: 1;
            color: #1f2937;
            font-size: 14px;
        }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e5e7eb;
            border-radius: 4px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: <?php echo $has_threats ? '#dc2626' : '#10b981'; ?>;
            transition: width 0.3s ease;
        }
        .threat-list {
            background: #fef2f2;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .threat-item {
            padding: 15px;
            background: #fff;
            border-left: 3px solid #dc2626;
            margin-bottom: 12px;
            border-radius: 4px;
        }
        .threat-item:last-child {
            margin-bottom: 0;
        }
        .threat-item h4 {
            margin: 0 0 8px 0;
            font-size: 15px;
            color: #991b1b;
        }
        .threat-item p {
            margin: 0;
            font-size: 13px;
            color: #6b7280;
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
        }
        .button:hover {
            background: #5568d3;
        }
        .button-success {
            background: #10b981;
        }
        .button-success:hover {
            background: #059669;
        }
        .recommendations {
            background: #eff6ff;
            border-left: 4px solid #3b82f6;
            padding: 20px;
            margin: 30px 0;
            border-radius: 6px;
        }
        .recommendations h3 {
            margin: 0 0 15px 0;
            font-size: 16px;
            color: #1e40af;
        }
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        .recommendations li {
            margin: 8px 0;
            color: #1e3a8a;
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
        .success-badge {
            display: inline-block;
            background: #d1fae5;
            color: #065f46;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="email-container">
        <!-- Header -->
        <div class="email-header">
            <div class="scan-icon"><?php echo $has_threats ? '⚠️' : '✅'; ?></div>
            <h1><?php _e('Security Scan Completed', 'secure-aura'); ?></h1>
            <?php if (!$has_threats) : ?>
                <span class="success-badge"><?php _e('All Clear', 'secure-aura'); ?></span>
            <?php endif; ?>
        </div>
        
        <!-- Body -->
        <div class="email-body">
            <!-- Scan Summary -->
            <div class="scan-summary">
                <h2>
                    <?php echo $has_threats 
                        ? __('Threats Detected', 'secure-aura') 
                        : __('No Threats Found', 'secure-aura'); ?>
                </h2>
                <p>
                    <?php if ($has_threats) : ?>
                        <?php printf(
                            _n(
                                'The security scan found %d potential threat on your website. Please review and take appropriate action.',
                                'The security scan found %d potential threats on your website. Please review and take appropriate action.',
                                $threats_found,
                                'secure-aura'
                            ),
                            $threats_found
                        ); ?>
                    <?php else : ?>
                        <?php _e('Great news! The security scan completed successfully and found no threats on your website. Your site is secure.', 'secure-aura'); ?>
                    <?php endif; ?>
                </p>
            </div>
            
            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-box">
                    <p class="stat-number info"><?php echo number_format($files_scanned); ?></p>
                    <p class="stat-label"><?php _e('Files Scanned', 'secure-aura'); ?></p>
                </div>
                <div class="stat-box">
                    <p class="stat-number <?php echo $has_threats ? 'danger' : 'success'; ?>">
                        <?php echo number_format($threats_found); ?>
                    </p>
                    <p class="stat-label"><?php _e('Threats Found', 'secure-aura'); ?></p>
                </div>
            </div>
            
            <!-- Scan Details -->
            <div class="scan-details">
                <h3><?php _e('Scan Information', 'secure-aura'); ?></h3>
                
                <div class="detail-row">
                    <div class="detail-label"><?php _e('Scan Type:', 'secure-aura'); ?></div>
                    <div class="detail-value"><?php echo esc_html($scan_results['scan_type'] ?? __('Full Scan', 'secure-aura')); ?></div>
                </div>
                
                <div class="detail-row">
                    <div class="detail-label"><?php _e('Completed At:', 'secure-aura'); ?></div>
                    <div class="detail-value"><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($scan_date))); ?></div>
                </div>
                
                <div class="detail-row">
                    <div class="detail-label"><?php _e('Duration:', 'secure-aura'); ?></div>
                    <div class="detail-value"><?php echo esc_html($scan_duration); ?></div>
                </div>
                
                <div class="detail-row">
                    <div class="detail-label"><?php _e('Files Scanned:', 'secure-aura'); ?></div>
                    <div class="detail-value"><?php echo number_format($files_scanned); ?></div>
                </div>
                
                <div class="detail-row">
                    <div class="detail-label"><?php _e('Scan Progress:', 'secure-aura'); ?></div>
                    <div class="detail-value">
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 100%;"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <?php if ($has_threats && !empty($scan_results['threats'])) : ?>
            <!-- Threat List -->
            <div class="threat-list">
                <h3 style="margin-top: 0; color: #991b1b;"><?php _e('Detected Threats', 'secure-aura'); ?></h3>
                <?php 
                $display_threats = array_slice($scan_results['threats'], 0, 5);
                foreach ($display_threats as $threat) : 
                ?>
                    <div class="threat-item">
                        <h4><?php echo esc_html($threat['type'] ?? __('Unknown Threat', 'secure-aura')); ?></h4>
                        <p><strong><?php _e('File:', 'secure-aura'); ?></strong> <?php echo esc_html($threat['file_path'] ?? __('Unknown', 'secure-aura')); ?></p>
                        <?php if (!empty($threat['description'])) : ?>
                            <p><?php echo esc_html($threat['description']); ?></p>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
                
                <?php if (count($scan_results['threats']) > 5) : ?>
                    <p style="text-align: center; margin: 15px 0 0 0; color: #6b7280; font-size: 13px;">
                        <?php printf(__('+ %d more threats', 'secure-aura'), count($scan_results['threats']) - 5); ?>
                    </p>
                <?php endif; ?>
            </div>
            <?php endif; ?>
            
            <!-- Recommendations -->
            <div class="recommendations">
                <h3><?php _e('Recommended Next Steps', 'secure-aura'); ?></h3>
                <ul>
                    <?php if ($has_threats) : ?>
                        <li><?php _e('Review all detected threats in your dashboard', 'secure-aura'); ?></li>
                        <li><?php _e('Quarantine or remove infected files', 'secure-aura'); ?></li>
                        <li><?php _e('Update all WordPress core, themes, and plugins', 'secure-aura'); ?></li>
                        <li><?php _e('Change your admin passwords', 'secure-aura'); ?></li>
                        <li><?php _e('Run another scan after remediation', 'secure-aura'); ?></li>
                    <?php else : ?>
                        <li><?php _e('Keep your WordPress, themes, and plugins up to date', 'secure-aura'); ?></li>
                        <li><?php _e('Schedule regular security scans', 'secure-aura'); ?></li>
                        <li><?php _e('Review your firewall settings', 'secure-aura'); ?></li>
                        <li><?php _e('Monitor your site activity regularly', 'secure-aura'); ?></li>
                    <?php endif; ?>
                </ul>
            </div>
            
            <!-- Action Buttons -->
            <div class="action-buttons">
                <a href="<?php echo esc_url(admin_url('admin.php?page=secure-aura')); ?>" 
                   class="button <?php echo !$has_threats ? 'button-success' : ''; ?>">
                    <?php _e('View Full Report', 'secure-aura'); ?>
                </a>
                <?php if ($has_threats) : ?>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=secure-aura&tab=threats')); ?>" 
                       class="button">
                        <?php _e('View Threats', 'secure-aura'); ?>
                    </a>
                <?php endif; ?>
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
                    __('Next scheduled scan: %s', 'secure-aura'),
                    '<strong>' . esc_html($scan_results['next_scan'] ?? __('Not scheduled', 'secure-aura')) . '</strong>'
                ); ?>
            </p>
            <p>
                <?php printf(
                    __('To manage notification settings, visit %s', 'secure-aura'),
                    '<a href="' . esc_url(admin_url('admin.php?page=secure-aura-settings')) . '">' . __('Settings', 'secure-aura') . '</a>'
                ); ?>
            </p>
            <p style="margin-top: 20px; font-size: 12px;">
                <?php _e('This is an automated security report. Please do not reply to this email.', 'secure-aura'); ?>
            </p>
        </div>
    </div>
</body>
</html>