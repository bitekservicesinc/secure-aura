<?php
/**
 * BiTek AI Security Guard - Settings Template
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

// Get current options
$instance = BiTek_AI_Security_Guard::get_instance();
$options = $instance->options ?? array();
?>

<div class="wrap bitek-settings">
    <div class="bitek-header">
        <h1><?php echo esc_html__('BiTek AI Security Settings', 'bitek-ai-security'); ?></h1>
        <p class="bitek-header-subtitle">
            <?php echo esc_html__('Configure your security protection settings', 'bitek-ai-security'); ?>
        </p>
    </div>

    <form method="post" action="">
        <?php wp_nonce_field('bitek_settings_nonce'); ?>

        <div class="bitek-settings-tabs">
            <nav class="nav-tab-wrapper">
                <a href="#general" class="nav-tab nav-tab-active"><?php echo esc_html__('General', 'bitek-ai-security'); ?></a>
                <a href="#firewall" class="nav-tab"><?php echo esc_html__('Firewall', 'bitek-ai-security'); ?></a>
                <a href="#ai-settings" class="nav-tab"><?php echo esc_html__('AI Engine', 'bitek-ai-security'); ?></a>
                <a href="#scanner" class="nav-tab"><?php echo esc_html__('Scanner', 'bitek-ai-security'); ?></a>
                <a href="#notifications" class="nav-tab"><?php echo esc_html__('Notifications', 'bitek-ai-security'); ?></a>
                <a href="#advanced" class="nav-tab"><?php echo esc_html__('Advanced', 'bitek-ai-security'); ?></a>
            </nav>

            <!-- General Settings -->
            <div id="general" class="tab-content active">
                <div class="bitek-settings-section">
                    <h2><?php echo esc_html__('Comment Protection', 'bitek-ai-security'); ?></h2>

                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php echo esc_html__('Comment Filtering', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[comment_filtering]" value="1" <?php checked(1, $options['comment_filtering'] ?? 1); ?> />
                                    <?php echo esc_html__('Enable comment spam protection', 'bitek-ai-security'); ?>
                                </label>
                                <p class="description"><?php echo esc_html__('Protects your site from spam and malicious comments', 'bitek-ai-security'); ?></p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th scope="row"><?php echo esc_html__('Keyword Filtering', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[keyword_filtering]" value="1" <?php checked(1, $options['keyword_filtering'] ?? 1); ?> />
                                    <?php echo esc_html__('Enable keyword-based filtering', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Blocked Keywords', 'bitek-ai-security'); ?></th>
                            <td>
                                <textarea name="bitek_ai_security_options[custom_keywords]" rows="10" cols="50" class="large-text"><?php echo esc_textarea($options['custom_keywords'] ?? ''); ?></textarea>
                                <p class="description"><?php echo esc_html__('Enter one keyword per line. These will be blocked in comments.', 'bitek-ai-security'); ?></p>
                                <p class="description">
                                    <strong><?php echo esc_html__('Keywords count:', 'bitek-ai-security'); ?></strong> 
                                    <span id="keyword-count"><?php echo count(array_filter(explode("\n", $options['custom_keywords'] ?? ''))); ?></span>
                                </p>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Blocked Message', 'bitek-ai-security'); ?></th>
                            <td>
                                <input type="text" name="bitek_ai_security_options[blocked_message]" value="<?php echo esc_attr($options['blocked_message'] ?? ''); ?>" class="regular-text" />
                                <p class="description"><?php echo esc_html__('Message shown to users when their comment is blocked.', 'bitek-ai-security'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Firewall Settings -->
            <div id="firewall" class="tab-content">
                <div class="bitek-settings-section">
                    <h2><?php echo esc_html__('Firewall Protection', 'bitek-ai-security'); ?></h2>

                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php echo esc_html__('Enable Firewall', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[firewall_enabled]" value="1" <?php checked(1, $options['firewall_enabled'] ?? 1); ?> />
                                    <?php echo esc_html__('Enable advanced firewall protection', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Rate Limiting', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[rate_limiting]" value="1" <?php checked(1, $options['rate_limiting'] ?? 1); ?> />
                                    <?php echo esc_html__('Enable rate limiting for requests', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Brute Force Protection', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[brute_force_protection]" value="1" <?php checked(1, $options['brute_force_protection'] ?? 1); ?> />
                                    <?php echo esc_html__('Protect against brute force login attempts', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('SQL Injection Protection', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[sql_injection_protection]" value="1" <?php checked(1, $options['sql_injection_protection'] ?? 1); ?> />
                                    <?php echo esc_html__('Block SQL injection attempts', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('XSS Protection', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[xss_protection]" value="1" <?php checked(1, $options['xss_protection'] ?? 1); ?> />
                                    <?php echo esc_html__('Block cross-site scripting attacks', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Whitelist IPs', 'bitek-ai-security'); ?></th>
                            <td>
                                <textarea name="bitek_ai_security_options[whitelist_ips]" rows="5" cols="50" class="regular-text"><?php echo esc_textarea($options['whitelist_ips'] ?? ''); ?></textarea>
                                <p class="description"><?php echo esc_html__('Enter one IP address per line. These IPs will never be blocked.', 'bitek-ai-security'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- AI Settings -->
            <div id="ai-settings" class="tab-content">
                <div class="bitek-settings-section">
                    <h2><?php echo esc_html__('AI Engine Configuration', 'bitek-ai-security'); ?></h2>

                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php echo esc_html__('Enable AI Analysis', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[ai_comment_enabled]" value="1" <?php checked(1, $options['ai_comment_enabled'] ?? 1); ?> />
                                    <?php echo esc_html__('Enable AI-powered comment analysis', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('HuggingFace API Key', 'bitek-ai-security'); ?></th>
                            <td>
                                <input type="password" name="bitek_ai_security_options[huggingface_api_key]" value="<?php echo esc_attr($options['huggingface_api_key'] ?? ''); ?>" class="regular-text" />
                                <p class="description">
                                    <?php echo wp_kses_post(__('Get your free API key from <a href="https://huggingface.co/settings/tokens" target="_blank">HuggingFace</a>', 'bitek-ai-security')); ?>
                                </p>
                                <?php if (!empty($options['huggingface_api_key'])) : ?>
                                    <p class="description" style="color: green;">
                                        <span class="dashicons dashicons-yes-alt"></span>
                                        <?php echo esc_html__('API key is configured', 'bitek-ai-security'); ?>
                                    </p>
                                <?php endif; ?>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('AI Model for Comments', 'bitek-ai-security'); ?></th>
                            <td>
                                <select name="bitek_ai_security_options[ai_model_comment]">
                                    <option value="unitary/toxic-bert" <?php selected('unitary/toxic-bert', $options['ai_model_comment'] ?? 'unitary/toxic-bert'); ?>>
                                        Toxic BERT (Recommended)
                                    </option>
                                    <option value="martin-ha/toxic-comment-model" <?php selected('martin-ha/toxic-comment-model', $options['ai_model_comment'] ?? ''); ?>>
                                        Toxic Comment Model
                                    </option>
                                    <option value="unitary/unbiased-toxic-roberta" <?php selected('unitary/unbiased-toxic-roberta', $options['ai_model_comment'] ?? ''); ?>>
                                        Unbiased Toxic RoBERTa
                                    </option>
                                </select>
                                <p class="description"><?php echo esc_html__('Choose the AI model for comment analysis', 'bitek-ai-security'); ?></p>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('AI Threshold', 'bitek-ai-security'); ?></th>
                            <td>
                                <input type="range" name="bitek_ai_security_options[ai_threshold]" value="<?php echo esc_attr($options['ai_threshold'] ?? 0.7); ?>" min="0.1" max="1.0" step="0.1" class="bitek-threshold-slider" />
                                <span class="bitek-threshold-value"><?php echo esc_html($options['ai_threshold'] ?? 0.7); ?></span>
                                <p class="description"><?php echo esc_html__('Higher values = stricter filtering (0.7 recommended)', 'bitek-ai-security'); ?></p>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('API Rate Limit', 'bitek-ai-security'); ?></th>
                            <td>
                                <input type="number" name="bitek_ai_security_options[ai_max_requests_per_hour]" value="<?php echo esc_attr($options['ai_max_requests_per_hour'] ?? 1000); ?>" min="100" max="10000" class="small-text" />
                                <p class="description"><?php echo esc_html__('Maximum AI API requests per hour', 'bitek-ai-security'); ?></p>
                            </td>
                        </tr>
                    </table>

                    <div class="bitek-ai-test">
                        <h3><?php echo esc_html__('Test AI Connection', 'bitek-ai-security'); ?></h3>
                        <p><?php echo esc_html__('Test your API key and model configuration', 'bitek-ai-security'); ?></p>
                        <button type="button" class="button button-secondary" id="test-ai-api">
                            <?php echo esc_html__('Test AI Connection', 'bitek-ai-security'); ?>
                        </button>
                        <div id="ai-test-result"></div>
                    </div>
                </div>
            </div>

            <!-- Scanner Settings -->
            <div id="scanner" class="tab-content">
                <div class="bitek-settings-section">
                    <h2><?php echo esc_html__('Security Scanner', 'bitek-ai-security'); ?></h2>

                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php echo esc_html__('Enable Scanner', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[malware_scanner]" value="1" <?php checked(1, $options['malware_scanner'] ?? 1); ?> />
                                    <?php echo esc_html__('Enable malware scanner', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Daily Scan', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[daily_scan]" value="1" <?php checked(1, $options['daily_scan'] ?? 1); ?> />
                                    <?php echo esc_html__('Run daily security scans', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('File Integrity Monitoring', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[file_change_detection]" value="1" <?php checked(1, $options['file_change_detection'] ?? 1); ?> />
                                    <?php echo esc_html__('Monitor file changes', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Scan Targets', 'bitek-ai-security'); ?></th>
                            <td>
                                <fieldset>
                                    <label>
                                        <input type="checkbox" name="bitek_ai_security_options[scan_core_files]" value="1" <?php checked(1, $options['scan_core_files'] ?? 1); ?> />
                                        <?php echo esc_html__('WordPress Core Files', 'bitek-ai-security'); ?>
                                    </label><br>
                                    <label>
                                        <input type="checkbox" name="bitek_ai_security_options[scan_plugins]" value="1" <?php checked(1, $options['scan_plugins'] ?? 1); ?> />
                                        <?php echo esc_html__('Plugin Files', 'bitek-ai-security'); ?>
                                    </label><br>
                                    <label>
                                        <input type="checkbox" name="bitek_ai_security_options[scan_themes]" value="1" <?php checked(1, $options['scan_themes'] ?? 1); ?> />
                                        <?php echo esc_html__('Theme Files', 'bitek-ai-security'); ?>
                                    </label><br>
                                    <label>
                                        <input type="checkbox" name="bitek_ai_security_options[scan_uploads]" value="1" <?php checked(1, $options['scan_uploads'] ?? 1); ?> />
                                        <?php echo esc_html__('Upload Directory', 'bitek-ai-security'); ?>
                                    </label>
                                </fieldset>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Notifications -->
            <div id="notifications" class="tab-content">
                <div class="bitek-settings-section">
                    <h2><?php echo esc_html__('Notification Settings', 'bitek-ai-security'); ?></h2>

                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php echo esc_html__('Email Notifications', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[email_notifications]" value="1" <?php checked(1, $options['email_notifications'] ?? 1); ?> />
                                    <?php echo esc_html__('Enable email notifications', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Admin Email', 'bitek-ai-security'); ?></th>
                            <td>
                                <input type="email" name="bitek_ai_security_options[admin_email]" value="<?php echo esc_attr($options['admin_email'] ?? get_option('admin_email')); ?>" class="regular-text" />
                                <p class="description"><?php echo esc_html__('Email address for security notifications', 'bitek-ai-security'); ?></p>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Notification Threshold', 'bitek-ai-security'); ?></th>
                            <td>
                                <select name="bitek_ai_security_options[notification_threshold]">
                                    <option value="low" <?php selected('low', $options['notification_threshold'] ?? 'medium'); ?>>
                                        <?php echo esc_html__('Low - All events', 'bitek-ai-security'); ?>
                                    </option>
                                    <option value="medium" <?php selected('medium', $options['notification_threshold'] ?? 'medium'); ?>>
                                        <?php echo esc_html__('Medium - Important events only', 'bitek-ai-security'); ?>
                                    </option>
                                    <option value="high" <?php selected('high', $options['notification_threshold'] ?? 'medium'); ?>>
                                        <?php echo esc_html__('High - Critical events only', 'bitek-ai-security'); ?>
                                    </option>
                                </select>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Slack Webhook', 'bitek-ai-security'); ?></th>
                            <td>
                                <input type="url" name="bitek_ai_security_options[slack_webhook]" value="<?php echo esc_attr($options['slack_webhook'] ?? ''); ?>" class="regular-text" />
                                <p class="description"><?php echo esc_html__('Optional: Slack webhook URL for notifications', 'bitek-ai-security'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>

            <!-- Advanced Settings -->
            <div id="advanced" class="tab-content">
                <div class="bitek-settings-section">
                    <h2><?php echo esc_html__('Advanced Settings', 'bitek-ai-security'); ?></h2>

                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php echo esc_html__('Logging', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[logging_enabled]" value="1" <?php checked(1, $options['logging_enabled'] ?? 1); ?> />
                                    <?php echo esc_html__('Enable security logging', 'bitek-ai-security'); ?>
                                </label><br>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[detailed_logging]" value="1" <?php checked(1, $options['detailed_logging'] ?? 0); ?> />
                                    <?php echo esc_html__('Enable detailed logging (may impact performance)', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Log Retention', 'bitek-ai-security'); ?></th>
                            <td>
                                <input type="number" name="bitek_ai_security_options[log_retention_days]" value="<?php echo esc_attr($options['log_retention_days'] ?? 30); ?>" min="1" max="365" class="small-text" />
                                <?php echo esc_html__('days', 'bitek-ai-security'); ?>
                                <p class="description"><?php echo esc_html__('Number of days to keep security logs', 'bitek-ai-security'); ?></p>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Performance Monitoring', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[performance_monitoring]" value="1" <?php checked(1, $options['performance_monitoring'] ?? 1); ?> />
                                    <?php echo esc_html__('Monitor plugin performance impact', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('Cache Settings', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[cache_enabled]" value="1" <?php checked(1, $options['cache_enabled'] ?? 1); ?> />
                                    <?php echo esc_html__('Enable caching for better performance', 'bitek-ai-security'); ?>
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th scope="row"><?php echo esc_html__('XMLRPC', 'bitek-ai-security'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bitek_ai_security_options[xmlrpc_enabled]" value="1" <?php checked(1, $options['xmlrpc_enabled'] ?? 0); ?> />
                                    <?php echo esc_html__('Enable XMLRPC (not recommended)', 'bitek-ai-security'); ?>
                                </label>
                                <p class="description"><?php echo esc_html__('XMLRPC is disabled by default for security', 'bitek-ai-security'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>

        <?php submit_button(__('Save Settings', 'bitek-ai-security'), 'primary', 'submit', true, array('id' => 'submit-settings')); ?>
    </form>
</div>

<script type="text/javascript">
jQuery(document).ready(function($) {
    // Tab switching
    $('.nav-tab').on('click', function(e) {
        e.preventDefault();
        var target = $(this).attr('href');

        $('.nav-tab').removeClass('nav-tab-active');
        $(this).addClass('nav-tab-active');

        $('.tab-content').removeClass('active');
        $(target).addClass('active');
    });

    // Update keyword count
    $('textarea[name="bitek_ai_security_options[custom_keywords]"]').on('input', function() {
        var keywords = $(this).val().split('\n').filter(function(line) {
            return line.trim() !== '';
        });
        $('#keyword-count').text(keywords.length);
    });

    // Update threshold value display
    $('.bitek-threshold-slider').on('input', function() {
        $('.bitek-threshold-value').text($(this).val());
    });

    // Test AI API
    $('#test-ai-api').on('click', function() {
        var $button = $(this);
        var $result = $('#ai-test-result');
        var originalText = $button.text();

        $button.prop('disabled', true).text('<?php echo esc_js(__('Testing...', 'bitek-ai-security')); ?>');
        $result.html('');

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'bitek_test_api',
                nonce: '<?php echo wp_create_nonce('bitek_ajax_nonce'); ?>'
            },
            success: function(response) {
                if (response.success) {
                    $result.html('<div class="notice notice-success inline"><p><strong><?php echo esc_js(__('Success!', 'bitek-ai-security')); ?></strong> ' + response.data.message + '</p></div>');
                } else {
                    $result.html('<div class="notice notice-error inline"><p><strong><?php echo esc_js(__('Error:', 'bitek-ai-security')); ?></strong> ' + response.data + '</p></div>');
                }
            },
            error: function() {
                $result.html('<div class="notice notice-error inline"><p><strong><?php echo esc_js(__('Error:', 'bitek-ai-security')); ?></strong> <?php echo esc_js(__('Connection failed', 'bitek-ai-security')); ?></p></div>');
            },
            complete: function() {
                $button.prop('disabled', false).text(originalText);
            }
        });
    });

    // Form validation
    $('#submit-settings').on('click', function(e) {
        var apiKey = $('input[name="bitek_ai_security_options[huggingface_api_key]"]').val();
        var aiEnabled = $('input[name="bitek_ai_security_options[ai_comment_enabled]"]').is(':checked');

        if (aiEnabled && !apiKey) {
            if (!confirm('<?php echo esc_js(__('AI analysis is enabled but no API key is provided. Continue without AI protection?', 'bitek-ai-security')); ?>')) {
                e.preventDefault();
                $('a[href="#ai-settings"]').click();
                $('input[name="bitek_ai_security_options[huggingface_api_key]"]').focus();
            }
        }
    });
});
</script>