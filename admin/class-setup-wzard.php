<?php
/**
 * SecureAura Setup Wizard
 *
 * File: admin/class-setup-wizard.php
 * Path: /wp-content/plugins/secure-aura/admin/class-setup-wizard.php
 *
 * Handles the initial setup wizard for configuring the plugin
 *
 * @package    SecureAura
 * @subpackage SecureAura/admin
 * @since      3.0.0
 * @author     Bitekservices
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

class Secure_Aura_Setup_Wizard {
    
    /**
     * Setup steps
     *
     * @var array
     */
    private $steps;
    
    /**
     * Current step
     *
     * @var string
     */
    private $current_step;
    
    /**
     * Initialize the setup wizard
     *
     * @since 3.0.0
     */
    public function __construct() {
        $this->steps = [
            'welcome' => [
                'name' => __('Welcome', 'secure-aura'),
                'view' => [$this, 'setup_welcome']
            ],
            'security-level' => [
                'name' => __('Security Level', 'secure-aura'),
                'view' => [$this, 'setup_security_level']
            ],
            'firewall' => [
                'name' => __('Firewall', 'secure-aura'),
                'view' => [$this, 'setup_firewall']
            ],
            'scanner' => [
                'name' => __('Scanner', 'secure-aura'),
                'view' => [$this, 'setup_scanner']
            ],
            'notifications' => [
                'name' => __('Notifications', 'secure-aura'),
                'view' => [$this, 'setup_notifications']
            ],
            'complete' => [
                'name' => __('Complete', 'secure-aura'),
                'view' => [$this, 'setup_complete']
            ]
        ];
        
        $this->current_step = isset($_GET['step']) ? sanitize_key($_GET['step']) : 'welcome';
        
        add_action('admin_menu', [$this, 'admin_menus']);
        add_action('admin_init', [$this, 'setup_wizard_actions']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
    }
    
    /**
     * Enqueue setup wizard scripts and styles
     *
     * @since 3.0.0
     */
    public function enqueue_scripts($hook) {
        if ($hook !== 'dashboard_page_secure-aura-setup') {
            return;
        }
        
        wp_enqueue_style(
            'secure-aura-setup-wizard',
            SECURE_AURA_PLUGIN_URL . 'assets/css/setup-wizard.css',
            [],
            SECURE_AURA_VERSION
        );
        
        wp_enqueue_script(
            'secure-aura-setup-wizard',
            SECURE_AURA_PLUGIN_URL . 'assets/js/setup-wizard.js',
            ['jquery'],
            SECURE_AURA_VERSION,
            true
        );
    }
    
    /**
     * Add setup wizard to admin menu
     *
     * @since 3.0.0
     */
    public function admin_menus() {
        // Only show if setup is not complete
        if (get_option('secure_aura_setup_complete')) {
            return;
        }
        
        add_dashboard_page(
            __('SecureAura Setup', 'secure-aura'),
            __('SecureAura Setup', 'secure-aura'),
            'manage_options',
            'secure-aura-setup',
            [$this, 'setup_wizard']
        );
    }
    
    /**
     * Handle setup wizard actions
     *
     * @since 3.0.0
     */
    public function setup_wizard_actions() {
        if (isset($_POST['save_step']) && isset($_POST['secure_aura_setup_nonce'])) {
            if (!wp_verify_nonce($_POST['secure_aura_setup_nonce'], 'secure_aura_setup')) {
                wp_die(__('Security check failed', 'secure-aura'));
            }
            
            $this->save_step();
        }
        
        // Handle skip setup
        if (isset($_GET['skip_setup']) && wp_verify_nonce($_GET['_wpnonce'], 'skip_setup')) {
            update_option('secure_aura_setup_complete', true);
            wp_safe_redirect(admin_url('admin.php?page=secure-aura'));
            exit;
        }
    }
    
    /**
     * Save current step data
     *
     * @since 3.0.0
     */
    private function save_step() {
        $settings = get_option('secure_aura_settings', []);
        
        switch ($this->current_step) {
            case 'security-level':
                $settings['security_level'] = sanitize_text_field($_POST['security_level'] ?? 'enhanced');
                break;
                
            case 'firewall':
                $settings['quantum_firewall_enabled'] = isset($_POST['firewall_enabled']);
                $settings['brute_force_protection'] = isset($_POST['brute_force_protection']);
                $settings['sql_injection_protection'] = isset($_POST['sql_injection_protection']);
                $settings['xss_protection'] = isset($_POST['xss_protection']);
                $settings['rate_limiting_enabled'] = isset($_POST['rate_limiting']);
                break;
                
            case 'scanner':
                $settings['real_time_scanning_enabled'] = isset($_POST['real_time_scan']);
                $settings['scan_frequency'] = sanitize_text_field($_POST['scan_frequency'] ?? 'daily');
                $settings['quarantine_malware'] = isset($_POST['quarantine_malware']);
                $settings['auto_clean_infections'] = isset($_POST['auto_clean']);
                break;
                
            case 'notifications':
                $notification_email = sanitize_email($_POST['notification_email'] ?? get_option('admin_email'));
                update_option('secure_aura_notification_email', $notification_email);
                $settings['notify_on_threat'] = isset($_POST['notify_threat']);
                $settings['notify_on_scan'] = isset($_POST['notify_scan']);
                $settings['notify_on_update'] = isset($_POST['notify_update']);
                break;
                
            case 'complete':
                $settings['setup_complete'] = true;
                update_option('secure_aura_setup_complete', true);
                update_option('secure_aura_setup_completed_at', current_time('mysql'));
                
                // Run initial scan if requested
                if (isset($_POST['run_initial_scan'])) {
                    $this->schedule_initial_scan();
                }
                
                // Redirect to dashboard
                wp_safe_redirect(admin_url('admin.php?page=secure-aura&setup=complete'));
                exit;
        }
        
        update_option('secure_aura_settings', $settings);
        
        // Redirect to next step
        $next_step = $this->get_next_step();
        if ($next_step) {
            wp_safe_redirect(admin_url('admin.php?page=secure-aura-setup&step=' . $next_step));
            exit;
        }
    }
    
    /**
     * Get next step
     *
     * @since 3.0.0
     * @return string|bool Next step key or false
     */
    private function get_next_step() {
        $keys = array_keys($this->steps);
        $current_index = array_search($this->current_step, $keys);
        
        if ($current_index !== false && isset($keys[$current_index + 1])) {
            return $keys[$current_index + 1];
        }
        
        return false;
    }
    
    /**
     * Get previous step
     *
     * @since 3.0.0
     * @return string|bool Previous step key or false
     */
    private function get_previous_step() {
        $keys = array_keys($this->steps);
        $current_index = array_search($this->current_step, $keys);
        
        if ($current_index !== false && $current_index > 0) {
            return $keys[$current_index - 1];
        }
        
        return false;
    }
    
    /**
     * Display setup wizard
     *
     * @since 3.0.0
     */
    public function setup_wizard() {
        ?>
        <div class="wrap secure-aura-setup-wizard">
            <h1><?php _e('SecureAura Setup Wizard', 'secure-aura'); ?></h1>
            
            <div class="secure-aura-setup-content">
                <!-- Progress Steps -->
                <ul class="secure-aura-setup-steps">
                    <?php foreach ($this->steps as $step_key => $step) : 
                        $class = '';
                        if ($step_key === $this->current_step) {
                            $class = 'active';
                        } elseif (array_search($step_key, array_keys($this->steps)) < array_search($this->current_step, array_keys($this->steps))) {
                            $class = 'done';
                        }
                    ?>
                        <li class="<?php echo esc_attr($class); ?>">
                            <span><?php echo esc_html($step['name']); ?></span>
                        </li>
                    <?php endforeach; ?>
                </ul>
                
                <!-- Step Content -->
                <div class="secure-aura-setup-step">
                    <?php
                    if (isset($this->steps[$this->current_step])) {
                        call_user_func($this->steps[$this->current_step]['view']);
                    }
                    ?>
                </div>
            </div>
        </div>
        <?php
    }
    
    /**
     * Welcome step
     *
     * @since 3.0.0
     */
    private function setup_welcome() {
        ?>
        <div class="secure-aura-setup-welcome">
            <div class="secure-aura-welcome-header">
                <h2><?php _e('Welcome to SecureAura', 'secure-aura'); ?></h2>
                <p class="lead"><?php _e('Thank you for choosing SecureAura to protect your WordPress site. This wizard will help you configure the essential security settings in just a few minutes.', 'secure-aura'); ?></p>
            </div>
            
            <div class="secure-aura-features-overview">
                <h3><?php _e('What SecureAura Will Do:', 'secure-aura'); ?></h3>
                <div class="feature-grid">
                    <div class="feature-item">
                        <span class="dashicons dashicons-shield-alt"></span>
                        <h4><?php _e('Malware Protection', 'secure-aura'); ?></h4>
                        <p><?php _e('Protect against malware and hacking attempts', 'secure-aura'); ?></p>
                    </div>
                    <div class="feature-item">
                        <span class="dashicons dashicons-admin-network"></span>
                        <h4><?php _e('Firewall Protection', 'secure-aura'); ?></h4>
                        <p><?php _e('Block malicious IP addresses and traffic', 'secure-aura'); ?></p>
                    </div>
                    <div class="feature-item">
                        <span class="dashicons dashicons-search"></span>
                        <h4><?php _e('Security Scanning', 'secure-aura'); ?></h4>
                        <p><?php _e('Scan your site for vulnerabilities', 'secure-aura'); ?></p>
                    </div>
                    <div class="feature-item">
                        <span class="dashicons dashicons-visibility"></span>
                        <h4><?php _e('File Monitoring', 'secure-aura'); ?></h4>
                        <p><?php _e('Monitor file changes and suspicious activity', 'secure-aura'); ?></p>
                    </div>
                    <div class="feature-item">
                        <span class="dashicons dashicons-email-alt"></span>
                        <h4><?php _e('Instant Alerts', 'secure-aura'); ?></h4>
                        <p><?php _e('Get notified about security threats', 'secure-aura'); ?></p>
                    </div>
                    <div class="feature-item">
                        <span class="dashicons dashicons-chart-line"></span>
                        <h4><?php _e('Real-time Reports', 'secure-aura'); ?></h4>
                        <p><?php _e('Detailed security analytics and reports', 'secure-aura'); ?></p>
                    </div>
                </div>
            </div>
            
            <div class="secure-aura-setup-actions">
                <form method="post">
                    <?php wp_nonce_field('secure_aura_setup', 'secure_aura_setup_nonce'); ?>
                    <input type="hidden" name="save_step" value="1">
                    <button type="submit" class="button button-primary button-hero">
                        <?php _e('Let\'s Get Started', 'secure-aura'); ?>
                        <span class="dashicons dashicons-arrow-right-alt"></span>
                    </button>
                </form>
                <a href="<?php echo wp_nonce_url(admin_url('admin.php?page=secure-aura-setup&skip_setup=1'), 'skip_setup'); ?>" class="button button-link">
                    <?php _e('Skip Setup (Not Recommended)', 'secure-aura'); ?>
                </a>
            </div>
        </div>
        <?php
    }
    
    /**
     * Security level step
     *
     * @since 3.0.0
     */
    private function setup_security_level() {
        $current_level = get_option('secure_aura_settings')['security_level'] ?? 'enhanced';
        ?>
        <div class="secure-aura-setup-security-level">
            <h2><?php _e('Choose Your Security Level', 'secure-aura'); ?></h2>
            <p><?php _e('Select the security level that best fits your needs. You can change this later.', 'secure-aura'); ?></p>
            
            <form method="post" class="secure-aura-setup-form">
                <?php wp_nonce_field('secure_aura_setup', 'secure_aura_setup_nonce'); ?>
                <input type="hidden" name="save_step" value="1">
                
                <div class="security-level-options">
                    <label class="security-level-option <?php echo $current_level === 'basic' ? 'selected' : ''; ?>">
                        <input type="radio" name="security_level" value="basic" <?php checked($current_level, 'basic'); ?>>
                        <div class="option-content">
                            <h3><?php _e('Basic', 'secure-aura'); ?></h3>
                            <p><?php _e('Essential protection for small sites', 'secure-aura'); ?></p>
                            <ul>
                                <li><?php _e('Basic firewall protection', 'secure-aura'); ?></li>
                                <li><?php _e('Weekly security scans', 'secure-aura'); ?></li>
                                <li><?php _e('Basic threat detection', 'secure-aura'); ?></li>
                            </ul>
                        </div>
                    </label>
                    
                    <label class="security-level-option <?php echo $current_level === 'enhanced' ? 'selected' : ''; ?>">
                        <input type="radio" name="security_level" value="enhanced" <?php checked($current_level, 'enhanced'); ?>>
                        <div class="option-content">
                            <h3><?php _e('Enhanced', 'secure-aura'); ?> <span class="recommended"><?php _e('Recommended', 'secure-aura'); ?></span></h3>
                            <p><?php _e('Comprehensive protection for most sites', 'secure-aura'); ?></p>
                            <ul>
                                <li><?php _e('Advanced firewall with rate limiting', 'secure-aura'); ?></li>
                                <li><?php _e('Daily security scans', 'secure-aura'); ?></li>
                                <li><?php _e('Real-time threat detection', 'secure-aura'); ?></li>
                                <li><?php _e('File integrity monitoring', 'secure-aura'); ?></li>
                            </ul>
                        </div>
                    </label>
                    
                    <label class="security-level-option <?php echo $current_level === 'maximum' ? 'selected' : ''; ?>">
                        <input type="radio" name="security_level" value="maximum" <?php checked($current_level, 'maximum'); ?>>
                        <div class="option-content">
                            <h3><?php _e('Maximum', 'secure-aura'); ?></h3>
                            <p><?php _e('Highest security for critical sites', 'secure-aura'); ?></p>
                            <ul>
                                <li><?php _e('All Enhanced features', 'secure-aura'); ?></li>
                                <li><?php _e('Aggressive threat blocking', 'secure-aura'); ?></li>
                                <li><?php _e('Continuous monitoring', 'secure-aura'); ?></li>
                                <li><?php _e('Strict access controls', 'secure-aura'); ?></li>
                            </ul>
                        </div>
                    </label>
                </div>
                
                <div class="secure-aura-setup-navigation">
                    <?php if ($prev = $this->get_previous_step()) : ?>
                        <a href="<?php echo admin_url('admin.php?page=secure-aura-setup&step=' . $prev); ?>" class="button button-secondary">
                            <span class="dashicons dashicons-arrow-left-alt"></span>
                            <?php _e('Previous', 'secure-aura'); ?>
                        </a>
                    <?php endif; ?>
                    <button type="submit" class="button button-primary">
                        <?php _e('Continue', 'secure-aura'); ?>
                        <span class="dashicons dashicons-arrow-right-alt"></span>
                    </button>
                </div>
            </form>
        </div>
        <?php
    }
    
    /**
     * Firewall setup step
     *
     * @since 3.0.0
     */
    private function setup_firewall() {
        $settings = get_option('secure_aura_settings', []);
        ?>
        <div class="secure-aura-setup-firewall">
            <h2><?php _e('Configure Firewall Protection', 'secure-aura'); ?></h2>
            <p><?php _e('Enable the firewall features you want to activate.', 'secure-aura'); ?></p>
            
            <form method="post" class="secure-aura-setup-form">
                <?php wp_nonce_field('secure_aura_setup', 'secure_aura_setup_nonce'); ?>
                <input type="hidden" name="save_step" value="1">
                
                <div class="firewall-options">
                    <label class="firewall-option">
                        <input type="checkbox" name="firewall_enabled" value="1" <?php checked($settings['quantum_firewall_enabled'] ?? true); ?>>
                        <div class="option-info">
                            <h4><?php _e('Enable Quantum Firewall', 'secure-aura'); ?></h4>
                            <p><?php _e('Advanced firewall protection against malicious requests', 'secure-aura'); ?></p>
                        </div>
                    </label>
                    
                    <label class="firewall-option">
                        <input type="checkbox" name="brute_force_protection" value="1" <?php checked($settings['brute_force_protection'] ?? true); ?>>
                        <div class="option-info">
                            <h4><?php _e('Brute Force Protection', 'secure-aura'); ?></h4>
                            <p><?php _e('Block automated login attempts', 'secure-aura'); ?></p>
                        </div>
                    </label>
                    
                    <label class="firewall-option">
                        <input type="checkbox" name="sql_injection_protection" value="1" <?php checked($settings['sql_injection_protection'] ?? true); ?>>
                        <div class="option-info">
                            <h4><?php _e('SQL Injection Protection', 'secure-aura'); ?></h4>
                            <p><?php _e('Prevent database attacks', 'secure-aura'); ?></p>
                        </div>
                    </label>
                    
                    <label class="firewall-option">
                        <input type="checkbox" name="xss_protection" value="1" <?php checked($settings['xss_protection'] ?? true); ?>>
                        <div class="option-info">
                            <h4><?php _e('XSS Protection', 'secure-aura'); ?></h4>
                            <p><?php _e('Block cross-site scripting attacks', 'secure-aura'); ?></p>
                        </div>
                    </label>
                    
                    <label class="firewall-option">
                        <input type="checkbox" name="rate_limiting" value="1" <?php checked($settings['rate_limiting_enabled'] ?? true); ?>>
                        <div class="option-info">
                            <h4><?php _e('Rate Limiting', 'secure-aura'); ?></h4>
                            <p><?php _e('Prevent DDoS attacks and excessive requests', 'secure-aura'); ?></p>
                        </div>
                    </label>
                </div>
                
                <div class="secure-aura-setup-navigation">
                    <a href="<?php echo admin_url('admin.php?page=secure-aura-setup&step=' . $this->get_previous_step()); ?>" class="button button-secondary">
                        <span class="dashicons dashicons-arrow-left-alt"></span>
                        <?php _e('Previous', 'secure-aura'); ?>
                    </a>
                    <button type="submit" class="button button-primary">
                        <?php _e('Continue', 'secure-aura'); ?>
                        <span class="dashicons dashicons-arrow-right-alt"></span>
                    </button>
                </div>
            </form>
        </div>
        <?php
    }
    
    /**
     * Scanner setup step
     *
     * @since 3.0.0
     */
    private function setup_scanner() {
        $settings = get_option('secure_aura_settings', []);
        ?>
        <div class="secure-aura-setup-scanner">
            <h2><?php _e('Configure Security Scanner', 'secure-aura'); ?></h2>
            <p><?php _e('Set up how SecureAura will scan your site for threats.', 'secure-aura'); ?></p>
            
            <form method="post" class="secure-aura-setup-form">
                <?php wp_nonce_field('secure_aura_setup', 'secure_aura_setup_nonce'); ?>
                <input type="hidden" name="save_step" value="1">
                
                <div class="scanner-options">
                    <label class="scanner-option">
                        <input type="checkbox" name="real_time_scan" value="1" <?php checked($settings['real_time_scanning_enabled'] ?? true); ?>>
                        <div class="option-info">
                            <h4><?php _e('Enable Real-time Scanning', 'secure-aura'); ?></h4>
                            <p><?php _e('Scan files as they are uploaded or modified', 'secure-aura'); ?></p>
                        </div>
                    </label>
                    
                    <div class="scan-frequency-option">
                        <h4><?php _e('Scheduled Scan Frequency', 'secure-aura'); ?></h4>
                        <select name="scan_frequency">
                            <option value="hourly" <?php selected($settings['scan_frequency'] ?? 'daily', 'hourly'); ?>><?php _e('Hourly', 'secure-aura'); ?></option>
                            <option value="daily" <?php selected($settings['scan_frequency'] ?? 'daily', 'daily'); ?>><?php _e('Daily (Recommended)', 'secure-aura'); ?></option>
                            <option value="weekly" <?php selected($settings['scan_frequency'] ?? 'daily', 'weekly'); ?>><?php _e('Weekly', 'secure-aura'); ?></option>
                            <option value="manual" <?php selected($settings['scan_frequency'] ?? 'daily', 'manual'); ?>><?php _e('Manual Only', 'secure-aura'); ?></option>
                        </select>
                    </div>
                    
                    <label class="scanner-option">
                        <input type="checkbox" name="quarantine_malware" value="1" <?php checked($settings['quarantine_malware'] ?? true); ?>>
                        <div class="option-info">
                            <h4><?php _e('Quarantine Malware', 'secure-aura'); ?></h4>
                            <p><?php _e('Automatically quarantine infected files', 'secure-aura'); ?></p>
                        </div>
                    </label>
                    
                    <label class="scanner-option">
                        <input type="checkbox" name="auto_clean" value="1" <?php checked($settings['auto_clean_infections'] ?? false); ?>>
                        <div class="option-info">
                            <h4><?php _e('Auto-Clean Infections', 'secure-aura'); ?></h4>
                            <p><?php _e('Automatically remove known threats (Use with caution)', 'secure-aura'); ?></p>
                        </div>
                    </label>
                </div>
                
                <div class="secure-aura-setup-navigation">
                    <a href="<?php echo admin_url('admin.php?page=secure-aura-setup&step=' . $this->get_previous_step()); ?>" class="button button-secondary">
                        <span class="dashicons dashicons-arrow-left-alt"></span>
                        <?php _e('Previous', 'secure-aura'); ?>
                    </a>
                    <button type="submit" class="button button-primary">
                        <?php _e('Continue', 'secure-aura'); ?>
                        <span class="dashicons dashicons-arrow-right-alt"></span>
                    </button>
                </div>
            </form>
        </div>
        <?php
    }
    
    /**
     * Notifications setup step
     *
     * @since 3.0.0
     */
    private function setup_notifications() {
        $settings = get_option('secure_aura_settings', []);
        $notification_email = get_option('secure_aura_notification_email', get_option('admin_email'));
        ?>
        <div class="secure-aura-setup-notifications">
            <h2><?php _e('Setup Notifications', 'secure-aura'); ?></h2>
            <p><?php _e('Choose what security alerts you want to receive via email.', 'secure-aura'); ?></p>
            
            <form method="post" class="secure-aura-setup-form">
                <?php wp_nonce_field('secure_aura_setup', 'secure_aura_setup_nonce'); ?>
                <input type="hidden" name="save_step" value="1">
                
                <div class="notification-email">
                    <label for="notification_email">
                        <h4><?php _e('Notification Email', 'secure-aura'); ?></h4>
                        <input type="email" id="notification_email" name="notification_email" value="<?php echo esc_attr($notification_email); ?>" class="regular-text" required>
                    </label>
                </div>
                
                <div class="notification-options">
                    <label class="notification-option">
                        <input type="checkbox" name="notify_threat" value="1" <?php checked($settings['notify_on_threat'] ?? true); ?>>
                        <div class="option-info">
                            <h4><?php _e('Threat Detected', 'secure-aura'); ?></h4>
                            <p><?php _e('Get notified when malware or threats are detected', 'secure-aura'); ?></p>
                        </div>
                    </label>
                    
                    <label class="notification-option">
                        <input type="checkbox" name="notify_scan" value="1" <?php checked($settings['notify_on_scan'] ?? true); ?>>
                        <div class="option-info">
                            <h4><?php _e('Scan Completed', 'secure-aura'); ?></h4>
                            <p><?php _e('Receive scan reports after each security scan', 'secure-aura'); ?></p>
                        </div>
                    </label>
                    
                    <label class="notification-option">
                        <input type="checkbox" name="notify_update" value="1" <?php checked($settings['notify_on_update'] ?? false); ?>>
                        <div class="option-info">
                            <h4><?php _e('Plugin Updates', 'secure-aura'); ?></h4>
                            <p><?php _e('Get notified about SecureAura updates', 'secure-aura'); ?></p>
                        </div>
                    </label>
                </div>
                
                <div class="secure-aura-setup-navigation">
                    <a href="<?php echo admin_url('admin.php?page=secure-aura-setup&step=' . $this->get_previous_step()); ?>" class="button button-secondary">
                        <span class="dashicons dashicons-arrow-left-alt"></span>
                        <?php _e('Previous', 'secure-aura'); ?>
                    </a>
                    <button type="submit" class="button button-primary">
                        <?php _e('Continue', 'secure-aura'); ?>
                        <span class="dashicons dashicons-arrow-right-alt"></span>
                    </button>
                </div>
            </form>
        </div>
        <?php
    }
    
    /**
     * Complete step
     *
     * @since 3.0.0
     */
    private function setup_complete() {
        ?>
        <div class="secure-aura-setup-complete">
            <div class="complete-icon">
                <span class="dashicons dashicons-yes-alt"></span>
            </div>
            <h2><?php _e('Setup Complete!', 'secure-aura'); ?></h2>
            <p class="lead"><?php _e('Your site is now protected by SecureAura. We recommend running an initial security scan.', 'secure-aura'); ?></p>
            
            <form method="post" class="secure-aura-setup-form">
                <?php wp_nonce_field('secure_aura_setup', 'secure_aura_setup_nonce'); ?>
                <input type="hidden" name="save_step" value="1">
                
                <div class="final-options">
                    <label class="final-option">
                        <input type="checkbox" name="run_initial_scan" value="1" checked>
                        <div class="option-info">
                            <h4><?php _e('Run Initial Security Scan', 'secure-aura'); ?></h4>
                            <p><?php _e('Scan your site now to identify any existing threats', 'secure-aura'); ?></p>
                        </div>
                    </label>
                </div>
                
                <div class="next-steps">
                    <h3><?php _e('What\'s Next?', 'secure-aura'); ?></h3>
                    <ul>
                        <li><?php _e('Review your security dashboard', 'secure-aura'); ?></li>
                        <li><?php _e('Check scan results and threats', 'secure-aura'); ?></li>
                        <li><?php _e('Configure advanced settings', 'secure-aura'); ?></li>
                        <li><?php _e('Review blocked IPs and activity logs', 'secure-aura'); ?></li>
                    </ul>
                </div>
                
                <div class="secure-aura-setup-actions">
                    <button type="submit" class="button button-primary button-hero">
                        <?php _e('Go to Dashboard', 'secure-aura'); ?>
                        <span class="dashicons dashicons-arrow-right-alt"></span>
                    </button>
                </div>
            </form>
        </div>
        <?php
    }
    
    /**
     * Schedule initial scan
     *
     * @since 3.0.0
     */
    private function schedule_initial_scan() {
        // Schedule a one-time scan to run in 1 minute
        if (!wp_next_scheduled('secure_aura_initial_scan')) {
            wp_schedule_single_event(time() + 60, 'secure_aura_initial_scan');
        }
    }
}