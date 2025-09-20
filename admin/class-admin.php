<?php
/**
 * The admin-specific functionality of the plugin.
 *
 * @link       https://secureaura.pro
 * @since      3.0.0
 *
 * @package    SecureAura
 * @subpackage SecureAura/admin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * The admin-specific functionality of the plugin.
 *
 * Defines the plugin name, version, and hooks for enqueuing the admin-specific
 * stylesheet and JavaScript, creating admin menus, and handling admin functionality.
 *
 * @package    SecureAura
 * @subpackage SecureAura/admin
 * @author     Bitekservices
 */
class Secure_Aura_Admin {

    /**
     * The ID of this plugin.
     *
     * @since    3.0.0
     * @access   private
     * @var      string    $plugin_name    The ID of this plugin.
     */
    private $plugin_name;

    /**
     * The version of this plugin.
     *
     * @since    3.0.0
     * @access   private
     * @var      string    $version    The current version of this plugin.
     */
    private $version;

    /**
     * Plugin configuration.
     *
     * @since    3.0.0
     * @access   private
     * @var      array    $config    Plugin configuration array.
     */
    private $config;

    /**
     * Main plugin instance.
     *
     * @since    3.0.0
     * @access   private
     * @var      object    $plugin    Main plugin instance.
     */
    private $plugin;

    /**
     * Dashboard instance.
     *
     * @since    3.0.0
     * @access   private
     * @var      object    $dashboard    Dashboard instance.
     */
    private $dashboard;

    /**
     * Settings manager instance.
     *
     * @since    3.0.0
     * @access   private
     * @var      object    $settings    Settings manager instance.
     */
    private $settings;

    /**
     * Initialize the class and set its properties.
     *
     * @since    3.0.0
     * @param    string    $plugin_name       The name of this plugin.
     * @param    string    $version    The version of this plugin.
     * @param    array     $config     Plugin configuration.
     */
    public function __construct($plugin_name, $version, $config = []) {
        $this->plugin_name = $plugin_name;
        $this->version = $version;
        $this->config = $config;
        
        // Initialize dashboard
        if (class_exists('Secure_Aura_Dashboard')) {
            $this->dashboard = new Secure_Aura_Dashboard($this->config);
        }
        
        // Initialize settings manager
        if (class_exists('Secure_Aura_Settings')) {
            $this->settings = new Secure_Aura_Settings($this->config);
        }
    }

    /**
     * Register the stylesheets for the admin area.
     *
     * @since    3.0.0
     * @param    string    $hook    The current admin page.
     */
    public function enqueue_styles($hook) {
        // Only load on SecureAura admin pages
        if (strpos($hook, 'secure-aura') === false && strpos($hook, 'toplevel_page_secure-aura') === false) {
            return;
        }

        // Main admin styles
        wp_enqueue_style(
            $this->plugin_name . '-admin',
            SECURE_AURA_ASSETS_URL . 'css/admin.css',
            [],
            $this->version,
            'all'
        );

        // Dashboard specific styles
        if (strpos($hook, 'secure-aura') !== false) {
            wp_enqueue_style(
                $this->plugin_name . '-dashboard',
                SECURE_AURA_ASSETS_URL . 'css/dashboard.css',
                [$this->plugin_name . '-admin'],
                $this->version,
                'all'
            );
        }

        // Components styles
        wp_enqueue_style(
            $this->plugin_name . '-components',
            SECURE_AURA_ASSETS_URL . 'css/components.css',
            [$this->plugin_name . '-admin'],
            $this->version,
            'all'
        );

        // Responsive styles
        wp_enqueue_style(
            $this->plugin_name . '-responsive',
            SECURE_AURA_ASSETS_URL . 'css/responsive.css',
            [$this->plugin_name . '-admin'],
            $this->version,
            'all'
        );

        // Third-party styles
        wp_enqueue_style('wp-color-picker');
        
        // Chart.js styles for dashboard
        if (strpos($hook, 'secure-aura') !== false) {
            wp_enqueue_style(
                'chartjs',
                'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.css',
                [],
                '3.9.1'
            );
        }
    }

    /**
     * Register the JavaScript for the admin area.
     *
     * @since    3.0.0
     * @param    string    $hook    The current admin page.
     */
    public function enqueue_scripts($hook) {
        // Only load on SecureAura admin pages
        if (strpos($hook, 'secure-aura') === false && strpos($hook, 'toplevel_page_secure-aura') === false) {
            return;
        }

        // Main admin JavaScript
        wp_enqueue_script(
            $this->plugin_name . '-admin',
            SECURE_AURA_ASSETS_URL . 'js/admin.js',
            ['jquery', 'wp-util', 'wp-color-picker'],
            $this->version,
            true
        );

        // Dashboard JavaScript
        if (strpos($hook, 'secure-aura') !== false) {
            wp_enqueue_script(
                $this->plugin_name . '-dashboard',
                SECURE_AURA_ASSETS_URL . 'js/dashboard.js',
                [$this->plugin_name . '-admin'],
                $this->version,
                true
            );
        }

        // Real-time monitoring
        wp_enqueue_script(
            $this->plugin_name . '-realtime',
            SECURE_AURA_ASSETS_URL . 'js/real-time-monitor.js',
            [$this->plugin_name . '-admin'],
            $this->version,
            true
        );

        // Scanner interface
        wp_enqueue_script(
            $this->plugin_name . '-scanner',
            SECURE_AURA_ASSETS_URL . 'js/scanner.js',
            [$this->plugin_name . '-admin'],
            $this->version,
            true
        );

        // Components JavaScript
        wp_enqueue_script(
            $this->plugin_name . '-components',
            SECURE_AURA_ASSETS_URL . 'js/components.js',
            [$this->plugin_name . '-admin'],
            $this->version,
            true
        );

        // Third-party libraries
        wp_enqueue_script(
            'chartjs',
            'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js',
            [],
            '3.9.1',
            true
        );

        // Localize scripts with data
        wp_localize_script($this->plugin_name . '-admin', 'secureAura', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('secure_aura_ajax_nonce'),
            'scanNonce' => wp_create_nonce('secure_aura_scan_nonce'),
            'settingsNonce' => wp_create_nonce('secure_aura_settings_nonce'),
            'pluginUrl' => SECURE_AURA_PLUGIN_URL,
            'assetsUrl' => SECURE_AURA_ASSETS_URL,
            'version' => $this->version,
            'config' => [
                'refreshInterval' => 30000, // 30 seconds
                'scanUpdateInterval' => 2000, // 2 seconds
                'chartColors' => $this->get_chart_colors(),
                'licenseType' => get_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE),
            ],
            'strings' => [
                // General
                'loading' => __('Loading...', 'secure-aura'),
                'saving' => __('Saving...', 'secure-aura'),
                'saved' => __('Saved successfully!', 'secure-aura'),
                'error' => __('An error occurred. Please try again.', 'secure-aura'),
                'confirm' => __('Are you sure?', 'secure-aura'),
                'cancel' => __('Cancel', 'secure-aura'),
                'continue' => __('Continue', 'secure-aura'),
                
                // Scanner
                'scanStarted' => __('Security scan started...', 'secure-aura'),
                'scanCompleted' => __('Security scan completed!', 'secure-aura'),
                'scanFailed' => __('Security scan failed. Please try again.', 'secure-aura'),
                'scanInProgress' => __('A scan is already in progress.', 'secure-aura'),
                'scanCanceled' => __('Security scan was canceled.', 'secure-aura'),
                'scanTimeout' => __('Security scan timed out.', 'secure-aura'),
                
                // Threats
                'threatsFound' => __('Security threats detected!', 'secure-aura'),
                'noThreatsFound' => __('No security threats found.', 'secure-aura'),
                'quarantineSuccess' => __('Files quarantined successfully.', 'secure-aura'),
                'quarantineFailed' => __('Failed to quarantine files.', 'secure-aura'),
                
                // Emergency Mode
                'emergencyActivated' => __('Emergency mode activated!', 'secure-aura'),
                'emergencyDeactivated' => __('Emergency mode deactivated.', 'secure-aura'),
                'emergencyConfirm' => __('This will activate maximum security protection. Continue?', 'secure-aura'),
                
                // Updates
                'updateAvailable' => __('Update available!', 'secure-aura'),
                'updateSuccess' => __('Update completed successfully.', 'secure-aura'),
                'updateFailed' => __('Update failed. Please try again.', 'secure-aura'),
                
                // License
                'licenseValid' => __('License is valid and active.', 'secure-aura'),
                'licenseInvalid' => __('License is invalid or expired.', 'secure-aura'),
                'licenseActivated' => __('License activated successfully!', 'secure-aura'),
                'licenseDeactivated' => __('License deactivated.', 'secure-aura'),
            ]
        ]);
    }

    /**
     * Add admin menu and pages.
     *
     * @since    3.0.0
     */
    public function add_admin_menu() {
        // Main menu page
        add_menu_page(
            __('SecureAura Security', 'secure-aura'),
            __('SecureAura', 'secure-aura'),
            'manage_options',
            'secure-aura',
            [$this, 'display_dashboard_page'],
            $this->get_menu_icon(),
            30
        );

        // Dashboard submenu (same as main)
        add_submenu_page(
            'secure-aura',
            __('Security Dashboard', 'secure-aura'),
            __('Dashboard', 'secure-aura'),
            'manage_options',
            'secure-aura',
            [$this, 'display_dashboard_page']
        );

        // Scanner submenu
        add_submenu_page(
            'secure-aura',
            __('Malware Scanner', 'secure-aura'),
            __('Scanner', 'secure-aura'),
            'manage_options',
            'secure-aura-scanner',
            [$this, 'display_scanner_page']
        );

        // Firewall submenu
        add_submenu_page(
            'secure-aura',
            __('Quantum Firewall', 'secure-aura'),
            __('Firewall', 'secure-aura'),
            'manage_options',
            'secure-aura-firewall',
            [$this, 'display_firewall_page']
        );

        // Threats submenu
        add_submenu_page(
            'secure-aura',
            __('Threat Intelligence', 'secure-aura'),
            __('Threats', 'secure-aura'),
            'manage_options',
            'secure-aura-threats',
            [$this, 'display_threats_page']
        );

        // Logs submenu
        add_submenu_page(
            'secure-aura',
            __('Security Logs', 'secure-aura'),
            __('Logs', 'secure-aura'),
            'manage_options',
            'secure-aura-logs',
            [$this, 'display_logs_page']
        );

        // Reports submenu (Pro feature)
        if ($this->is_pro_feature_available()) {
            add_submenu_page(
                'secure-aura',
                __('Security Reports', 'secure-aura'),
                __('Reports', 'secure-aura'),
                'manage_options',
                'secure-aura-reports',
                [$this, 'display_reports_page']
            );
        }

        // Settings submenu
        add_submenu_page(
            'secure-aura',
            __('Security Settings', 'secure-aura'),
            __('Settings', 'secure-aura'),
            'manage_options',
            'secure-aura-settings',
            [$this, 'display_settings_page']
        );

        // Tools submenu
        add_submenu_page(
            'secure-aura',
            __('Security Tools', 'secure-aura'),
            __('Tools', 'secure-aura'),
            'manage_options',
            'secure-aura-tools',
            [$this, 'display_tools_page']
        );

        // Upgrade submenu (for free users)
        if (get_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE) === SECURE_AURA_LICENSE_FREE) {
            add_submenu_page(
                'secure-aura',
                __('Upgrade to Pro', 'secure-aura'),
                '<span style="color: #ff6600;">' . __('Upgrade to Pro', 'secure-aura') . '</span>',
                'manage_options',
                'secure-aura-upgrade',
                [$this, 'display_upgrade_page']
            );
        }
    }

    /**
     * Initialize admin settings.
     *
     * @since    3.0.0
     */
    public function init_settings() {
        if ($this->settings) {
            $this->settings->init_settings();
        }
    }

    /**
     * Display admin notices.
     *
     * @since    3.0.0
     */
    public function show_admin_notices() {
        $current_screen = get_current_screen();
        
        // Only show on SecureAura admin pages
        if (!$current_screen || strpos($current_screen->id, 'secure-aura') === false) {
            return;
        }

        // Check for critical errors
        $critical_errors = get_option('secure_aura_critical_errors', []);
        if (!empty($critical_errors)) {
            $this->display_critical_error_notice($critical_errors);
        }

        // Check for emergency mode
        if (get_option('secure_aura_emergency_mode', false)) {
            $this->display_emergency_mode_notice();
        }

        // Check for scan results with threats
        $this->check_and_display_threat_notices();

        // Check for license expiration
        $this->check_and_display_license_notices();

        // Check for update notifications
        $this->check_and_display_update_notices();

        // Check for setup completion
        if (!get_option('secure_aura_setup_complete', false)) {
            $this->display_setup_incomplete_notice();
        }
    }

    /**
     * Display dashboard page.
     *
     * @since    3.0.0
     */
    public function display_dashboard_page() {
        if ($this->dashboard) {
            $this->dashboard->display();
        } else {
            include_once SECURE_AURA_ADMIN_DIR . 'partials/dashboard-display.php';
        }
    }

    /**
     * Display scanner page.
     *
     * @since    3.0.0
     */
    public function display_scanner_page() {
        include_once SECURE_AURA_ADMIN_DIR . 'partials/scanner-display.php';
    }

    /**
     * Display firewall page.
     *
     * @since    3.0.0
     */
    public function display_firewall_page() {
        include_once SECURE_AURA_ADMIN_DIR . 'partials/firewall-display.php';
    }

    /**
     * Display threats page.
     *
     * @since    3.0.0
     */
    public function display_threats_page() {
        include_once SECURE_AURA_ADMIN_DIR . 'partials/threats-display.php';
    }

    /**
     * Display logs page.
     *
     * @since    3.0.0
     */
    public function display_logs_page() {
        include_once SECURE_AURA_ADMIN_DIR . 'partials/logs-display.php';
    }

    /**
     * Display reports page.
     *
     * @since    3.0.0
     */
    public function display_reports_page() {
        if ($this->is_pro_feature_available()) {
            include_once SECURE_AURA_ADMIN_DIR . 'partials/reports-display.php';
        } else {
            $this->display_pro_upgrade_needed();
        }
    }

    /**
     * Display settings page.
     *
     * @since    3.0.0
     */
    public function display_settings_page() {
        if ($this->settings) {
            $this->settings->display();
        } else {
            include_once SECURE_AURA_ADMIN_DIR . 'partials/settings-display.php';
        }
    }

    /**
     * Display tools page.
     *
     * @since    3.0.0
     */
    public function display_tools_page() {
        include_once SECURE_AURA_ADMIN_DIR . 'partials/tools-display.php';
    }

    /**
     * Display upgrade page.
     *
     * @since    3.0.0
     */
    public function display_upgrade_page() {
        include_once SECURE_AURA_ADMIN_DIR . 'partials/upgrade-display.php';
    }

    /**
     * Get menu icon (SVG or Dashicon).
     *
     * @since    3.0.0
     * @return   string Menu icon.
     */
    private function get_menu_icon() {
        // SVG icon (base64 encoded)
        return 'data:image/svg+xml;base64,' . base64_encode('
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path fill="#9EA3A8" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
                <path fill="#FFF" d="M12 7c-1.11 0-2 .89-2 2 0 .74.4 1.38 1 1.72v2.78c0 .55.45 1 1 1s1-.45 1-1v-2.78c.6-.34 1-.98 1-1.72 0-1.11-.89-2-2-2z"/>
            </svg>
        ');
    }

    /**
     * Get chart colors for dashboard.
     *
     * @since    3.0.0
     * @return   array Chart color scheme.
     */
    private function get_chart_colors() {
        return [
            'primary' => '#2271b1',
            'success' => '#00a32a',
            'warning' => '#dba617',
            'danger' => '#d63638',
            'info' => '#72aee6',
            'secondary' => '#646970',
        ];
    }

    /**
     * Check if Pro features are available.
     *
     * @since    3.0.0
     * @return   bool True if Pro features are available.
     */
    private function is_pro_feature_available() {
        $license_type = get_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE);
        return $license_type !== SECURE_AURA_LICENSE_FREE;
    }

    /**
     * Display critical error notice.
     *
     * @since    3.0.0
     * @param    array $errors Critical errors.
     */
    private function display_critical_error_notice($errors) {
        $latest_error = end($errors);
        ?>
        <div class="notice notice-error is-dismissible secure-aura-notice">
            <p>
                <strong><?php _e('SecureAura Critical Error:', 'secure-aura'); ?></strong>
                <?php echo esc_html($latest_error['error']); ?>
            </p>
            <p>
                <a href="<?php echo admin_url('admin.php?page=secure-aura-tools&tab=diagnostics'); ?>" class="button button-secondary">
                    <?php _e('View Diagnostics', 'secure-aura'); ?>
                </a>
                <a href="https://secureaura.pro/support" target="_blank" class="button button-secondary">
                    <?php _e('Get Support', 'secure-aura'); ?>
                </a>
            </p>
        </div>
        <?php
    }

    /**
     * Display emergency mode notice.
     *
     * @since    3.0.0
     */
    private function display_emergency_mode_notice() {
        ?>
        <div class="notice notice-warning secure-aura-emergency-notice">
            <p>
                <strong><?php _e('Emergency Mode Active!', 'secure-aura'); ?></strong>
                <?php _e('SecureAura is running in emergency mode with maximum security protection.', 'secure-aura'); ?>
                <a href="<?php echo admin_url('admin.php?page=secure-aura'); ?>" class="button button-primary">
                    <?php _e('Manage Emergency Mode', 'secure-aura'); ?>
                </a>
            </p>
        </div>
        <?php
    }

    /**
     * Check and display threat notices.
     *
     * @since    3.0.0
     */
    private function check_and_display_threat_notices() {
        $last_scan = get_option('secure_aura_last_scan_results', []);
        
        if (!empty($last_scan['threats_found'])) {
            $threat_count = count($last_scan['threats_found']);
            ?>
            <div class="notice notice-error secure-aura-threat-notice">
                <p>
                    <strong><?php _e('Security Threats Detected!', 'secure-aura'); ?></strong>
                    <?php printf(
                        _n('SecureAura found %d security threat on your website.', 'SecureAura found %d security threats on your website.', $threat_count, 'secure-aura'),
                        $threat_count
                    ); ?>
                </p>
                <p>
                    <a href="<?php echo admin_url('admin.php?page=secure-aura-scanner'); ?>" class="button button-primary">
                        <?php _e('Review Threats', 'secure-aura'); ?>
                    </a>
                    <a href="<?php echo admin_url('admin.php?page=secure-aura&action=quarantine-all'); ?>" class="button button-secondary">
                        <?php _e('Quarantine All', 'secure-aura'); ?>
                    </a>
                </p>
            </div>
            <?php
        }
    }

    /**
     * Check and display license notices.
     *
     * @since    3.0.0
     */
    private function check_and_display_license_notices() {
        $license_status = get_option('secure_aura_license_status', 'inactive');
        $license_expires = get_option('secure_aura_license_expires', '');
        
        if ($license_status === 'expired' || ($license_expires && strtotime($license_expires) < time())) {
            ?>
            <div class="notice notice-warning secure-aura-license-notice">
                <p>
                    <strong><?php _e('License Expired!', 'secure-aura'); ?></strong>
                    <?php _e('Your SecureAura Pro license has expired. Renew now to continue receiving updates and premium features.', 'secure-aura'); ?>
                </p>
                <p>
                    <a href="https://secureaura.pro/renew" target="_blank" class="button button-primary">
                        <?php _e('Renew License', 'secure-aura'); ?>
                    </a>
                    <a href="<?php echo admin_url('admin.php?page=secure-aura-settings&tab=license'); ?>" class="button button-secondary">
                        <?php _e('License Settings', 'secure-aura'); ?>
                    </a>
                </p>
            </div>
            <?php
        }
    }

    /**
     * Check and display update notices.
     *
     * @since    3.0.0
     */
    private function check_and_display_update_notices() {
        $update_available = get_transient('secure_aura_update_available');
        
        if ($update_available) {
            ?>
            <div class="notice notice-info secure-aura-update-notice">
                <p>
                    <strong><?php _e('Update Available!', 'secure-aura'); ?></strong>
                    <?php printf(
                        __('SecureAura version %s is now available. Update to get the latest security improvements and features.', 'secure-aura'),
                        esc_html($update_available['version'])
                    ); ?>
                </p>
                <p>
                    <a href="<?php echo admin_url('update-core.php'); ?>" class="button button-primary">
                        <?php _e('Update Now', 'secure-aura'); ?>
                    </a>
                    <a href="<?php echo esc_url($update_available['details_url']); ?>" target="_blank" class="button button-secondary">
                        <?php _e('View Details', 'secure-aura'); ?>
                    </a>
                </p>
            </div>
            <?php
        }
    }

    /**
     * Display setup incomplete notice.
     *
     * @since    3.0.0
     */
    private function display_setup_incomplete_notice() {
        ?>
        <div class="notice notice-info secure-aura-setup-notice">
            <p>
                <strong><?php _e('Welcome to SecureAura!', 'secure-aura'); ?></strong>
                <?php _e('Complete the setup wizard to configure your security settings and run your first scan.', 'secure-aura'); ?>
            </p>
            <p>
                <a href="<?php echo admin_url('admin.php?page=secure-aura-settings&tab=setup'); ?>" class="button button-primary">
                    <?php _e('Complete Setup', 'secure-aura'); ?>
                </a>
                <button type="button" class="button button-secondary" onclick="this.parentNode.parentNode.style.display='none';">
                    <?php _e('Dismiss', 'secure-aura'); ?>
                </button>
            </p>
        </div>
        <?php
    }

    /**
     * Display Pro upgrade needed message.
     *
     * @since    3.0.0
     */
    private function display_pro_upgrade_needed() {
        ?>
        <div class="wrap">
            <h1><?php _e('Upgrade to Pro Required', 'secure-aura'); ?></h1>
            <div class="secure-aura-pro-upgrade">
                <div class="secure-aura-upgrade-header">
                    <h2><?php _e('Unlock Advanced Security Features', 'secure-aura'); ?></h2>
                    <p><?php _e('This feature requires SecureAura Pro. Upgrade now to access advanced security reports, AI-powered threat detection, and premium support.', 'secure-aura'); ?></p>
                </div>
                
                <div class="secure-aura-upgrade-features">
                    <div class="feature-grid">
                        <div class="feature-item">
                            <span class="dashicons dashicons-chart-line"></span>
                            <h3><?php _e('Advanced Reports', 'secure-aura'); ?></h3>
                            <p><?php _e('Detailed security analytics and compliance reports.', 'secure-aura'); ?></p>
                        </div>
                        
                        <div class="feature-item">
                            <span class="dashicons dashicons-admin-generic"></span>
                            <h3><?php _e('AI Threat Detection', 'secure-aura'); ?></h3>
                            <p><?php _e('Machine learning-powered threat identification.', 'secure-aura'); ?></p>
                        </div>
                        
                        <div class="feature-item">
                            <span class="dashicons dashicons-visibility"></span>
                            <h3><?php _e('Behavioral Monitoring', 'secure-aura'); ?></h3>
                            <p><?php _e('Advanced user behavior analysis and anomaly detection.', 'secure-aura'); ?></p>
                        </div>
                        
                        <div class="feature-item">
                            <span class="dashicons dashicons-location-alt"></span>
                            <h3><?php _e('Geographic Blocking', 'secure-aura'); ?></h3>
                            <p><?php _e('Block traffic from specific countries and regions.', 'secure-aura'); ?></p>
                        </div>
                        
                        <div class="feature-item">
                            <span class="dashicons dashicons-sos"></span>
                            <h3><?php _e('Priority Support', 'secure-aura'); ?></h3>
                            <p><?php _e('Get help from security experts when you need it.', 'secure-aura'); ?></p>
                        </div>
                        
                        <div class="feature-item">
                            <span class="dashicons dashicons-backup"></span>
                            <h3><?php _e('Automated Backups', 'secure-aura'); ?></h3>
                            <p><?php _e('Scheduled backups with cloud storage integration.', 'secure-aura'); ?></p>
                        </div>
                    </div>
                </div>
                
                <div class="secure-aura-upgrade-actions">
                    <a href="https://secureaura.pro/upgrade/" target="_blank" class="button button-primary button-hero">
                        <?php _e('Upgrade to Pro', 'secure-aura'); ?>
                    </a>
                    <a href="https://secureaura.pro/features/" target="_blank" class="button button-secondary">
                        <?php _e('Compare Features', 'secure-aura'); ?>
                    </a>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Add admin bar menu items.
     *
     * @since    3.0.0
     */
    public function add_admin_bar_menu() {
        if (!is_admin_bar_showing() || !current_user_can('manage_options')) {
            return;
        }

        global $wp_admin_bar;

        // Main SecureAura node
        $wp_admin_bar->add_node([
            'id'    => 'secure-aura',
            'title' => '<span class="ab-icon dashicons-shield-alt"></span>' . __('SecureAura', 'secure-aura'),
            'href'  => admin_url('admin.php?page=secure-aura'),
        ]);

        // Security status
        $security_status = $this->get_security_status_summary();
        $status_class = $security_status['class'];
        $wp_admin_bar->add_node([
            'parent' => 'secure-aura',
            'id'     => 'secure-aura-status',
            'title'  => sprintf(
                '<span class="secure-aura-status %s">%s</span> %s',
                $status_class,
                $security_status['icon'],
                $security_status['text']
            ),
            'href'   => admin_url('admin.php?page=secure-aura'),
        ]);

        // Quick scan
        $wp_admin_bar->add_node([
            'parent' => 'secure-aura',
            'id'     => 'secure-aura-quick-scan',
            'title'  => __('Quick Scan', 'secure-aura'),
            'href'   => admin_url('admin.php?page=secure-aura-scanner&action=quick-scan'),
            'meta'   => ['class' => 'secure-aura-quick-scan'],
        ]);

        // Emergency mode toggle
        $emergency_mode = get_option('secure_aura_emergency_mode', false);
        $wp_admin_bar->add_node([
            'parent' => 'secure-aura',
            'id'     => 'secure-aura-emergency',
            'title'  => $emergency_mode ? __('Disable Emergency', 'secure-aura') : __('Emergency Mode', 'secure-aura'),
            'href'   => wp_nonce_url(
                admin_url('admin.php?page=secure-aura&action=toggle-emergency'),
                'secure_aura_emergency_nonce'
            ),
            'meta'   => ['class' => $emergency_mode ? 'secure-aura-emergency-active' : 'secure-aura-emergency-inactive'],
        ]);

        // View logs
        $wp_admin_bar->add_node([
            'parent' => 'secure-aura',
            'id'     => 'secure-aura-logs',
            'title'  => __('Security Logs', 'secure-aura'),
            'href'   => admin_url('admin.php?page=secure-aura-logs'),
        ]);
    }

    /**
     * Get security status summary for admin bar.
     *
     * @since    3.0.0
     * @return   array Security status information.
     */
    private function get_security_status_summary() {
        $threats_today = $this->get_threats_blocked_today();
        $emergency_mode = get_option('secure_aura_emergency_mode', false);
        $last_scan = get_option('secure_aura_last_scan_time', '');
        
        if ($emergency_mode) {
            return [
                'text' => __('Emergency Mode', 'secure-aura'),
                'icon' => '⚠️',
                'class' => 'emergency',
            ];
        }
        
        if ($threats_today > 0) {
            return [
                'text' => sprintf(__('%d Threats Blocked', 'secure-aura'), $threats_today),
                'icon' => '🛡️',
                'class' => 'active',
            ];
        }
        
        if (empty($last_scan)) {
            return [
                'text' => __('No Scan Yet', 'secure-aura'),
                'icon' => '❓',
                'class' => 'warning',
            ];
        }
        
        return [
            'text' => __('Protected', 'secure-aura'),
            'icon' => '✅',
            'class' => 'secure',
        ];
    }

    /**
     * Get number of threats blocked today.
     *
     * @since    3.0.0
     * @return   int Number of threats blocked today.
     */
    private function get_threats_blocked_today() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $count = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE response_action IN ('block', 'quarantine', 'blocked') 
            AND DATE(created_at) = %s
        ", current_time('Y-m-d')));
        
        return intval($count);
    }

    /**
     * Handle admin AJAX requests.
     *
     * @since    3.0.0
     */
    public function handle_ajax_requests() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'secure_aura_ajax_nonce')) {
            wp_die(__('Security check failed.', 'secure-aura'));
        }

        $action = sanitize_text_field($_POST['sa_action']);

        switch ($action) {
            case 'get_dashboard_data':
                $this->ajax_get_dashboard_data();
                break;
            case 'run_quick_scan':
                $this->ajax_run_quick_scan();
                break;
            case 'get_scan_status':
                $this->ajax_get_scan_status();
                break;
            case 'toggle_emergency_mode':
                $this->ajax_toggle_emergency_mode();
                break;
            case 'update_threat_intel':
                $this->ajax_update_threat_intelligence();
                break;
            case 'get_activity_feed':
                $this->ajax_get_activity_feed();
                break;
            default:
                wp_send_json_error(__('Unknown action.', 'secure-aura'));
        }
    }

    /**
     * AJAX: Get dashboard data.
     *
     * @since    3.0.0
     */
    private function ajax_get_dashboard_data() {
        $data = [
            'security_score' => $this->calculate_security_score(),
            'threats_blocked' => $this->get_threat_statistics(),
            'scan_status' => $this->get_scan_status(),
            'system_health' => $this->get_system_health(),
            'recent_activity' => $this->get_recent_activity(),
        ];
        
        wp_send_json_success($data);
    }

    /**
     * AJAX: Run quick scan.
     *
     * @since    3.0.0
     */
    private function ajax_run_quick_scan() {
        // Check if scan is already running
        if (get_transient('secure_aura_scan_in_progress')) {
            wp_send_json_error(__('A scan is already in progress.', 'secure-aura'));
        }

        // Start quick scan
        $scanner = new Secure_Aura_Malware_Scanner();
        $scan_result = $scanner->run_quick_scan();
        
        wp_send_json_success($scan_result);
    }

    /**
     * AJAX: Get scan status.
     *
     * @since    3.0.0
     */
    private function ajax_get_scan_status() {
        $progress = get_transient('secure_aura_scan_progress');
        wp_send_json_success($progress);
    }

    /**
     * AJAX: Toggle emergency mode.
     *
     * @since    3.0.0
     */
    private function ajax_toggle_emergency_mode() {
        $current_mode = get_option('secure_aura_emergency_mode', false);
        $new_mode = !$current_mode;
        
        update_option('secure_aura_emergency_mode', $new_mode);
        
        // Log the change
        $this->log_emergency_mode_change($new_mode);
        
        wp_send_json_success([
            'emergency_mode' => $new_mode,
            'message' => $new_mode ? 
                __('Emergency mode activated!', 'secure-aura') : 
                __('Emergency mode deactivated.', 'secure-aura')
        ]);
    }

    /**
     * AJAX: Update threat intelligence.
     *
     * @since    3.0.0
     */
    private function ajax_update_threat_intelligence() {
        if (!$this->is_pro_feature_available()) {
            wp_send_json_error(__('This feature requires SecureAura Pro.', 'secure-aura'));
        }

        $threat_intel = new Secure_Aura_Threat_Intelligence();
        $result = $threat_intel->update_feeds();
        
        wp_send_json_success($result);
    }

    /**
     * AJAX: Get activity feed.
     *
     * @since    3.0.0
     */
    private function ajax_get_activity_feed() {
        $activities = $this->get_recent_activity(20);
        ob_start();
        
        foreach ($activities as $activity) {
            $this->render_activity_item($activity);
        }
        
        $html = ob_get_clean();
        wp_send_json_success(['html' => $html]);
    }

    /**
     * Calculate overall security score.
     *
     * @since    3.0.0
     * @return   array Security score data.
     */
    private function calculate_security_score() {
        $score = 0;
        $factors = [];
        
        // Base score for having the plugin active
        $score += 20;
        $factors[] = ['name' => 'Plugin Active', 'score' => 20];
        
        // Firewall enabled
        if (get_option('secure_aura_quantum_firewall_enabled', true)) {
            $score += 25;
            $factors[] = ['name' => 'Firewall Enabled', 'score' => 25];
        }
        
        // Recent scan
        $last_scan = get_option('secure_aura_last_scan_time', '');
        if (!empty($last_scan) && strtotime($last_scan) > (time() - 7 * 24 * 60 * 60)) {
            $score += 20;
            $factors[] = ['name' => 'Recent Scan', 'score' => 20];
        }
        
        // Real-time protection
        if (get_option('secure_aura_real_time_scanning_enabled', true)) {
            $score += 15;
            $factors[] = ['name' => 'Real-time Protection', 'score' => 15];
        }
        
        // File integrity monitoring
        if (get_option('secure_aura_file_integrity_monitoring_enabled', true)) {
            $score += 10;
            $factors[] = ['name' => 'File Integrity', 'score' => 10];
        }
        
        // Pro features
        if ($this->is_pro_feature_available()) {
            $score += 10;
            $factors[] = ['name' => 'Pro Features', 'score' => 10];
        }
        
        // Determine status
        $status = 'good';
        $status_text = __('Good', 'secure-aura');
        $status_class = 'good';
        
        if ($score >= 90) {
            $status = 'excellent';
            $status_text = __('Excellent', 'secure-aura');
            $status_class = 'excellent';
        } elseif ($score >= 70) {
            $status = 'good';
            $status_text = __('Good', 'secure-aura');
            $status_class = 'good';
        } elseif ($score >= 50) {
            $status = 'warning';
            $status_text = __('Needs Improvement', 'secure-aura');
            $status_class = 'warning';
        } else {
            $status = 'critical';
            $status_text = __('Critical', 'secure-aura');
            $status_class = 'critical';
        }
        
        return [
            'score' => min($score, 100),
            'status' => $status,
            'status_text' => $status_text,
            'status_class' => $status_class,
            'factors' => $factors,
        ];
    }

    /**
     * Get threat statistics.
     *
     * @since    3.0.0
     * @return   array Threat statistics.
     */
    private function get_threat_statistics() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        // Threats blocked today
        $blocked_today = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE response_action IN ('block', 'quarantine', 'blocked') 
            AND DATE(created_at) = %s
        ", current_time('Y-m-d')));
        
        // Threats blocked yesterday
        $blocked_yesterday = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE response_action IN ('block', 'quarantine', 'blocked') 
            AND DATE(created_at) = %s
        ", date('Y-m-d', strtotime('-1 day'))));
        
        // Total threats blocked
        $total_blocked = $wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE response_action IN ('block', 'quarantine', 'blocked')
        ");
        
        // Calculate change
        $change_percent = 0;
        $change_class = 'neutral';
        $change_icon = 'dashicons-minus';
        
        if ($blocked_yesterday > 0) {
            $change_percent = round((($blocked_today - $blocked_yesterday) / $blocked_yesterday) * 100);
            if ($change_percent > 0) {
                $change_class = 'positive';
                $change_icon = 'dashicons-arrow-up-alt';
            } elseif ($change_percent < 0) {
                $change_class = 'negative';
                $change_icon = 'dashicons-arrow-down-alt';
                $change_percent = abs($change_percent);
            }
        }
        
        return [
            'blocked_today' => intval($blocked_today),
            'blocked_yesterday' => intval($blocked_yesterday),
            'total_blocked' => intval($total_blocked),
            'change_percent' => $change_percent,
            'change_class' => $change_class,
            'change_icon' => $change_icon,
        ];
    }

    /**
     * Get current scan status.
     *
     * @since    3.0.0
     * @return   array Scan status information.
     */
    private function get_scan_status() {
        $last_scan = get_option('secure_aura_last_scan_results', []);
        $last_scan_time = get_option('secure_aura_last_scan_time', '');
        
        return [
            'last_scan' => $last_scan_time,
            'files_scanned' => $last_scan['files_scanned'] ?? 0,
            'threats_found' => count($last_scan['threats_found'] ?? []),
            'status' => $last_scan['status'] ?? 'never',
        ];
    }

    /**
     * Get system health information.
     *
     * @since    3.0.0
     * @return   array System health data.
     */
    private function get_system_health() {
        $health_status = 'healthy';
        $issues = [];
        
        // Check memory usage
        $memory_limit = wp_convert_hr_to_bytes(ini_get('memory_limit'));
        $memory_usage = memory_get_usage(true);
        $memory_percent = ($memory_usage / $memory_limit) * 100;
        
        if ($memory_percent > 80) {
            $health_status = 'warning';
            $issues[] = __('High memory usage', 'secure-aura');
        }
        
        // Check disk space
        $disk_free = disk_free_space(ABSPATH);
        $disk_total = disk_total_space(ABSPATH);
        $disk_percent = (($disk_total - $disk_free) / $disk_total) * 100;
        
        if ($disk_percent > 90) {
            $health_status = 'critical';
            $issues[] = __('Low disk space', 'secure-aura');
        } elseif ($disk_percent > 80) {
            $health_status = 'warning';
            $issues[] = __('Disk space running low', 'secure-aura');
        }
        
        // Check database connectivity
        if (!$this->test_database_connection()) {
            $health_status = 'critical';
            $issues[] = __('Database connection issues', 'secure-aura');
        }
        
        return [
            'status' => $health_status,
            'memory_usage' => $memory_percent,
            'disk_usage' => $disk_percent,
            'issues' => $issues,
        ];
    }

    /**
     * Test database connection.
     *
     * @since    3.0.0
     * @return   bool True if database is accessible.
     */
    private function test_database_connection() {
        global $wpdb;
        
        $result = $wpdb->get_var("SELECT 1");
        return $result == 1;
    }

    /**
     * Get recent security activity.
     *
     * @since    3.0.0
     * @param    int $limit Number of activities to retrieve.
     * @return   array Recent activities.
     */
    private function get_recent_activity($limit = 10) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $activities = $wpdb->get_results($wpdb->prepare("
            SELECT * FROM {$table_name} 
            ORDER BY created_at DESC 
            LIMIT %d
        ", $limit));
        
        return array_map([$this, 'format_activity_item'], $activities);
    }

    /**
     * Format activity item for display.
     *
     * @since    3.0.0
     * @param    object $activity Raw activity data.
     * @return   array Formatted activity item.
     */
    private function format_activity_item($activity) {
        $icon_class = 'info';
        $title = '';
        $description = '';
        
        switch ($activity->event_type) {
            case 'malware_detected':
                $icon_class = 'danger';
                $title = __('Malware Detected', 'secure-aura');
                $description = sprintf(__('Threat found in %s', 'secure-aura'), basename($activity->request_uri));
                break;
                
            case 'login_failed':
                $icon_class = 'warning';
                $title = __('Failed Login Attempt', 'secure-aura');
                $description = sprintf(__('From IP %s', 'secure-aura'), $activity->source_ip);
                break;
                
            case 'file_quarantined':
                $icon_class = 'success';
                $title = __('File Quarantined', 'secure-aura');
                $description = __('Malicious file isolated', 'secure-aura');
                break;
                
            case 'scan_completed':
                $icon_class = 'success';
                $title = __('Scan Completed', 'secure-aura');
                $description = __('System scan finished successfully', 'secure-aura');
                break;
                
            default:
                $title = ucwords(str_replace('_', ' ', $activity->event_type));
                $description = $activity->request_uri ?: __('Security event recorded', 'secure-aura');
        }
        
        return [
            'id' => $activity->id,
            'title' => $title,
            'description' => $description,
            'icon_class' => $icon_class,
            'severity' => $activity->severity,
            'time' => human_time_diff(strtotime($activity->created_at), current_time('timestamp')),
            'timestamp' => $activity->created_at,
        ];
    }

    /**
     * Render single activity item.
     *
     * @since    3.0.0
     * @param    array $activity Activity data.
     */
    private function render_activity_item($activity) {
        ?>
        <div class="secure-aura-activity-item">
            <div class="secure-aura-activity-icon <?php echo esc_attr($activity['icon_class']); ?>">
                <span class="dashicons dashicons-<?php echo $this->get_activity_icon($activity['icon_class']); ?>"></span>
            </div>
            <div class="secure-aura-activity-content">
                <div class="secure-aura-activity-title"><?php echo esc_html($activity['title']); ?></div>
                <div class="secure-aura-activity-description"><?php echo esc_html($activity['description']); ?></div>
            </div>
            <div class="secure-aura-activity-time"><?php echo esc_html($activity['time']); ?> <?php _e('ago', 'secure-aura'); ?></div>
        </div>
        <?php
    }

    /**
     * Get activity icon based on class.
     *
     * @since    3.0.0
     * @param    string $class Icon class.
     * @return   string Dashicon name.
     */
    private function get_activity_icon($class) {
        $icons = [
            'success' => 'yes-alt',
            'warning' => 'warning',
            'danger' => 'dismiss',
            'info' => 'info-outline',
        ];
        
        return $icons[$class] ?? 'marker';
    }

    /**
     * Log emergency mode change.
     *
     * @since    3.0.0
     * @param    bool $activated Whether emergency mode was activated.
     */
    private function log_emergency_mode_change($activated) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $wpdb->insert($table_name, [
            'event_type' => 'emergency_mode_' . ($activated ? 'activated' : 'deactivated'),
            'severity' => SECURE_AURA_SEVERITY_HIGH,
            'source_ip' => $this->get_client_ip(),
            'user_id' => get_current_user_id(),
            'event_data' => json_encode([
                'emergency_mode' => $activated,
                'triggered_by' => get_current_user_id(),
                'timestamp' => current_time('mysql'),
            ]),
            'response_action' => 'emergency_mode_change',
        ]);
    }

    /**
     * Get client IP address.
     *
     * @since    3.0.0
     * @return   string Client IP address.
     */
    private function get_client_ip() {
        $ip_headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ];
        
        foreach ($ip_headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = trim(explode(',', $_SERVER[$header])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Add dashboard widgets.
     *
     * @since    3.0.0
     */
    public function add_dashboard_widgets() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Security Status Widget
        wp_add_dashboard_widget(
            'secure_aura_security_status',
            __('Security Status - SecureAura', 'secure-aura'),
            [$this, 'render_security_status_widget']
        );

        // Recent Threats Widget
        wp_add_dashboard_widget(
            'secure_aura_recent_threats',
            __('Recent Security Events - SecureAura', 'secure-aura'),
            [$this, 'render_recent_threats_widget']
        );
    }

    /**
     * Render security status dashboard widget.
     *
     * @since    3.0.0
     */
    public function render_security_status_widget() {
        $security_score = $this->calculate_security_score();
        $threats_today = $this->get_threats_blocked_today();
        $last_scan = get_option('secure_aura_last_scan_time', '');
        
        ?>
        <div class="secure-aura-widget-content">
            <div class="security-score">
                <div class="score-circle">
                    <span class="score-number"><?php echo $security_score['score']; ?>%</span>
                </div>
                <div class="score-status <?php echo $security_score['status_class']; ?>">
                    <?php echo $security_score['status_text']; ?>
                </div>
            </div>
            
            <div class="security-stats">
                <div class="stat-item">
                    <span class="stat-label"><?php _e('Threats Blocked Today:', 'secure-aura'); ?></span>
                    <span class="stat-value"><?php echo $threats_today; ?></span>
                </div>
                <div class="stat-item">
                    <span class="stat-label"><?php _e('Last Scan:', 'secure-aura'); ?></span>
                    <span class="stat-value">
                        <?php echo $last_scan ? human_time_diff(strtotime($last_scan), current_time('timestamp')) . ' ' . __('ago', 'secure-aura') : __('Never', 'secure-aura'); ?>
                    </span>
                </div>
            </div>
            
            <div class="widget-actions">
                <a href="<?php echo admin_url('admin.php?page=secure-aura'); ?>" class="button button-primary">
                    <?php _e('View Dashboard', 'secure-aura'); ?>
                </a>
                <a href="<?php echo admin_url('admin.php?page=secure-aura-scanner'); ?>" class="button button-secondary">
                    <?php _e('Run Scan', 'secure-aura'); ?>
                </a>
            </div>
        </div>
        <?php
    }

    /**
     * Render recent threats dashboard widget.
     *
     * @since    3.0.0
     */
    public function render_recent_threats_widget() {
        $recent_threats = $this->get_recent_threats(5);
        
        if (empty($recent_threats)) {
            ?>
            <div class="secure-aura-widget-content">
                <div class="no-threats">
                    <span class="dashicons dashicons-yes-alt"></span>
                    <p><?php _e('No recent security threats detected. Your site is secure!', 'secure-aura'); ?></p>
                </div>
            </div>
            <?php
            return;
        }
        
        ?>
        <div class="secure-aura-widget-content">
            <div class="recent-threats-list">
                <?php foreach ($recent_threats as $threat): ?>
                    <div class="threat-item">
                        <div class="threat-icon">
                            <span class="dashicons dashicons-warning"></span>
                        </div>
                        <div class="threat-details">
                            <div class="threat-type"><?php echo esc_html($threat['type']); ?></div>
                            <div class="threat-time"><?php echo esc_html($threat['time_ago']); ?></div>
                        </div>
                        <div class="threat-status <?php echo esc_attr($threat['status']); ?>">
                            <?php echo esc_html($threat['status_text']); ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
            
            <div class="widget-actions">
                <a href="<?php echo admin_url('admin.php?page=secure-aura-logs'); ?>" class="button button-primary">
                    <?php _e('View All Logs', 'secure-aura'); ?>
                </a>
            </div>
        </div>
        <?php
    }

    /**
     * Get recent threats for widget.
     *
     * @since    3.0.0
     * @param    int $limit Number of threats to retrieve.
     * @return   array Recent threats.
     */
    private function get_recent_threats($limit = 5) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $threats = $wpdb->get_results($wpdb->prepare("
            SELECT * FROM {$table_name} 
            WHERE event_type IN ('malware_detected', 'suspicious_activity', 'brute_force_attempt') 
            ORDER BY created_at DESC 
            LIMIT %d
        ", $limit));
        
        return array_map(function($threat) {
            $type_names = [
                'malware_detected' => __('Malware Detected', 'secure-aura'),
                'suspicious_activity' => __('Suspicious Activity', 'secure-aura'),
                'brute_force_attempt' => __('Brute Force Attack', 'secure-aura'),
            ];
            
            $status_info = [
                'blocked' => ['text' => __('Blocked', 'secure-aura'), 'class' => 'blocked'],
                'quarantined' => ['text' => __('Quarantined', 'secure-aura'), 'class' => 'quarantined'],
                'monitored' => ['text' => __('Monitored', 'secure-aura'), 'class' => 'monitored'],
            ];
            
            $action = $threat->response_action ?: 'monitored';
            $status = $status_info[$action] ?? $status_info['monitored'];
            
            return [
                'type' => $type_names[$threat->event_type] ?? ucwords(str_replace('_', ' ', $threat->event_type)),
                'time_ago' => human_time_diff(strtotime($threat->created_at), current_time('timestamp')) . ' ' . __('ago', 'secure-aura'),
                'status' => $status['class'],
                'status_text' => $status['text'],
                'severity' => $threat->severity,
                'ip' => $threat->source_ip,
            ];
        }, $threats);
    }

    /**
     * Handle plugin updates and maintenance.
     *
     * @since    3.0.0
     */
    public function handle_plugin_updates() {
        $current_version = get_option('secure_aura_version', '0');
        
        if (version_compare($current_version, SECURE_AURA_VERSION, '<')) {
            $this->perform_update_tasks($current_version);
            update_option('secure_aura_version', SECURE_AURA_VERSION);
        }
    }

    /**
     * Perform update tasks when plugin is updated.
     *
     * @since    3.0.0
     * @param    string $old_version Previous version.
     */
    private function perform_update_tasks($old_version) {
        // Update database schema if needed
        if (class_exists('Secure_Aura_Schema')) {
            $schema = new Secure_Aura_Schema();
            $schema->update_schema();
        }
        
        // Clear cache
        $this->clear_plugin_cache();
        
        // Update default settings for new features
        $this->update_default_settings($old_version);
        
        // Log update
        $this->log_plugin_update($old_version);
        
        // Show update notice
        set_transient('secure_aura_show_update_notice', [
            'old_version' => $old_version,
            'new_version' => SECURE_AURA_VERSION,
        ], 24 * HOUR_IN_SECONDS);
    }

    /**
     * Clear plugin cache.
     *
     * @since    3.0.0
     */
    private function clear_plugin_cache() {
        // Clear WordPress cache
        wp_cache_flush();
        
        // Clear transients
        delete_transient('secure_aura_malware_signatures');
        delete_transient('secure_aura_threat_intel_cache');
        delete_transient('secure_aura_geoip_cache');
        
        // Clear plugin-specific cache files
        $cache_dir = SECURE_AURA_CACHE_DIR;
        if (is_dir($cache_dir)) {
            $files = glob($cache_dir . '*');
            foreach ($files as $file) {
                if (is_file($file)) {
                    unlink($file);
                }
            }
        }
    }

    /**
     * Update default settings for new version.
     *
     * @since    3.0.0
     * @param    string $old_version Previous version.
     */
    private function update_default_settings($old_version) {
        $current_settings = get_option('secure_aura_settings', []);
        
        // Load new default settings
        $default_settings_file = SECURE_AURA_PLUGIN_DIR . 'config/default-settings.php';
        if (file_exists($default_settings_file)) {
            $default_settings = include $default_settings_file;
            
            // Merge new settings with existing ones (don't overwrite user preferences)
            foreach ($default_settings as $key => $value) {
                if (!isset($current_settings[$key])) {
                    $current_settings[$key] = $value;
                }
            }
            
            update_option('secure_aura_settings', $current_settings);
        }
    }

    /**
     * Log plugin update.
     *
     * @since    3.0.0
     * @param    string $old_version Previous version.
     */
    private function log_plugin_update($old_version) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        
        $wpdb->insert($table_name, [
            'event_type' => 'plugin_updated',
            'severity' => SECURE_AURA_SEVERITY_INFO,
            'source_ip' => $this->get_client_ip(),
            'user_id' => get_current_user_id(),
            'event_data' => json_encode([
                'old_version' => $old_version,
                'new_version' => SECURE_AURA_VERSION,
                'update_time' => current_time('mysql'),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]),
            'response_action' => 'plugin_updated',
        ]);
    }

    /**
     * Add custom admin footer text.
     *
     * @since    3.0.0
     * @param    string $footer_text Current footer text.
     * @return   string Modified footer text.
     */
    public function add_admin_footer_text($footer_text) {
        $current_screen = get_current_screen();
        
        if ($current_screen && strpos($current_screen->id, 'secure-aura') !== false) {
            $footer_text = sprintf(
                __('Thank you for using %s SecureAura %s! Please %s rate us %s on WordPress.org', 'secure-aura'),
                '<strong>',
                SECURE_AURA_VERSION . '</strong>',
                '<a href="https://wordpress.org/support/plugin/secure-aura/reviews/?rate=5#new-post" target="_blank" rel="noopener noreferrer">',
                '</a> ⭐⭐⭐⭐⭐'
            );
        }
        
        return $footer_text;
    }

    /**
     * Add version info to admin footer.
     *
     * @since    3.0.0
     * @param    string $version_text Current version text.
     * @return   string Modified version text.
     */
    public function add_admin_footer_version($version_text) {
        $current_screen = get_current_screen();
        
        if ($current_screen && strpos($current_screen->id, 'secure-aura') !== false) {
            $license_type = get_option('secure_aura_license_type', SECURE_AURA_LICENSE_FREE);
            $license_text = $license_type === SECURE_AURA_LICENSE_FREE ? 'Free' : 'Pro';
            
            $version_text = sprintf(
                __('SecureAura %s (%s) | WordPress %s', 'secure-aura'),
                SECURE_AURA_VERSION,
                $license_text,
                get_bloginfo('version')
            );
        }
        
        return $version_text;
    }

    /**
     * Handle bulk actions for security logs.
     *
     * @since    3.0.0
     */
    public function handle_bulk_actions() {
        $action = $_REQUEST['action'] ?? '';
        $action2 = $_REQUEST['action2'] ?? '';
        
        // Use action2 if action is -1 (from bottom dropdown)
        if ($action === '-1') {
            $action = $action2;
        }
        
        if (empty($action) || !isset($_REQUEST['log_ids'])) {
            return;
        }
        
        // Verify nonce
        if (!wp_verify_nonce($_REQUEST['_wpnonce'], 'bulk-security-logs')) {
            wp_die(__('Security check failed.', 'secure-aura'));
        }
        
        $log_ids = array_map('intval', $_REQUEST['log_ids']);
        
        switch ($action) {
            case 'delete':
                $this->bulk_delete_logs($log_ids);
                break;
            case 'mark_as_reviewed':
                $this->bulk_mark_logs_reviewed($log_ids);
                break;
            case 'export':
                $this->bulk_export_logs($log_ids);
                break;
        }
    }

    /**
     * Bulk delete security logs.
     *
     * @since    3.0.0
     * @param    array $log_ids Log IDs to delete.
     */
    private function bulk_delete_logs($log_ids) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        $placeholders = implode(',', array_fill(0, count($log_ids), '%d'));
        
        $deleted = $wpdb->query($wpdb->prepare("
            DELETE FROM {$table_name} 
            WHERE id IN ({$placeholders})
        ", $log_ids));
        
        if ($deleted) {
            $message = sprintf(
                _n('%d log entry deleted.', '%d log entries deleted.', $deleted, 'secure-aura'),
                $deleted
            );
            add_settings_error('secure_aura_messages', 'logs_deleted', $message, 'updated');
        }
    }

    /**
     * Bulk mark logs as reviewed.
     *
     * @since    3.0.0
     * @param    array $log_ids Log IDs to mark as reviewed.
     */
    private function bulk_mark_logs_reviewed($log_ids) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        $placeholders = implode(',', array_fill(0, count($log_ids), '%d'));
        
        $updated = $wpdb->query($wpdb->prepare("
            UPDATE {$table_name} 
            SET event_data = JSON_SET(COALESCE(event_data, '{}'), '$.reviewed', true, '$.reviewed_by', %d, '$.reviewed_at', %s)
            WHERE id IN ({$placeholders})
        ", get_current_user_id(), current_time('mysql'), ...$log_ids));
        
        if ($updated) {
            $message = sprintf(
                _n('%d log entry marked as reviewed.', '%d log entries marked as reviewed.', $updated, 'secure-aura'),
                $updated
            );
            add_settings_error('secure_aura_messages', 'logs_reviewed', $message, 'updated');
        }
    }

    /**
     * Bulk export logs.
     *
     * @since    3.0.0
     * @param    array $log_ids Log IDs to export.
     */
    private function bulk_export_logs($log_ids) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . SECURE_AURA_TABLE_LOGS;
        $placeholders = implode(',', array_fill(0, count($log_ids), '%d'));
        
        $logs = $wpdb->get_results($wpdb->prepare("
            SELECT * FROM {$table_name} 
            WHERE id IN ({$placeholders})
            ORDER BY created_at DESC
        ", $log_ids));
        
        if (!empty($logs)) {
            $this->export_logs_to_csv($logs);
        }
    }

    /**
     * Export logs to CSV format.
     *
     * @since    3.0.0
     * @param    array $logs Log entries to export.
     */
    private function export_logs_to_csv($logs) {
        $filename = 'secure-aura-logs-' . date('Y-m-d-H-i-s') . '.csv';
        
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        $output = fopen('php://output', 'w');
        
        // CSV headers
        fputcsv($output, [
            'ID',
            'Timestamp',
            'Event Type',
            'Severity',
            'Source IP',
            'User ID',
            'Request URI',
            'User Agent',
            'Response Action',
            'Event Data'
        ]);
        
        // CSV data
        foreach ($logs as $log) {
            fputcsv($output, [
                $log->id,
                $log->timestamp,
                $log->event_type,
                $log->severity,
                $log->source_ip,
                $log->user_id,
                $log->request_uri,
                $log->user_agent,
                $log->response_action,
                $log->event_data
            ]);
        }
        
        fclose($output);
        exit;
    }

    /**
     * Add help tabs to admin pages.
     *
     * @since    3.0.0
     */
    public function add_help_tabs() {
        $current_screen = get_current_screen();
        
        if (!$current_screen || strpos($current_screen->id, 'secure-aura') === false) {
            return;
        }
        
        // General help tab
        $current_screen->add_help_tab([
            'id' => 'secure_aura_general_help',
            'title' => __('General Help', 'secure-aura'),
            'content' => $this->get_general_help_content(),
        ]);
        
        // Feature-specific help tabs
        if (strpos($current_screen->id, 'scanner') !== false) {
            $current_screen->add_help_tab([
                'id' => 'secure_aura_scanner_help',
                'title' => __('Scanner Help', 'secure-aura'),
                'content' => $this->get_scanner_help_content(),
            ]);
        }
        
        if (strpos($current_screen->id, 'firewall') !== false) {
            $current_screen->add_help_tab([
                'id' => 'secure_aura_firewall_help',
                'title' => __('Firewall Help', 'secure-aura'),
                'content' => $this->get_firewall_help_content(),
            ]);
        }
        
        // Help sidebar
        $current_screen->set_help_sidebar($this->get_help_sidebar());
    }

    /**
     * Get general help content.
     *
     * @since    3.0.0
     * @return   string Help content HTML.
     */
    private function get_general_help_content() {
        return '
        <h3>' . __('Getting Started with SecureAura', 'secure-aura') . '</h3>
        <p>' . __('SecureAura provides comprehensive WordPress security protection. Here are the key features:', 'secure-aura') . '</p>
        <ul>
            <li><strong>' . __('Security Dashboard:', 'secure-aura') . '</strong> ' . __('Monitor your site\'s security status in real-time.', 'secure-aura') . '</li>
            <li><strong>' . __('Malware Scanner:', 'secure-aura') . '</strong> ' . __('Scan your site for threats and malicious code.', 'secure-aura') . '</li>
            <li><strong>' . __('Quantum Firewall:', 'secure-aura') . '</strong> ' . __('Advanced protection against attacks and malicious traffic.', 'secure-aura') . '</li>
            <li><strong>' . __('Threat Intelligence:', 'secure-aura') . '</strong> ' . __('Stay updated with the latest security threats.', 'secure-aura') . '</li>
        </ul>
        <p>' . __('For detailed documentation, visit our help center.', 'secure-aura') . '</p>
        ';
    }

    /**
     * Get scanner help content.
     *
     * @since    3.0.0
     * @return   string Help content HTML.
     */
    private function get_scanner_help_content() {
        return '
        <h3>' . __('Using the Malware Scanner', 'secure-aura') . '</h3>
        <p>' . __('The SecureAura scanner uses advanced detection methods to find malware and suspicious files:', 'secure-aura') . '</p>
        <ul>
            <li><strong>' . __('Quick Scan:', 'secure-aura') . '</strong> ' . __('Scans core WordPress files and recently modified files.', 'secure-aura') . '</li>
            <li><strong>' . __('Full Scan:', 'secure-aura') . '</strong> ' . __('Comprehensive scan of all files on your website.', 'secure-aura') . '</li>
            <li><strong>' . __('Real-time Protection:', 'secure-aura') . '</strong> ' . __('Monitors file changes and uploads in real-time.', 'secure-aura') . '</li>
        </ul>
        <h4>' . __('Scan Results', 'secure-aura') . '</h4>
        <p>' . __('When threats are found, you can:', 'secure-aura') . '</p>
        <ul>
            <li>' . __('Quarantine malicious files', 'secure-aura') . '</li>
            <li>' . __('Review false positives', 'secure-aura') . '</li>
            <li>' . __('Restore files from quarantine', 'secure-aura') . '</li>
        </ul>
        ';
    }

    /**
     * Get firewall help content.
     *
     * @since    3.0.0
     * @return   string Help content HTML.
     */
    private function get_firewall_help_content() {
        return '
        <h3>' . __('Configuring the Quantum Firewall', 'secure-aura') . '</h3>
        <p>' . __('The Quantum Firewall provides multiple layers of protection:', 'secure-aura') . '</p>
        <ul>
            <li><strong>' . __('Learning Mode:', 'secure-aura') . '</strong> ' . __('Observes traffic patterns without blocking (recommended for new sites).', 'secure-aura') . '</li>
            <li><strong>' . __('Monitoring Mode:', 'secure-aura') . '</strong> ' . __('Logs suspicious activity but allows traffic through.', 'secure-aura') . '</li>
            <li><strong>' . __('Blocking Mode:', 'secure-aura') . '</strong> ' . __('Actively blocks malicious traffic and attacks.', 'secure-aura') . '</li>
        </ul>
        <h4>' . __('Protection Features', 'secure-aura') . '</h4>
        <ul>
            <li>' . __('Brute force attack protection', 'secure-aura') . '</li>
            <li>' . __('SQL injection prevention', 'secure-aura') . '</li>
            <li>' . __('Cross-site scripting (XSS) protection', 'secure-aura') . '</li>
            <li>' . __('Rate limiting and DDoS protection', 'secure-aura') . '</li>
        </ul>
        ';
    }

    /**
     * Get help sidebar content.
     *
     * @since    3.0.0
     * @return   string Help sidebar HTML.
     */
    private function get_help_sidebar() {
        return '
        <p><strong>' . __('For more help:', 'secure-aura') . '</strong></p>
        <p>
            <a href="https://secureaura.pro/docs" target="_blank">' . __('Documentation', 'secure-aura') . '</a><br>
            <a href="https://secureaura.pro/support" target="_blank">' . __('Support Forum', 'secure-aura') . '</a><br>
            <a href="https://secureaura.pro/contact" target="_blank">' . __('Contact Support', 'secure-aura') . '</a>
        </p>
        <p>
            <strong>' . __('Emergency Support:', 'secure-aura') . '</strong><br>
            ' . __('If your site is compromised, contact us immediately for emergency assistance.', 'secure-aura') . '
        </p>
        ';
    }

    /**
     * Initialize color scheme based on user preference.
     *
     * @since    3.0.0
     */
    public function init_color_scheme() {
        $user_id = get_current_user_id();
        $color_scheme = get_user_meta($user_id, 'admin_color', true);
        
        // Add custom CSS variables based on color scheme
        add_action('admin_head', function() use ($color_scheme) {
            $this->output_color_scheme_css($color_scheme);
        });
    }

    /**
     * Output CSS for color scheme.
     *
     * @since    3.0.0
     * @param    string $color_scheme WordPress color scheme.
     */
    private function output_color_scheme_css($color_scheme) {
        $colors = $this->get_color_scheme_colors($color_scheme);
        
        echo '<style type="text/css">';
        echo '.secure-aura-dashboard {';
        foreach ($colors as $property => $value) {
            echo $property . ': ' . $value . ';';
        }
        echo '}';
        echo '</style>';
    }

    /**
     * Get colors for specific WordPress color scheme.
     *
     * @since    3.0.0
     * @param    string $color_scheme Color scheme name.
     * @return   array Color scheme CSS custom properties.
     */
    private function get_color_scheme_colors($color_scheme) {
        $schemes = [
            'fresh' => [
                '--sa-primary' => '#0073aa',
                '--sa-primary-dark' => '#005a87',
            ],
            'light' => [
                '--sa-primary' => '#04a4cc',
                '--sa-primary-dark' => '#037d99',
            ],
            'blue' => [
                '--sa-primary' => '#096484',
                '--sa-primary-dark' => '#07526c',
            ],
            'midnight' => [
                '--sa-primary' => '#e14d43',
                '--sa-primary-dark' => '#dd382d',
            ],
        ];
        
        return $schemes[$color_scheme] ?? $schemes['fresh'];
    }

    /**
     * Cleanup admin resources.
     *
     * @since    3.0.0
     */
    public function cleanup() {
        // Clean up dashboard widgets
        if ($this->dashboard && method_exists($this->dashboard, 'cleanup')) {
            $this->dashboard->cleanup();
        }
        
        // Clean up settings
        if ($this->settings && method_exists($this->settings, 'cleanup')) {
            $this->settings->cleanup();
        }
        
        // Clear admin transients
        delete_transient('secure_aura_admin_notice_cache');
        delete_transient('secure_aura_dashboard_cache');
        
        // Remove admin hooks
        remove_action('admin_menu', [$this, 'add_admin_menu']);
        remove_action('admin_init', [$this, 'init_settings']);
        remove_action('admin_notices', [$this, 'show_admin_notices']);
        remove_action('admin_enqueue_scripts', [$this, 'enqueue_styles']);
        remove_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
    }
}

?>