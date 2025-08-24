<?php
/**
 * BiTek AI Security Guard - Security Logs Page Class
 * 
 * This file should be saved as: includes/class-logs-page.php
 * 
 * @package BiTekAISecurityGuard
 * @since 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class BiTek_Security_Logs_Page {
    
    private $options;
    private $logs_per_page = 50;
    
    public function __construct($options) {
        $this->options = $options;
        $this->init_hooks();
    }
    
    private function init_hooks() {
        add_action('wp_ajax_bitek_get_logs', array($this, 'ajax_get_logs'));
        add_action('wp_ajax_bitek_get_log_details', array($this, 'ajax_get_log_details'));
        add_action('wp_ajax_bitek_block_ip', array($this, 'ajax_block_ip'));
        add_action('wp_ajax_bitek_clear_logs', array($this, 'ajax_clear_logs'));
        add_action('wp_ajax_bitek_export_logs', array($this, 'ajax_export_logs'));
    }
    
    /**
     * Render the security logs page
     */
    public function render_logs_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'bitek-ai-security'));
        }
        
        $current_page = isset($_GET['paged']) ? intval($_GET['paged']) : 1;
        $filter_type = isset($_GET['filter_type']) ? sanitize_text_field($_GET['filter_type']) : '';
        $filter_date = isset($_GET['filter_date']) ? sanitize_text_field($_GET['filter_date']) : '';
        
        $logs = $this->get_logs($current_page, $filter_type, $filter_date);
        $total_logs = $this->get_total_logs($filter_type, $filter_date);
        $total_pages = ceil($total_logs / $this->logs_per_page);
        
        ?>
        <div class="wrap bitek-logs">
            <div class="bitek-header">
                <h1><?php echo esc_html__('Security Logs', 'bitek-ai-security'); ?></h1>
                <div class="bitek-header-notice">
                    <span class="dashicons dashicons-info"></span>
                    <?php echo esc_html__('Monitor all security events and blocked attempts in real-time', 'bitek-ai-security'); ?>
                </div>
            </div>
            
            <div class="bitek-logs-container">
                <!-- Filters -->
                <div class="bitek-logs-filters">
                    <div class="bitek-filter-group">
                        <label for="log-type-filter"><?php echo esc_html__('Filter by Type:', 'bitek-ai-security'); ?></label>
                        <select id="log-type-filter" name="filter_type">
                            <option value=""><?php echo esc_html__('All Types', 'bitek-ai-security'); ?></option>
                            <option value="comment_blocked" <?php selected($filter_type, 'comment_blocked'); ?>><?php echo esc_html__('Blocked Comments', 'bitek-ai-security'); ?></option>
                            <option value="ai_comment_blocked" <?php selected($filter_type, 'ai_comment_blocked'); ?>><?php echo esc_html__('AI Blocked Comments', 'bitek-ai-security'); ?></option>
                            <option value="firewall_blocked" <?php selected($filter_type, 'firewall_blocked'); ?>><?php echo esc_html__('Firewall Events', 'bitek-ai-security'); ?></option>
                            <option value="login_failed" <?php selected($filter_type, 'login_failed'); ?>><?php echo esc_html__('Failed Logins', 'bitek-ai-security'); ?></option>
                            <option value="scan_completed" <?php selected($filter_type, 'scan_completed'); ?>><?php echo esc_html__('Security Scans', 'bitek-ai-security'); ?></option>
                            <option value="system" <?php selected($filter_type, 'system'); ?>><?php echo esc_html__('System Events', 'bitek-ai-security'); ?></option>
                        </select>
                    </div>
                    
                    <div class="bitek-filter-group">
                        <label for="log-date-filter"><?php echo esc_html__('Filter by Date:', 'bitek-ai-security'); ?></label>
                        <input type="date" id="log-date-filter" name="filter_date" value="<?php echo esc_attr($filter_date); ?>" />
                    </div>
                    
                    <div class="bitek-filter-actions">
                        <button type="button" class="button button-primary" id="apply-filters"><?php echo esc_html__('Apply Filters', 'bitek-ai-security'); ?></button>
                        <button type="button" class="button button-secondary" id="clear-filters"><?php echo esc_html__('Clear Filters', 'bitek-ai-security'); ?></button>
                        <button type="button" class="button button-secondary" id="export-logs"><?php echo esc_html__('Export Logs', 'bitek-ai-security'); ?></button>
                        <button type="button" class="button button-danger" id="clear-all-logs"><?php echo esc_html__('Clear All Logs', 'bitek-ai-security'); ?></button>
                    </div>
                </div>
                
                <!-- Statistics -->
                <div class="bitek-logs-stats">
                    <div class="bitek-stat-item">
                        <span class="bitek-stat-number"><?php echo esc_html($total_logs); ?></span>
                        <span class="bitek-stat-label"><?php echo esc_html__('Total Events', 'bitek-ai-security'); ?></span>
                    </div>
                    <div class="bitek-stat-item">
                        <span class="bitek-stat-number"><?php echo esc_html($this->get_today_logs_count()); ?></span>
                        <span class="bitek-stat-label"><?php echo esc_html__('Today\'s Events', 'bitek-ai-security'); ?></span>
                    </div>
                    <div class="bitek-stat-item">
                        <span class="bitek-stat-number"><?php echo esc_html($this->get_blocked_attempts_count()); ?></span>
                        <span class="bitek-stat-label"><?php echo esc_html__('Blocked Attempts', 'bitek-ai-security'); ?></span>
                    </div>
                    <div class="bitek-stat-item">
                        <span class="bitek-stat-number"><?php echo esc_html($this->get_unique_ips_count()); ?></span>
                        <span class="bitek-stat-label"><?php echo esc_html__('Unique IPs', 'bitek-ai-security'); ?></span>
                    </div>
                </div>
                
                <!-- Logs Table -->
                <div class="bitek-logs-table-container">
                    <?php if (empty($logs)): ?>
                        <div class="bitek-no-logs">
                            <div class="bitek-no-logs-icon">
                                <span class="dashicons dashicons-shield-alt"></span>
                            </div>
                            <h3><?php echo esc_html__('No Security Events Found', 'bitek-ai-security'); ?></h3>
                            <p><?php echo esc_html__('No security events match your current filters. Try adjusting the filters or check back later.', 'bitek-ai-security'); ?></p>
                        </div>
                    <?php else: ?>
                                                    <table class="wp-list-table widefat fixed striped bitek-logs-table" id="bitek-logs-table">
                            <thead>
                                <tr>
                                    <th class="column-timestamp"><?php echo esc_html__('Time', 'bitek-ai-security'); ?></th>
                                    <th class="column-type"><?php echo esc_html__('Type', 'bitek-ai-security'); ?></th>
                                    <th class="column-event"><?php echo esc_html__('Event', 'bitek-ai-security'); ?></th>
                                    <th class="column-ip"><?php echo esc_html__('IP Address', 'bitek-ai-security'); ?></th>
                                    <th class="column-user-agent"><?php echo esc_html__('User Agent', 'bitek-ai-security'); ?></th>
                                    <th class="column-actions"><?php echo esc_html__('Actions', 'bitek-ai-security'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($logs as $log): ?>
                                <tr class="bitek-log-row" data-log-id="<?php echo esc_attr($log->id); ?>">
                                    <td class="column-timestamp" data-label="Time">
                                        <div class="bitek-timestamp">
                                            <?php echo esc_html(date('M j, Y', strtotime($log->created_at))); ?>
                                            <br>
                                            <small><?php echo esc_html(date('g:i:s A', strtotime($log->created_at))); ?></small>
                                        </div>
                                    </td>
                                    <td class="column-type" data-label="Type">
                                        <span class="bitek-log-type bitek-log-<?php echo esc_attr($this->get_log_type_class($log->type)); ?>">
                                            <?php echo esc_html($this->get_formatted_log_type($log->type)); ?>
                                        </span>
                                    </td>
                                    <td class="column-event" data-label="Event">
                                        <div class="bitek-event-text">
                                            <?php echo esc_html($this->truncate_text($log->event, 80)); ?>
                                        </div>
                                    </td>
                                    <td class="column-ip" data-label="IP Address">
                                        <div class="bitek-ip-info">
                                            <strong><?php echo esc_html($log->ip); ?></strong>
                                            <?php if ($this->is_ip_blocked($log->ip)): ?>
                                                <br><span class="bitek-ip-blocked"><?php echo esc_html__('Blocked', 'bitek-ai-security'); ?></span>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                    <td class="column-user-agent" data-label="User Agent">
                                        <div class="bitek-user-agent" title="<?php echo esc_attr($log->user_agent); ?>">
                                            <?php echo esc_html($this->truncate_text($log->user_agent, 40)); ?>
                                        </div>
                                    </td>
                                    <td class="column-actions" data-label="Actions">
                                        <div class="bitek-log-actions">
                                            <button type="button" class="button button-small bitek-view-details" data-log-id="<?php echo esc_attr($log->id); ?>" title="<?php echo esc_attr__('View Details', 'bitek-ai-security'); ?>">
                                                <span class="dashicons dashicons-visibility"></span>
                                            </button>
                                            <?php if (!$this->is_ip_blocked($log->ip) && filter_var($log->ip, FILTER_VALIDATE_IP)): ?>
                                                <button type="button" class="button button-small bitek-block-ip" data-ip="<?php echo esc_attr($log->ip); ?>" title="<?php echo esc_attr__('Block IP', 'bitek-ai-security'); ?>">
                                                    <span class="dashicons dashicons-dismiss"></span>
                                                </button>
                                            <?php endif; ?>
                                            <?php if ($log->ip && filter_var($log->ip, FILTER_VALIDATE_IP)): ?>
                                                <button type="button" class="button button-small bitek-whois-lookup" data-ip="<?php echo esc_attr($log->ip); ?>" title="<?php echo esc_attr__('WHOIS Lookup', 'bitek-ai-security'); ?>">
                                                    <span class="dashicons dashicons-admin-site"></span>
                                                </button>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                        
                        <!-- Pagination -->
                        <?php if ($total_pages > 1): ?>
                        <div class="bitek-pagination">
                            <?php
                            $pagination_args = array(
                                'base' => add_query_arg('paged', '%#%'),
                                'format' => '',
                                'prev_text' => '&laquo; ' . __('Previous', 'bitek-ai-security'),
                                'next_text' => __('Next', 'bitek-ai-security') . ' &raquo;',
                                'current' => $current_page,
                                'total' => $total_pages,
                                'show_all' => false,
                                'end_size' => 1,
                                'mid_size' => 2,
                                'type' => 'array'
                            );
                            
                            $pagination_links = paginate_links($pagination_args);
                            
                            if ($pagination_links) {
                                echo '<div class="tablenav-pages">';
                                echo '<span class="displaying-num">';
                                printf(__('%s events', 'bitek-ai-security'), number_format_i18n($total_logs));
                                echo '</span>';
                                echo '<span class="pagination-links">';
                                echo implode("\n", $pagination_links);
                                echo '</span>';
                                echo '</div>';
                            }
                            ?>
                        </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <script type="text/javascript">
        jQuery(document).ready(function($) {
            
            // Apply filters
            $('#apply-filters').on('click', function() {
                const type = $('#log-type-filter').val();
                const date = $('#log-date-filter').val();
                
                let url = window.location.pathname + '?page=bitek-security-logs';
                if (type) url += '&filter_type=' + encodeURIComponent(type);
                if (date) url += '&filter_date=' + encodeURIComponent(date);
                
                window.location.href = url;
            });
            
            // Clear filters
            $('#clear-filters').on('click', function() {
                $('#log-type-filter').val('');
                $('#log-date-filter').val('');
                window.location.href = window.location.pathname + '?page=bitek-security-logs';
            });
            
            // View log details
            $('.bitek-view-details').on('click', function() {
                const logId = $(this).data('log-id');
                BiTekLogs.viewLogDetails(logId);
            });
            
            // Block IP
            $('.bitek-block-ip').on('click', function() {
                const ip = $(this).data('ip');
                BiTekLogs.blockIP(ip);
            });
            
            // WHOIS lookup
            $('.bitek-whois-lookup').on('click', function() {
                const ip = $(this).data('ip');
                window.open('https://whois.net/ip-address-lookup/' + ip, '_blank');
            });
            
            // Export logs
            $('#export-logs').on('click', function() {
                BiTekLogs.exportLogs();
            });
            
            // Clear all logs
            $('#clear-all-logs').on('click', function() {
                BiTekLogs.clearAllLogs();
            });
            
        });
        
        // BiTek Logs JavaScript object
        const BiTekLogs = {
            
            viewLogDetails: function(logId) {
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'bitek_get_log_details',
                        log_id: logId,
                        nonce: '<?php echo wp_create_nonce('bitek_logs_nonce'); ?>'
                    },
                    beforeSend: function() {
                        $('.bitek-view-details[data-log-id="' + logId + '"]')
                            .prop('disabled', true)
                            .html('<span class="dashicons dashicons-update"></span>');
                    },
                    success: function(response) {
                        if (response.success && response.data) {
                            BiTekLogs.showLogDetailsModal(response.data);
                        } else {
                            alert('<?php echo esc_js(__('Failed to load log details', 'bitek-ai-security')); ?>');
                        }
                    },
                    error: function() {
                        alert('<?php echo esc_js(__('Error loading log details', 'bitek-ai-security')); ?>');
                    },
                    complete: function() {
                        $('.bitek-view-details[data-log-id="' + logId + '"]')
                            .prop('disabled', false)
                            .html('<span class="dashicons dashicons-visibility"></span>');
                    }
                });
            },
            
            showLogDetailsModal: function(logData) {
                const modal = $(`
                    <div id="bitek-log-details-modal" class="bitek-modal">
                        <div class="bitek-modal-content bitek-modal-large">
                            <div class="bitek-modal-header">
                                <h3><?php echo esc_js(__('Security Log Details', 'bitek-ai-security')); ?></h3>
                                <button type="button" class="bitek-modal-close">&times;</button>
                            </div>
                            <div class="bitek-modal-body">
                                <table class="bitek-details-table">
                                    <tr><th><?php echo esc_js(__('Time:', 'bitek-ai-security')); ?></th><td>${logData.created_at || '<?php echo esc_js(__('Unknown', 'bitek-ai-security')); ?>'}</td></tr>
                                    <tr><th><?php echo esc_js(__('Type:', 'bitek-ai-security')); ?></th><td><span class="bitek-log-type bitek-log-${BiTekLogs.getLogTypeClass(logData.type)}">${BiTekLogs.formatLogType(logData.type)}</span></td></tr>
                                    <tr><th><?php echo esc_js(__('Event:', 'bitek-ai-security')); ?></th><td>${logData.event || '<?php echo esc_js(__('No event description', 'bitek-ai-security')); ?>'}</td></tr>
                                    <tr><th><?php echo esc_js(__('IP Address:', 'bitek-ai-security')); ?></th><td>${logData.ip || '<?php echo esc_js(__('Unknown', 'bitek-ai-security')); ?>'}</td></tr>
                                    <tr><th><?php echo esc_js(__('User Agent:', 'bitek-ai-security')); ?></th><td>${logData.user_agent || '<?php echo esc_js(__('Unknown', 'bitek-ai-security')); ?>'}</td></tr>
                                    <tr><th><?php echo esc_js(__('URL:', 'bitek-ai-security')); ?></th><td>${logData.url || '<?php echo esc_js(__('N/A', 'bitek-ai-security')); ?>'}</td></tr>
                                    ${logData.data ? `<tr><th><?php echo esc_js(__('Additional Data:', 'bitek-ai-security')); ?></th><td><pre>${BiTekLogs.formatJSON(logData.data)}</pre></td></tr>` : ''}
                                </table>
                            </div>
                        </div>
                    </div>
                `);
                
                $('body').append(modal);
                
                modal.find('.bitek-modal-close, .bitek-modal').on('click', function(e) {
                    if (e.target === this) {
                        modal.remove();
                    }
                });
            },
            
            blockIP: function(ip) {
                if (!confirm('<?php echo esc_js(__('Are you sure you want to block this IP address?', 'bitek-ai-security')); ?>')) {
                    return;
                }
                
                const reason = prompt('<?php echo esc_js(__('Reason for blocking (optional):', 'bitek-ai-security')); ?>', '<?php echo esc_js(__('Blocked via logs page', 'bitek-ai-security')); ?>');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'bitek_block_ip',
                        ip: ip,
                        reason: reason,
                        nonce: '<?php echo wp_create_nonce('bitek_logs_nonce'); ?>'
                    },
                    beforeSend: function() {
                        $('.bitek-block-ip[data-ip="' + ip + '"]').prop('disabled', true);
                    },
                    success: function(response) {
                        if (response.success) {
                            alert('<?php echo esc_js(__('IP address blocked successfully', 'bitek-ai-security')); ?>');
                            location.reload();
                        } else {
                            alert('<?php echo esc_js(__('Failed to block IP address', 'bitek-ai-security')); ?>');
                        }
                    },
                    error: function() {
                        alert('<?php echo esc_js(__('Error blocking IP address', 'bitek-ai-security')); ?>');
                    },
                    complete: function() {
                        $('.bitek-block-ip[data-ip="' + ip + '"]').prop('disabled', false);
                    }
                });
            },
            
            exportLogs: function() {
                const format = prompt('<?php echo esc_js(__('Export format (json, csv, xml):', 'bitek-ai-security')); ?>', 'json');
                if (!format) return;
                
                window.location.href = `admin-ajax.php?action=bitek_export_logs&format=${format}&nonce=<?php echo wp_create_nonce('bitek_logs_nonce'); ?>`;
            },
            
            clearAllLogs: function() {
                if (!confirm('<?php echo esc_js(__('Are you sure you want to clear all security logs? This action cannot be undone.', 'bitek-ai-security')); ?>')) {
                    return;
                }
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'bitek_clear_logs',
                        nonce: '<?php echo wp_create_nonce('bitek_logs_nonce'); ?>'
                    },
                    beforeSend: function() {
                        $('#clear-all-logs').prop('disabled', true).text('<?php echo esc_js(__('Clearing...', 'bitek-ai-security')); ?>');
                    },
                    success: function(response) {
                        if (response.success) {
                            alert('<?php echo esc_js(__('All security logs cleared successfully', 'bitek-ai-security')); ?>');
                            location.reload();
                        } else {
                            alert('<?php echo esc_js(__('Failed to clear logs', 'bitek-ai-security')); ?>');
                        }
                    },
                    error: function() {
                        alert('<?php echo esc_js(__('Error clearing logs', 'bitek-ai-security')); ?>');
                    },
                    complete: function() {
                        $('#clear-all-logs').prop('disabled', false).text('<?php echo esc_js(__('Clear All Logs', 'bitek-ai-security')); ?>');
                    }
                });
            },
            
            getLogTypeClass: function(type) {
                const typeClasses = {
                    'comment_blocked': 'blocked',
                    'ai_comment_blocked': 'ai-blocked',
                    'firewall_blocked': 'firewall',
                    'login_failed': 'login',
                    'scan_completed': 'scan',
                    'system': 'system',
                    'error': 'error',
                    'threat_intelligence_update': 'update',
                    'emergency_lockdown': 'emergency'
                };
                return typeClasses[type] || 'default';
            },
            
            formatLogType: function(type) {
                const typeNames = {
                    'comment_blocked': '<?php echo esc_js(__('Comment Blocked', 'bitek-ai-security')); ?>',
                    'ai_comment_blocked': '<?php echo esc_js(__('AI Blocked', 'bitek-ai-security')); ?>',
                    'firewall_blocked': '<?php echo esc_js(__('Firewall Block', 'bitek-ai-security')); ?>',
                    'login_failed': '<?php echo esc_js(__('Failed Login', 'bitek-ai-security')); ?>',
                    'scan_completed': '<?php echo esc_js(__('Security Scan', 'bitek-ai-security')); ?>',
                    'system': '<?php echo esc_js(__('System Event', 'bitek-ai-security')); ?>',
                    'error': '<?php echo esc_js(__('Error', 'bitek-ai-security')); ?>',
                    'threat_intelligence_update': '<?php echo esc_js(__('Threat Update', 'bitek-ai-security')); ?>',
                    'emergency_lockdown': '<?php echo esc_js(__('Emergency Mode', 'bitek-ai-security')); ?>'
                };
                return typeNames[type] || type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            },
            
            formatJSON: function(jsonString) {
                try {
                    const parsed = JSON.parse(jsonString);
                    return JSON.stringify(parsed, null, 2);
                } catch (e) {
                    return jsonString;
                }
            }
            
        };
        </script>
        <?php
    }
    
    /**
     * Get security logs with pagination and filtering
     */
    private function get_logs($page = 1, $type = '', $date = '') {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        $offset = ($page - 1) * $this->logs_per_page;
        
        $where_conditions = array('1=1');
        $prepare_values = array();
        
        if (!empty($type)) {
            $where_conditions[] = 'type = %s';
            $prepare_values[] = $type;
        }
        
        if (!empty($date)) {
            $where_conditions[] = 'DATE(created_at) = %s';
            $prepare_values[] = $date;
        }
        
        $where_clause = implode(' AND ', $where_conditions);
        
        // Add pagination values
        $prepare_values[] = $this->logs_per_page;
        $prepare_values[] = $offset;
        
        $query = "SELECT * FROM {$table_name} WHERE {$where_clause} ORDER BY created_at DESC LIMIT %d OFFSET %d";
        
        if (!empty($prepare_values)) {
            return $wpdb->get_results($wpdb->prepare($query, $prepare_values));
        } else {
            return $wpdb->get_results($query);
        }
    }
    
    /**
     * Get total count of logs with filtering
     */
    private function get_total_logs($type = '', $date = '') {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $where_conditions = array('1=1');
        $prepare_values = array();
        
        if (!empty($type)) {
            $where_conditions[] = 'type = %s';
            $prepare_values[] = $type;
        }
        
        if (!empty($date)) {
            $where_conditions[] = 'DATE(created_at) = %s';
            $prepare_values[] = $date;
        }
        
        $where_clause = implode(' AND ', $where_conditions);
        $query = "SELECT COUNT(*) FROM {$table_name} WHERE {$where_clause}";
        
        if (!empty($prepare_values)) {
            return intval($wpdb->get_var($wpdb->prepare($query, $prepare_values)));
        } else {
            return intval($wpdb->get_var($query));
        }
    }
    
    /**
     * Get today's logs count
     */
    private function get_today_logs_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        return intval($wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE DATE(created_at) = CURDATE()
        ")) ?: 0;
    }
    
    /**
     * Get blocked attempts count (last 7 days)
     */
    private function get_blocked_attempts_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        return intval($wpdb->get_var("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE type LIKE '%blocked%' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ")) ?: 0;
    }
    
    /**
     * Get unique IPs count (last 7 days)
     */
    private function get_unique_ips_count() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        return intval($wpdb->get_var("
            SELECT COUNT(DISTINCT ip) FROM {$table_name} 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ")) ?: 0;
    }
    
    /**
     * Check if IP is blocked
     */
    private function is_ip_blocked($ip) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'bitek_blocked_ips';
        
        $result = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$table_name} 
            WHERE ip = %s 
            AND (expires_at IS NULL OR expires_at > NOW())
        ", $ip));
        
        return intval($result) > 0;
    }
    
    /**
     * Get formatted log type for display
     */
    private function get_formatted_log_type($type) {
        $type_names = array(
            'comment_blocked' => __('Comment Blocked', 'bitek-ai-security'),
            'ai_comment_blocked' => __('AI Blocked', 'bitek-ai-security'),
            'firewall_blocked' => __('Firewall Block', 'bitek-ai-security'),
            'login_failed' => __('Failed Login', 'bitek-ai-security'),
            'scan_completed' => __('Security Scan', 'bitek-ai-security'),
            'system' => __('System Event', 'bitek-ai-security'),
            'error' => __('Error', 'bitek-ai-security'),
            'threat_intelligence_update' => __('Threat Update', 'bitek-ai-security'),
            'emergency_lockdown' => __('Emergency Mode', 'bitek-ai-security'),
            'ip_blocked' => __('IP Blocked', 'bitek-ai-security')
        );
        
        return isset($type_names[$type]) ? $type_names[$type] : ucwords(str_replace('_', ' ', $type));
    }
    
    /**
     * Get CSS class for log type
     */
    private function get_log_type_class($type) {
        $type_classes = array(
            'comment_blocked' => 'blocked',
            'ai_comment_blocked' => 'ai-blocked',
            'firewall_blocked' => 'firewall',
            'login_failed' => 'login',
            'scan_completed' => 'scan',
            'system' => 'system',
            'error' => 'error',
            'threat_intelligence_update' => 'update',
            'emergency_lockdown' => 'emergency',
            'ip_blocked' => 'blocked'
        );
        
        return isset($type_classes[$type]) ? $type_classes[$type] : 'default';
    }
    
    /**
     * Truncate text to specified length
     */
    private function truncate_text($text, $length = 50) {
        if (strlen($text) <= $length) {
            return $text;
        }
        
        return substr($text, 0, $length - 3) . '...';
    }
    
    /**
     * AJAX: Get log details
     */
    public function ajax_get_log_details() {
        check_ajax_referer('bitek_logs_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }
        
        $log_id = isset($_POST['log_id']) ? intval($_POST['log_id']) : 0;
        
        if (!$log_id) {
            wp_send_json_error('Invalid log ID');
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $log = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table_name} WHERE id = %d",
            $log_id
        ), ARRAY_A);
        
        if (!$log) {
            wp_send_json_error('Log not found');
        }
        
        // Ensure all required fields exist with default values
        $log_data = array(
            'id' => $log['id'] ?? '',
            'type' => $log['type'] ?? 'unknown',
            'event' => $log['event'] ?? 'No event description',
            'ip' => $log['ip'] ?? 'Unknown',
            'user_agent' => $log['user_agent'] ?? 'Unknown',
            'url' => $log['url'] ?? '',
            'data' => $log['data'] ?? '',
            'created_at' => $log['created_at'] ?? 'Unknown'
        );
        
        wp_send_json_success($log_data);
    }
    
    /**
     * AJAX: Block IP address
     */
    public function ajax_block_ip() {
        check_ajax_referer('bitek_logs_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }
        
        $ip = isset($_POST['ip']) ? sanitize_text_field($_POST['ip']) : '';
        $reason = isset($_POST['reason']) ? sanitize_text_field($_POST['reason']) : 'Blocked via logs page';
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error('Invalid IP address');
        }
        
        // Check if IP is already blocked
        if ($this->is_ip_blocked($ip)) {
            wp_send_json_error('IP address is already blocked');
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'bitek_blocked_ips';
        
        $result = $wpdb->insert(
            $table_name,
            array(
                'ip' => $ip,
                'reason' => $reason,
                'blocked_at' => current_time('mysql'),
                'is_permanent' => 1
            ),
            array('%s', '%s', '%s', '%d')
        );
        
        if ($result === false) {
            wp_send_json_error('Failed to block IP address');
        }
        
        // Log the blocking action
        $this->log_security_event('ip_blocked', "IP {$ip} blocked manually", array(
            'ip' => $ip,
            'reason' => $reason,
            'blocked_by' => get_current_user_id()
        ));
        
        wp_send_json_success('IP address blocked successfully');
    }
    
    /**
     * AJAX: Clear all logs
     */
    public function ajax_clear_logs() {
        check_ajax_referer('bitek_logs_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $result = $wpdb->query("TRUNCATE TABLE {$table_name}");
        
        if ($result === false) {
            wp_send_json_error('Failed to clear logs');
        }
        
        wp_send_json_success('All logs cleared successfully');
    }
    
    /**
     * AJAX: Export logs
     */
    public function ajax_export_logs() {
        check_ajax_referer('bitek_logs_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }
        
        $format = isset($_GET['format']) ? sanitize_text_field($_GET['format']) : 'json';
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'bitek_security_logs';
        
        $logs = $wpdb->get_results("SELECT * FROM {$table_name} ORDER BY created_at DESC", ARRAY_A);
        
        switch ($format) {
            case 'csv':
                $this->export_logs_csv($logs);
                break;
            case 'xml':
                $this->export_logs_xml($logs);
                break;
            default:
                $this->export_logs_json($logs);
                break;
        }
    }
    
    /**
     * Export logs as JSON
     */
    private function export_logs_json($logs) {
        $filename = 'bitek-security-logs-' . date('Y-m-d-H-i-s') . '.json';
        
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Cache-Control: no-cache, must-revalidate');
        header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
        
        echo wp_json_encode(array(
            'export_info' => array(
                'site_url' => get_site_url(),
                'export_date' => current_time('mysql'),
                'plugin_version' => BITEK_AI_SECURITY_VERSION,
                'total_logs' => count($logs)
            ),
            'logs' => $logs
        ), JSON_PRETTY_PRINT);
        
        exit;
    }
    
    /**
     * Export logs as CSV
     */
    private function export_logs_csv($logs) {
        $filename = 'bitek-security-logs-' . date('Y-m-d-H-i-s') . '.csv';
        
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Cache-Control: no-cache, must-revalidate');
        header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
        
        $output = fopen('php://output', 'w');
        
        // CSV headers
        fputcsv($output, array('ID', 'Type', 'Event', 'IP', 'User Agent', 'URL', 'Data', 'Created At'));
        
        // CSV data
        foreach ($logs as $log) {
            fputcsv($output, array(
                $log['id'] ?? '',
                $log['type'] ?? '',
                $log['event'] ?? '',
                $log['ip'] ?? '',
                $log['user_agent'] ?? '',
                $log['url'] ?? '',
                $log['data'] ?? '',
                $log['created_at'] ?? ''
            ));
        }
        
        fclose($output);
        exit;
    }
    
    /**
     * Export logs as XML
     */
    private function export_logs_xml($logs) {
        $filename = 'bitek-security-logs-' . date('Y-m-d-H-i-s') . '.xml';
        
        header('Content-Type: application/xml');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Cache-Control: no-cache, must-revalidate');
        header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
        
        $xml = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><security_logs></security_logs>');
        
        $export_info = $xml->addChild('export_info');
        $export_info->addChild('site_url', htmlspecialchars(get_site_url()));
        $export_info->addChild('export_date', current_time('mysql'));
        $export_info->addChild('plugin_version', BITEK_AI_SECURITY_VERSION);
        $export_info->addChild('total_logs', count($logs));
        
        $logs_node = $xml->addChild('logs');
        
        foreach ($logs as $log_data) {
            $log_node = $logs_node->addChild('log');
            $log_node->addChild('id', $log_data['id'] ?? '');
            $log_node->addChild('type', htmlspecialchars($log_data['type'] ?? ''));
            $log_node->addChild('event', htmlspecialchars($log_data['event'] ?? ''));
            $log_node->addChild('ip', $log_data['ip'] ?? '');
            $log_node->addChild('user_agent', htmlspecialchars($log_data['user_agent'] ?? ''));
            $log_node->addChild('url', htmlspecialchars($log_data['url'] ?? ''));
            $log_node->addChild('data', htmlspecialchars($log_data['data'] ?? ''));
            $log_node->addChild('created_at', $log_data['created_at'] ?? '');
        }
        
        echo $xml->asXML();
        exit;
    }
    
    /**
     * Log security event
     */
    private function log_security_event($type, $message, $data = array()) {
        if (class_exists('BiTek_AI_Security_Guard')) {
            $instance = BiTek_AI_Security_Guard::get_instance();
            $instance->bitek_log_security_event($type, $message, $data);
        }
    }
}