/**
 * SecureAura Setup Wizard JavaScript
 * 
 * @package    SecureAura
 * @subpackage SecureAura/assets
 * @since      3.0.0
 * @author     Bitekservices
 * 
 */

(function($) {
    'use strict';

    /**
     * Setup Wizard Object
     */
    var SetupWizard = {
        
        /**
         * Initialize setup wizard
         */
        init: function() {
            this.bindEvents();
            this.initializeSelections();
        },
        
        /**
         * Bind event handlers
         */
        bindEvents: function() {
            // Security level selection
            $('.security-level-option').on('click', function() {
                var radio = $(this).find('input[type="radio"]');
                $('.security-level-option').removeClass('selected');
                $(this).addClass('selected');
                radio.prop('checked', true);
            });
            
            // Firewall option hover effects
            $('.firewall-option, .scanner-option, .notification-option').on('change', 'input[type="checkbox"]', function() {
                if ($(this).is(':checked')) {
                    $(this).closest('.firewall-option, .scanner-option, .notification-option').addClass('checked');
                } else {
                    $(this).closest('.firewall-option, .scanner-option, .notification-option').removeClass('checked');
                }
            });
            
            // Form validation before submit
            $('form.secure-aura-setup-form').on('submit', function(e) {
                return SetupWizard.validateStep($(this));
            });
            
            // Scan frequency change
            $('select[name="scan_frequency"]').on('change', function() {
                var frequency = $(this).val();
                SetupWizard.updateScanInfo(frequency);
            });
            
            // Enable/disable auto-clean based on quarantine
            $('input[name="quarantine_malware"]').on('change', function() {
                var autoClean = $('input[name="auto_clean"]');
                if (!$(this).is(':checked')) {
                    autoClean.prop('checked', false).prop('disabled', true);
                    autoClean.closest('.scanner-option').addClass('disabled');
                } else {
                    autoClean.prop('disabled', false);
                    autoClean.closest('.scanner-option').removeClass('disabled');
                }
            });
            
            // Email validation
            $('input[name="notification_email"]').on('blur', function() {
                SetupWizard.validateEmail($(this));
            });
            
            // Add loading state to buttons
            $('.secure-aura-setup-form button[type="submit"]').on('click', function() {
                var btn = $(this);
                btn.prop('disabled', true);
                btn.find('.dashicons').addClass('dashicons-update').addClass('spin');
                
                // Re-enable after 3 seconds (in case of validation error)
                setTimeout(function() {
                    btn.prop('disabled', false);
                    btn.find('.dashicons').removeClass('dashicons-update').removeClass('spin');
                }, 3000);
            });
        },
        
        /**
         * Initialize current selections
         */
        initializeSelections: function() {
            // Set selected security level
            $('.security-level-option input[type="radio"]:checked').closest('.security-level-option').addClass('selected');
            
            // Mark checked options
            $('.firewall-option input[type="checkbox"]:checked').closest('.firewall-option').addClass('checked');
            $('.scanner-option input[type="checkbox"]:checked').closest('.scanner-option').addClass('checked');
            $('.notification-option input[type="checkbox"]:checked').closest('.notification-option').addClass('checked');
            
            // Check quarantine dependency
            if (!$('input[name="quarantine_malware"]').is(':checked')) {
                $('input[name="auto_clean"]').prop('disabled', true);
                $('input[name="auto_clean"]').closest('.scanner-option').addClass('disabled');
            }
        },
        
        /**
         * Validate current step before submission
         */
        validateStep: function(form) {
            var currentStep = form.closest('.secure-aura-setup-step').find('[class*="secure-aura-setup-"]').attr('class');
            
            // Validate security level step
            if (currentStep.includes('security-level')) {
                if (!$('input[name="security_level"]:checked').length) {
                    SetupWizard.showError('Please select a security level');
                    return false;
                }
            }
            
            // Validate notifications step
            if (currentStep.includes('notifications')) {
                var email = $('input[name="notification_email"]');
                if (!SetupWizard.validateEmail(email)) {
                    return false;
                }
            }
            
            return true;
        },
        
        /**
         * Validate email address
         */
        validateEmail: function(emailInput) {
            var email = emailInput.val();
            var emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            
            if (!emailPattern.test(email)) {
                emailInput.css('border-color', '#dc2626');
                SetupWizard.showError('Please enter a valid email address');
                return false;
            } else {
                emailInput.css('border-color', '#10b981');
                return true;
            }
        },
        
        /**
         * Update scan frequency information
         */
        updateScanInfo: function(frequency) {
            var info = '';
            
            switch(frequency) {
                case 'hourly':
                    info = 'Scans will run every hour. This may impact performance.';
                    break;
                case 'daily':
                    info = 'Scans will run once per day during low-traffic hours.';
                    break;
                case 'weekly':
                    info = 'Scans will run once per week.';
                    break;
                case 'manual':
                    info = 'Scans will only run when manually triggered.';
                    break;
            }
            
            // Remove existing info
            $('.scan-frequency-info').remove();
            
            // Add new info
            if (info) {
                $('select[name="scan_frequency"]').after(
                    '<p class="scan-frequency-info" style="margin-top: 10px; color: #6b7280; font-size: 13px;">' + info + '</p>'
                );
            }
        },
        
        /**
         * Show error message
         */
        showError: function(message) {
            // Remove existing errors
            $('.setup-error-message').remove();
            
            // Add error message
            var errorHtml = '<div class="setup-error-message" style="background: #fee2e2; color: #dc2626; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #dc2626;">' +
                '<strong>Error:</strong> ' + message +
            '</div>';
            
            $('.secure-aura-setup-form').prepend(errorHtml);
            
            // Scroll to error
            $('html, body').animate({
                scrollTop: $('.setup-error-message').offset().top - 100
            }, 500);
            
            // Auto remove after 5 seconds
            setTimeout(function() {
                $('.setup-error-message').fadeOut(function() {
                    $(this).remove();
                });
            }, 5000);
        },
        
        /**
         * Show success message
         */
        showSuccess: function(message) {
            // Remove existing messages
            $('.setup-success-message').remove();
            
            // Add success message
            var successHtml = '<div class="setup-success-message" style="background: #d1fae5; color: #065f46; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #10b981;">' +
                '<strong>Success:</strong> ' + message +
            '</div>';
            
            $('.secure-aura-setup-form').prepend(successHtml);
            
            // Auto remove after 3 seconds
            setTimeout(function() {
                $('.setup-success-message').fadeOut(function() {
                    $(this).remove();
                });
            }, 3000);
        }
    };
    
    /**
     * Initialize on document ready
     */
    $(document).ready(function() {
        SetupWizard.init();
        
        // Add smooth scroll for navigation
        $('a[href^="#"]').on('click', function(e) {
            var target = $(this.hash);
            if (target.length) {
                e.preventDefault();
                $('html, body').animate({
                    scrollTop: target.offset().top - 100
                }, 500);
            }
        });
        
        // Add keyboard navigation
        $(document).on('keydown', function(e) {
            // Enter key to continue
            if (e.keyCode === 13 && !$(e.target).is('textarea')) {
                e.preventDefault();
                $('.secure-aura-setup-form button[type="submit"]').click();
            }
            
            // Escape key to go back
            if (e.keyCode === 27) {
                var backButton = $('.secure-aura-setup-navigation .button-secondary');
                if (backButton.length) {
                    window.location.href = backButton.attr('href');
                }
            }
        });
        
        // Progress animation
        $('.secure-aura-setup-steps li').each(function(index) {
            $(this).css({
                'opacity': '0',
                'transform': 'translateY(-20px)'
            }).delay(index * 100).animate({
                'opacity': '1'
            }, 400, function() {
                $(this).css('transform', 'translateY(0)');
            });
        });
        
        // Add tooltip functionality
        $('[data-tooltip]').hover(
            function() {
                var tooltip = $('<div class="setup-tooltip">' + $(this).data('tooltip') + '</div>');
                $('body').append(tooltip);
                
                var offset = $(this).offset();
                tooltip.css({
                    'top': offset.top - tooltip.outerHeight() - 10,
                    'left': offset.left + ($(this).outerWidth() / 2) - (tooltip.outerWidth() / 2),
                    'position': 'absolute',
                    'background': '#1f2937',
                    'color': '#fff',
                    'padding': '8px 12px',
                    'border-radius': '6px',
                    'font-size': '13px',
                    'z-index': '9999',
                    'white-space': 'nowrap'
                });
            },
            function() {
                $('.setup-tooltip').remove();
            }
        );
    });
    
    /**
     * Add CSS for animations
     */
    var style = document.createElement('style');
    style.textContent = `
        .spin {
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        .disabled {
            opacity: 0.5;
            pointer-events: none;
        }
        
        .checked {
            background-color: #f0f9ff !important;
            border-color: #667eea !important;
        }
    `;
    document.head.appendChild(style);

})(jQuery);