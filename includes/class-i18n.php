<?php
/**
 * Define the internationalization functionality
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @link       https://secureaura.pro
 * @since      3.0.0
 *
 * @package    SecureAura
 * @subpackage SecureAura/includes
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit('Direct access denied.');
}

/**
 * Define the internationalization functionality.
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @since      3.0.0
 * @package    SecureAura
 * @subpackage SecureAura/includes
 * @author     SecureAura Team
 */
class Secure_Aura_i18n {

    /**
     * Load the plugin text domain for translation.
     *
     * @since    3.0.0
     */
    public function load_plugin_textdomain() {
        load_plugin_textdomain(
            'secure-aura',
            false,
            dirname(dirname(plugin_basename(__FILE__))) . '/languages/'
        );
    }
}