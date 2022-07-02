<?php
/**
 * Plugin Activation & Deactivation
 * https://developer.wordpress.org/plugins/plugin-basics/activation-deactivation-hooks/
 *
 */

/**
 * Hook into the activation process
 */
function iwb_sso_activate () {
    /** @todo something here?
     * 1. I should check for dependencies and only allow activation if they are all availabe, or I can somehow make them available, and provide some user feedback.
     *  a. curl
     *  b. pythong
     *  c. beempy
     *  d. what else?
     */

}
register_activation_hook( __FILE__, 'iwb_sso_activate' );

/**
 * Redirect on activation
 * @todo make the settings page
 */
function iwb_sso_activation_redirect( $plugin ) {
    if( $plugin == plugin_basename( __FILE__ ) ) {
        exit( wp_redirect( admin_url('admin.php?page=iwb_sso_settings') ) );
    }
}
add_action( 'activated_plugin', 'iwb_sso_activation_redirect' );

?>