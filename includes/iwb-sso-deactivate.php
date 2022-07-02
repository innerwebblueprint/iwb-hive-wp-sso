<?php
/**
 * Plugin Activation & Deactivation
 * https://developer.wordpress.org/plugins/plugin-basics/activation-deactivation-hooks/
 *
 */

/**
 * Hook into deactivation process
 */
function iwb_sso_deactivate() {
	// do something here
}
register_deactivation_hook( __FILE__, 'iwb_sso_deactivate' );

?>