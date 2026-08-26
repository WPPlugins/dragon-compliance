<?php
/**
 * Uninstall: remove tables, options and cron.
 *
 * @package DragonCompliance
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Respect the site owner's data: nothing is removed unless they explicitly
// opted in (the "Delete all data on uninstall" setting). Without the opt-in,
// tables and options survive so a reinstall picks up exactly where it left off.
if ( ! get_option( 'dragoncompliance_delete_data_on_uninstall' ) ) {
	return;
}

global $wpdb;

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'dragoncompliance_findings' ) );
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'dragoncompliance_evidence' ) );
// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange

$dragoncompliance_options = array(
	'dragoncompliance_db_version',
	'dragoncompliance_alert_enabled',
	'dragoncompliance_attestations',
	'dragoncompliance_api_token',
	'dragoncompliance_feed_index',
	'dragoncompliance_feed_meta',
	'dragoncompliance_last_scan',
);
foreach ( $dragoncompliance_options as $dragoncompliance_option ) {
	delete_option( $dragoncompliance_option );
}

wp_clear_scheduled_hook( 'dragoncompliance_daily_scan' );
