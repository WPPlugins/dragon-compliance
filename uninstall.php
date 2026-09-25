<?php
/**
 * Uninstall: remove tables, options and cron, on every site of a network, but
 * only on sites whose owner opted in.
 *
 * @package DragonCompliance
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Remove this site's scheduled scans, and its tables and options when opted in.
 */
function dragoncompliance_uninstall_site(): void {
	// Scheduled tasks belong to the plugin, not to the data; clear them regardless.
	wp_clear_scheduled_hook( 'dragoncompliance_daily_scan' );
	wp_clear_scheduled_hook( 'dragoncompliance_change_scan' );

	// Respect the site owner's data: nothing else is removed unless they
	// explicitly opted in (the "Delete all data on uninstall" setting). Without
	// the opt-in, tables and options survive so a reinstall picks up exactly
	// where it left off.
	if ( ! get_option( 'dragoncompliance_delete_data_on_uninstall' ) ) {
		return;
	}

	global $wpdb;

	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'dragoncompliance_findings' ) );
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'dragoncompliance_evidence' ) );
	// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange

	foreach ( array(
		'dragoncompliance_db_version',
		'dragoncompliance_alert_enabled',
		'dragoncompliance_attestations',
		'dragoncompliance_attestation_evidence_pending',
		'dragoncompliance_api_token',
		'dragoncompliance_feed_index',
		'dragoncompliance_feed_meta',
		'dragoncompliance_last_scan',
		'dragoncompliance_review_prompt',
		'dragoncompliance_pro_pointer',
		'dragoncompliance_pro_pointer_events',
		'dragoncompliance_schema_failure',
		'dragoncompliance_delete_data_on_uninstall',
	) as $dragoncompliance_option ) {
		delete_option( $dragoncompliance_option );
	}

	delete_transient( 'dragoncompliance_schema_retry' );
	delete_transient( 'dragoncompliance_schema_verified' );
}

if ( is_multisite() ) {
	foreach ( get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	) as $dragoncompliance_site_id ) {
		switch_to_blog( (int) $dragoncompliance_site_id );
		dragoncompliance_uninstall_site();
		restore_current_blog();
	}
} else {
	dragoncompliance_uninstall_site();
}
