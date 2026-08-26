<?php
/**
 * Table creation and upgrades.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Creates the findings and evidence tables and seeds options.
 */
final class Installer {

	/**
	 * CREATE TABLE statements keyed by unprefixed basename.
	 *
	 * Pure so the schema is unit-testable. Table basenames are frozen —
	 * renaming them is a data migration.
	 *
	 * @param string $prefix  Table prefix (e.g. `wp_`).
	 * @param string $charset Charset collate clause.
	 * @return array<string,string>
	 */
	public static function tables( string $prefix, string $charset = '' ): array {
		$findings = $prefix . 'dragoncompliance_findings';
		$evidence = $prefix . 'dragoncompliance_evidence';

		return array(
			'dragoncompliance_findings' => "CREATE TABLE {$findings} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				component_type varchar(10) NOT NULL DEFAULT 'plugin',
				component_slug varchar(191) NOT NULL DEFAULT '',
				component_version varchar(32) NOT NULL DEFAULT '',
				vuln_id varchar(64) NOT NULL DEFAULT '',
				cve varchar(32) NOT NULL DEFAULT '',
				title text NOT NULL,
				severity varchar(16) NOT NULL DEFAULT '',
				cvss decimal(3,1) NOT NULL DEFAULT 0,
				affected_range varchar(191) NOT NULL DEFAULT '',
				status varchar(16) NOT NULL DEFAULT 'open',
				detected_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				resolved_at datetime NULL DEFAULT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY vuln_component (vuln_id, component_slug),
				KEY status (status)
			) {$charset};",
			'dragoncompliance_evidence' => "CREATE TABLE {$evidence} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				event_type varchar(64) NOT NULL DEFAULT '',
				payload longtext NOT NULL,
				created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				prev_hash char(64) NULL DEFAULT NULL,
				hash char(64) NULL DEFAULT NULL,
				PRIMARY KEY  (id),
				KEY event_type (event_type),
				KEY created_at (created_at),
				KEY hash (hash)
			) {$charset};",
		);
	}

	/**
	 * Create tables and seed options.
	 */
	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		foreach ( self::tables( $wpdb->prefix, $wpdb->get_charset_collate() ) as $sql ) {
			dbDelta( $sql );
		}

		add_option( 'dragoncompliance_db_version', DRAGONCOMPLIANCE_DB_VERSION );
		add_option( 'dragoncompliance_alert_enabled', 1 );
		add_option( 'dragoncompliance_attestations', array() );
	}

	/**
	 * Re-run install when the schema version bumps.
	 */
	public static function maybe_upgrade(): void {
		if ( get_option( 'dragoncompliance_db_version' ) !== DRAGONCOMPLIANCE_DB_VERSION ) {
			self::install();
			update_option( 'dragoncompliance_db_version', DRAGONCOMPLIANCE_DB_VERSION );
		}
	}
}
