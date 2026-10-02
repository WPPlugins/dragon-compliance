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
	 * Transient that holds off install retries after a failure.
	 */
	private const RETRY_TRANSIENT = 'dragoncompliance_schema_retry';

	/**
	 * Marks the stamped schema as confirmed against the real tables, so the
	 * confirmation costs one set of queries rather than one per request.
	 */
	private const VERIFIED_TRANSIENT = 'dragoncompliance_schema_verified';

	/**
	 * Option recording the last failed install: ['tables' => string[], 'at' => int].
	 */
	private const FAILURE_OPTION = 'dragoncompliance_schema_failure';

	/**
	 * Seconds between install retries after a failure.
	 */
	private const RETRY_INTERVAL = 10 * MINUTE_IN_SECONDS;

	/**
	 * CREATE TABLE statements keyed by unprefixed basename.
	 *
	 * Pure so the schema is unit-testable. Table basenames are frozen:
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
	 *
	 * The schema version is stamped only once every table is confirmed to
	 * exist; dbDelta reports what it attempted, not what succeeded.
	 *
	 * @return bool Whether every table exists after the run.
	 */
	public static function install(): bool {
		global $wpdb;

		foreach ( self::tables( $wpdb->prefix, $wpdb->get_charset_collate() ) as $sql ) {
			if ( ! function_exists( 'dbDelta' ) ) {
				require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			}
			dbDelta( $sql );
		}

		add_option( 'dragoncompliance_alert_enabled', 1 );
		add_option( 'dragoncompliance_attestations', array() );

		$missing = self::missing_tables();
		if ( array() !== $missing ) {
			delete_transient( self::VERIFIED_TRANSIENT );
			update_option(
				self::FAILURE_OPTION,
				array(
					'tables' => $missing,
					'at'     => time(),
				),
				false
			);
			set_transient( self::RETRY_TRANSIENT, 1, self::RETRY_INTERVAL );
			return false;
		}

		delete_option( self::FAILURE_OPTION );
		delete_transient( self::RETRY_TRANSIENT );
		update_option( 'dragoncompliance_db_version', DRAGONCOMPLIANCE_DB_VERSION );
		set_transient( self::VERIFIED_TRANSIENT, 1, DAY_IN_SECONDS );
		return true;
	}

	/**
	 * The last failed install, or null once the tables exist.
	 *
	 * @return array{tables:string[],at:int}|null
	 */
	public static function schema_failure(): ?array {
		$stored = get_option( self::FAILURE_OPTION );
		if ( ! is_array( $stored ) || empty( $stored['tables'] ) ) {
			return null;
		}
		return array(
			'tables' => array_map( 'strval', (array) $stored['tables'] ),
			'at'     => (int) ( $stored['at'] ?? 0 ),
		);
	}

	/**
	 * Admin notice naming the tables that could not be created.
	 */
	public static function render_schema_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$failure = self::schema_failure();
		if ( null === $failure ) {
			return;
		}
		printf(
			'<div class="notice notice-error"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: %s: list of table names. */
					__( 'Dragon Compliance could not create its database tables (%s). Check that the database user may CREATE TABLE; the plugin retries every 10 minutes.', 'dragon-compliance' ),
					implode( wp_get_list_item_separator(), $failure['tables'] )
				)
			)
		);
	}

	/**
	 * Plugin tables that do not exist, fully prefixed.
	 *
	 * @return string[]
	 */
	public static function missing_tables(): array {
		global $wpdb;

		$missing = array();
		foreach ( array_keys( self::tables( $wpdb->prefix ) ) as $basename ) {
			$table = $wpdb->prefix . $basename;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$found = (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) );
			if ( 0 !== strcasecmp( $found, $table ) ) {
				$missing[] = $table;
			}
		}
		return $missing;
	}

	/**
	 * Whether the stamped schema version is backed by tables that really exist.
	 *
	 * An earlier release could stamp the version despite a failed dbDelta, and
	 * the stamp it left matches the current one, so the stamp alone cannot be
	 * trusted: the installations needing repair are exactly the ones an
	 * unconditional early return would skip. Cached for a day so this is not a
	 * set of SHOW TABLES queries on every request.
	 *
	 * @return bool
	 */
	private static function schema_confirmed(): bool {
		/*
		 * On a front-end request a stamped schema is trusted, as it was before
		 * this check existed. The confirmation exists to drive an admin notice
		 * and recreate a missing table, and neither happens outside wp-admin;
		 * running it everywhere would add an uncached option read to every page
		 * view, because this runs on every request.
		 */
		if ( ! is_admin() ) {
			return true;
		}

		if ( false !== get_transient( self::VERIFIED_TRANSIENT ) ) {
			return true;
		}

		if ( ! empty( self::missing_tables() ) ) {
			return false;
		}

		set_transient( self::VERIFIED_TRANSIENT, 1, DAY_IN_SECONDS );

		return true;
	}

	/**
	 * Re-run install when the schema version bumps, unless a recent attempt failed.
	 */
	public static function maybe_upgrade(): void {
		if ( get_option( 'dragoncompliance_db_version' ) === DRAGONCOMPLIANCE_DB_VERSION && self::schema_confirmed() ) {
			return;
		}
		// A failed install is retried on a timer, not on every request.
		if ( false !== get_transient( self::RETRY_TRANSIENT ) ) {
			return;
		}
		self::install();
	}
}
