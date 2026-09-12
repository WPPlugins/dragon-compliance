<?php
/**
 * Findings table access.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * CRUD for the findings table. All queries prepared.
 */
class Findings_Store {

	/**
	 * Fully-prefixed table name.
	 */
	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'dragoncompliance_findings';
	}

	/**
	 * Open findings.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function open(): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare( 'SELECT * FROM %i WHERE status = %s', $this->table(), 'open' ),
			ARRAY_A
		);
		return array_map( array( $this, 'cast' ), (array) $rows );
	}

	/**
	 * All findings, optionally filtered.
	 *
	 * @param array $args ['status' => string|null, 'limit' => int, 'offset' => int].
	 * @return array<int,array<string,mixed>>
	 */
	public function all( array $args = array() ): array {
		global $wpdb;
		$limit  = isset( $args['limit'] ) ? max( 1, (int) $args['limit'] ) : 200;
		$offset = isset( $args['offset'] ) ? max( 0, (int) $args['offset'] ) : 0;

		if ( ! empty( $args['status'] ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM %i WHERE status = %s ORDER BY FIELD(severity,'critical','high','medium','low','unknown'), cvss DESC, detected_at DESC LIMIT %d OFFSET %d",
					$this->table(),
					sanitize_key( (string) $args['status'] ),
					$limit,
					$offset
				),
				ARRAY_A
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM %i ORDER BY FIELD(status,'open','ignored','resolved'), FIELD(severity,'critical','high','medium','low','unknown'), cvss DESC, detected_at DESC LIMIT %d OFFSET %d",
					$this->table(),
					$limit,
					$offset
				),
				ARRAY_A
			);
		}
		return array_map( array( $this, 'cast' ), (array) $rows );
	}

	/**
	 * Count findings by status.
	 *
	 * @return array<string,int> status => count.
	 */
	public function counts(): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows   = $wpdb->get_results(
			$wpdb->prepare( 'SELECT status, COUNT(*) AS n FROM %i GROUP BY status', $this->table() ),
			ARRAY_A
		);
		$counts = array(
			'open'     => 0,
			'resolved' => 0,
			'ignored'  => 0,
		);
		foreach ( (array) $rows as $row ) {
			$counts[ (string) $row['status'] ] = (int) $row['n'];
		}
		return $counts;
	}

	/**
	 * Open findings grouped by severity.
	 *
	 * @return array<string,int>
	 */
	public function open_by_severity(): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows   = $wpdb->get_results(
			$wpdb->prepare( 'SELECT severity, COUNT(*) AS n FROM %i WHERE status = %s GROUP BY severity', $this->table(), 'open' ),
			ARRAY_A
		);
		$result = array();
		foreach ( (array) $rows as $row ) {
			$result[ (string) $row['severity'] ] = (int) $row['n'];
		}
		return $result;
	}

	/**
	 * Insert a new open finding from a matched feed record.
	 *
	 * @param array $record Matched record (Matcher::matches shape).
	 * @return int Insert id, 0 on failure.
	 */
	public function insert_new( array $record ): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$this->table(),
			array(
				'component_type'    => sanitize_key( (string) ( $record['type'] ?? 'plugin' ) ),
				'component_slug'    => sanitize_text_field( (string) ( $record['slug'] ?? '' ) ),
				'component_version' => sanitize_text_field( (string) ( $record['installed_version'] ?? '' ) ),
				'vuln_id'           => sanitize_text_field( (string) ( $record['vuln_id'] ?? '' ) ),
				'cve'               => sanitize_text_field( (string) ( $record['cve'] ?? '' ) ),
				'title'             => sanitize_text_field( (string) ( $record['title'] ?? '' ) ),
				'severity'          => sanitize_key( (string) ( $record['severity'] ?? 'unknown' ) ),
				'cvss'              => (float) ( $record['cvss'] ?? 0 ),
				'affected_range'    => sanitize_text_field( self::range_label( (array) ( $record['affected'] ?? array() ) ) ),
				'status'            => 'open',
				'detected_at'       => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%f', '%s', '%s', '%s' )
		);
		return (int) $wpdb->insert_id;
	}

	/**
	 * Mark findings resolved.
	 *
	 * @param array $ids Finding ids.
	 * @return int[] The ids this call actually transitioned to resolved.
	 */
	public function resolve( array $ids ): array {
		global $wpdb;
		$ids = array_filter( array_map( 'absint', $ids ) );
		if ( array() === $ids ) {
			return array();
		}
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$resolved_at  = current_time( 'mysql', true );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Placeholder list is built from counted %d entries; values are absint()ed.
		$changed = (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = 'resolved', resolved_at = %s WHERE id IN ({$placeholders}) AND status = 'open'",
				array_merge( array( $this->table(), $resolved_at ), $ids )
			)
		);

		if ( $changed < 1 ) {
			return array();
		}

		/*
		 * The UPDATE only touches rows still open, so asking for two ids can
		 * transition one: the other may have been ignored or resolved between
		 * the read and the write. The row count does not say which, so the ids
		 * carrying the timestamp just written are read back. A caller that
		 * recorded evidence or fired hooks for every requested id would be
		 * claiming resolutions that never happened.
		 */
		$transitioned = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT id FROM %i WHERE id IN ({$placeholders}) AND status = 'resolved' AND resolved_at = %s",
				array_merge( array( $this->table() ), $ids, array( $resolved_at ) )
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber

		return array_values( array_map( 'absint', (array) $transitioned ) );
	}

	/**
	 * Toggle ignored status.
	 *
	 * @param int  $id      Finding id.
	 * @param bool $ignored True to ignore, false to reopen.
	 * @return bool Whether the row changed status (false on error or no-op).
	 */
	public function set_ignored( int $id, bool $ignored ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return 0 < (int) $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET status = %s WHERE id = %d AND status = %s',
				$this->table(),
				$ignored ? 'ignored' : 'open',
				$id,
				$ignored ? 'open' : 'ignored'
			)
		);
	}

	/**
	 * Resolved findings (for Pro time-to-patch).
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function resolved(): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare( 'SELECT * FROM %i WHERE status = %s ORDER BY resolved_at DESC', $this->table(), 'resolved' ),
			ARRAY_A
		);
		return array_map( array( $this, 'cast' ), (array) $rows );
	}

	/**
	 * Human label for the first affected range.
	 *
	 * @param array $affected Affected ranges.
	 */
	private static function range_label( array $affected ): string {
		if ( array() === $affected || ! is_array( $affected[0] ?? null ) ) {
			return '';
		}
		$first = $affected[0];
		return sprintf(
			'%s%s - %s%s',
			! empty( $first['from_inclusive'] ) ? '[' : '(',
			(string) ( $first['from'] ?? '*' ),
			(string) ( $first['to'] ?? '*' ),
			! empty( $first['to_inclusive'] ) ? ']' : ')'
		);
	}

	/**
	 * Cast a row's numeric fields.
	 *
	 * @param array $row Raw row.
	 */
	private function cast( array $row ): array {
		$row['id']   = (int) $row['id'];
		$row['cvss'] = (float) $row['cvss'];
		return $row;
	}
}
