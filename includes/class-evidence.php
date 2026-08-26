<?php
/**
 * Evidence log: append-only compliance trail.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Writes and reads the evidence table. Rows are never updated by the free
 * plugin; the Pro sealer fills the hash-chain columns afterwards.
 */
class Evidence {

	/**
	 * Fully-prefixed table name.
	 */
	private function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'dragoncompliance_evidence';
	}

	/**
	 * Append an event.
	 *
	 * @param string $event_type Event slug (scan_complete, vuln_detected, …).
	 * @param array  $payload    Event data, JSON-encoded for storage.
	 * @return int Row id, 0 on failure.
	 */
	public function record( string $event_type, array $payload = array() ): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$this->table(),
			array(
				'event_type' => sanitize_key( $event_type ),
				'payload'    => (string) wp_json_encode( $payload ),
				'created_at' => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%s' )
		);
		$id = (int) $wpdb->insert_id;
		if ( $id > 0 ) {
			/**
			 * Fires after an evidence row is written.
			 *
			 * @param int    $id         Row id.
			 * @param string $event_type Event type.
			 * @param array  $payload    Event payload.
			 */
			do_action( 'dragoncompliance_evidence_recorded', $id, $event_type, $payload );
		}
		return $id;
	}

	/**
	 * Query events, newest first.
	 *
	 * @param array $args ['event_type' => string|null, 'limit' => int, 'offset' => int].
	 * @return array<int,array<string,mixed>> Rows with decoded payloads.
	 */
	public function query( array $args = array() ): array {
		global $wpdb;
		$limit  = isset( $args['limit'] ) ? max( 1, (int) $args['limit'] ) : 100;
		$offset = isset( $args['offset'] ) ? max( 0, (int) $args['offset'] ) : 0;

		if ( ! empty( $args['event_type'] ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT * FROM %i WHERE event_type = %s ORDER BY id DESC LIMIT %d OFFSET %d',
					$this->table(),
					sanitize_key( (string) $args['event_type'] ),
					$limit,
					$offset
				),
				ARRAY_A
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$rows = $wpdb->get_results(
				$wpdb->prepare( 'SELECT * FROM %i ORDER BY id DESC LIMIT %d OFFSET %d', $this->table(), $limit, $offset ),
				ARRAY_A
			);
		}

		return array_map(
			static function ( array $row ): array {
				$row['id']      = (int) $row['id'];
				$decoded        = json_decode( (string) $row['payload'], true );
				$row['payload'] = is_array( $decoded ) ? $decoded : array();
				return $row;
			},
			(array) $rows
		);
	}

	/**
	 * Total row count.
	 */
	public function count(): int {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $this->table() ) );
	}
}
