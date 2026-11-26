<?php
/**
 * Scan pipeline: feed, match, persist, evidence, alerts, hooks.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Orchestrates a scan. All collaborators are constructor-injected.
 */
class Scanner {

	/**
	 * Inventory.
	 *
	 * @var Inventory
	 */
	private Inventory $inventory;

	/**
	 * Feed.
	 *
	 * @var Feed
	 */
	private Feed $feed;

	/**
	 * Findings store.
	 *
	 * @var Findings_Store
	 */
	private Findings_Store $findings;

	/**
	 * Evidence log.
	 *
	 * @var Evidence
	 */
	private Evidence $evidence;

	/**
	 * Alerts.
	 *
	 * @var Alerts
	 */
	private Alerts $alerts;

	/**
	 * Constructor.
	 *
	 * @param Inventory      $inventory Inventory.
	 * @param Feed           $feed      Feed.
	 * @param Findings_Store $findings  Findings store.
	 * @param Evidence       $evidence  Evidence log.
	 * @param Alerts         $alerts    Alerts.
	 */
	public function __construct( Inventory $inventory, Feed $feed, Findings_Store $findings, Evidence $evidence, Alerts $alerts ) {
		$this->inventory = $inventory;
		$this->feed      = $feed;
		$this->findings  = $findings;
		$this->evidence  = $evidence;
		$this->alerts    = $alerts;
	}

	/**
	 * Bring each still-open finding's recorded version up to the one now
	 * installed.
	 *
	 * A component updated to a release that is still vulnerable keeps its
	 * finding open, and without this the finding goes on naming the version
	 * it was first detected on. One evidence row per actual change; a scan
	 * that finds the same version writes nothing.
	 *
	 * @param array $open_rows Open findings as read before this scan.
	 * @param array $matched   Matched records from Matcher::matches().
	 */
	private function record_version_changes( array $open_rows, array $matched ): void {
		$installed = array();
		foreach ( $matched as $record ) {
			// Sanitised as insert_new() stores it, so an unchanged version compares equal.
			$installed[ $record['vuln_id'] . '|' . $record['slug'] ] = sanitize_text_field( (string) ( $record['installed_version'] ?? '' ) );
		}

		foreach ( $open_rows as $row ) {
			$key = (string) $row['vuln_id'] . '|' . (string) $row['component_slug'];
			if ( ! isset( $installed[ $key ] ) || '' === $installed[ $key ] ) {
				continue;
			}

			$from = (string) ( $row['component_version'] ?? '' );
			$to   = $installed[ $key ];
			if ( $from === $to || ! $this->findings->update_version( (int) $row['id'], $from, $to ) ) {
				continue;
			}

			$this->evidence->record(
				'finding_version_changed',
				array(
					'finding_id' => (int) $row['id'],
					'vuln_id'    => (string) $row['vuln_id'],
					'slug'       => (string) $row['component_slug'],
					'from'       => $from,
					'to'         => $to,
				)
			);
		}
	}

	/**
	 * Open findings minus those on a component the scan could not check.
	 *
	 * @param array $open_rows Open findings.
	 * @param array $unchecked "type|slug" => reason.
	 * @return array
	 */
	public static function without_unchecked( array $open_rows, array $unchecked ): array {
		if ( array() === $unchecked ) {
			return $open_rows;
		}
		return array_values(
			array_filter(
				$open_rows,
				static function ( $row ) use ( $unchecked ): bool {
					$key = (string) ( $row['component_type'] ?? '' ) . '|' . (string) ( $row['component_slug'] ?? '' );
					return ! isset( $unchecked[ $key ] );
				}
			)
		);
	}

	/**
	 * Evidence payload for components a scan could not check: how many, and
	 * the first 50 as "type:slug" with the reason.
	 *
	 * @param array $unchecked "type|slug" => reason.
	 * @return array
	 */
	public static function unchecked_evidence( array $unchecked ): array {
		$components = array();
		foreach ( array_slice( $unchecked, 0, 50, true ) as $key => $reason ) {
			$components[] = str_replace( '|', ':', (string) $key ) . ' (' . (string) $reason . ')';
		}
		return array(
			'count'      => count( $unchecked ),
			'components' => $components,
		);
	}

	/**
	 * Close the findings the previous source reported, without calling them
	 * fixed: the new source names vulnerabilities by its own ids, so they
	 * would otherwise all look resolved and come back as new.
	 *
	 * Findings on a component the new source could not check stay as they
	 * are, and the change stays pending until a later scan checks it.
	 *
	 * @param array $change    Pending change (Feed::pending_source_change()).
	 * @param array $unchecked "type|slug" => reason.
	 * @return array<string,string> "type|slug|CVE" => status before closing
	 *                              ('ignored' only when every row with that key was ignored).
	 */
	private function apply_source_change( array $change, array $unchecked ): array {
		$closable = array();
		$waiting  = 0;
		foreach ( $this->findings->detected_before( $change['at'] ) as $row ) {
			$key = (string) ( $row['component_type'] ?? '' ) . '|' . (string) ( $row['component_slug'] ?? '' );
			if ( isset( $unchecked[ $key ] ) ) {
				++$waiting;
				continue;
			}
			$closable[ (int) $row['id'] ] = $row;
		}

		$closed = array() === $closable ? array() : $this->findings->close_source_changed( array_keys( $closable ) );

		$carry = array();
		foreach ( $closed as $id ) {
			$row    = $closable[ $id ];
			$status = (string) ( $row['status'] ?? 'open' );
			$this->evidence->record(
				'finding_source_changed',
				array(
					'finding_id' => $id,
					'vuln_id'    => (string) ( $row['vuln_id'] ?? '' ),
					'slug'       => (string) ( $row['component_slug'] ?? '' ),
					'cve'        => (string) ( $row['cve'] ?? '' ),
					'status'     => $status,
					'reason'     => 'source_changed',
					'from'       => $change['from'],
					'to'         => $change['to'],
				)
			);

			$cve = (string) ( $row['cve'] ?? '' );
			if ( '' === $cve ) {
				continue;
			}
			$key           = (string) ( $row['component_type'] ?? '' ) . '|' . (string) ( $row['component_slug'] ?? '' ) . '|' . $cve;
			$carry[ $key ] = ( 'ignored' === $status && 'open' !== ( $carry[ $key ] ?? 'ignored' ) ) ? 'ignored' : 'open';
		}

		if ( 0 === $waiting && count( $closed ) === count( $closable ) ) {
			Feed::clear_source_change();
		}
		return $carry;
	}

	/**
	 * Run a full scan.
	 *
	 * @return array Summary.
	 */
	public function run(): array {
		// The first source lookup after an upgrade notes the implicit change.
		$this->feed->provider();

		$components = $this->inventory->components();
		$slug_map   = Inventory::slug_map( $components );

		// A change made by an upgrade has no settings save to record it.
		$change = Feed::pending_source_change();
		if ( null !== $change && ! $change['logged'] ) {
			$this->evidence->record(
				'feed_source_changed',
				array(
					'from'   => $change['from'],
					'to'     => $change['to'],
					'reason' => $change['reason'],
				)
			);
			Feed::source_change_logged();
		}

		$feed_error = null;
		$refreshed  = $this->feed->refresh( $slug_map );
		if ( is_wp_error( $refreshed ) ) {
			$feed_error = $refreshed->get_error_code();
			// Stale index continues to serve; the failure itself is
			// compliance evidence of active monitoring.
			$this->evidence->record(
				'feed_fetch_failed',
				array(
					'code'    => $refreshed->get_error_code(),
					'message' => $refreshed->get_error_message(),
				)
			);
		}

		$unchecked = $this->feed->unchecked();
		if ( array() !== $unchecked ) {
			$this->evidence->record( 'vuln_check_incomplete', self::unchecked_evidence( $unchecked ) );
		}

		$index    = $this->feed->index();
		$matched  = Matcher::matches( $index, $slug_map );
		$has_data = $this->feed->has_data();

		$carry = null !== $change && $has_data ? $this->apply_source_change( $change, $unchecked ) : array();

		// A scan may only resolve findings when it actually has vulnerability
		// data to compare against. Without any (never fetched, no token,
		// option wiped), an empty match set would otherwise mark every open
		// finding resolved: a false all-clear plus bogus resolution evidence,
		// the worst outcome for a compliance tool. A stale index (e.g. after a
		// fetch error) is still real data, so it processes fully. Findings on a
		// component this scan could not check are left exactly as they are.
		$open_rows = $has_data ? self::without_unchecked( $this->findings->open(), $unchecked ) : array();
		$diff      = $has_data
			? Matcher::diff( $open_rows, $matched )
			: array(
				'new'          => array(),
				'resolved_ids' => array(),
			);

		$this->record_version_changes( $open_rows, $matched );

		$new_findings = array();
		$carried      = 0;
		foreach ( $diff['new'] as $record ) {
			// Only open rows are diffed, so a vulnerability seen before arrives
			// here too: upsert() reopens a resolved row and leaves an ignored
			// one alone rather than colliding with the table's unique key.
			$upsert = $this->findings->upsert( $record );
			$id     = (int) $upsert['id'];
			if ( $id > 0 ) {
				// The same issue the previous source reported (same component
				// and CVE), or a row of a source back in use: already known, so
				// it keeps an ignored status and sends no alert.
				$carry_key = (string) ( $record['type'] ?? '' ) . '|' . (string) ( $record['slug'] ?? '' ) . '|' . (string) ( $record['cve'] ?? '' );
				$known     = 'restored' === $upsert['action'] || ( '' !== (string) ( $record['cve'] ?? '' ) && isset( $carry[ $carry_key ] ) );
				$status    = 'open';
				if ( 'ignored' === ( $carry[ $carry_key ] ?? '' ) && $this->findings->set_ignored( $id, true ) ) {
					$status = 'ignored';
				}

				$reopened             = 'reopened' === $upsert['action'];
				$record['finding_id'] = $id;
				$record['reopened']   = $reopened;
				$payload              = array(
					'finding_id' => $id,
					'vuln_id'    => (string) ( $record['vuln_id'] ?? '' ),
					'slug'       => (string) ( $record['slug'] ?? '' ),
					'severity'   => (string) ( $record['severity'] ?? '' ),
					'cve'        => (string) ( $record['cve'] ?? '' ),
				);
				if ( $known ) {
					$payload['source_changed'] = true;
					$payload['status']         = $status;
					$this->evidence->record( 'vuln_detected', $payload );
					++$carried;
					continue;
				}

				$new_findings[] = $record;
				$this->evidence->record( $reopened ? 'vuln_reopened' : 'vuln_detected', $payload );
				/**
				 * Fires when a new vulnerability is detected, or a resolved one
				 * comes back (the record's 'reopened' key is then true).
				 *
				 * @param array $record Matched record incl. finding_id and reopened.
				 */
				do_action( 'dragoncompliance_vuln_detected', $record );
			}
		}

		// resolve() reports the ids it actually transitioned, which can be fewer
		// than were put forward: a write that did not land, or a row ignored
		// between the read and the write. Evidence and hooks follow the rows that
		// really changed, and the next scan retries the rest.
		$resolved_ids = array();
		if ( array() !== $diff['resolved_ids'] ) {
			$resolved_ids = $this->findings->resolve( $diff['resolved_ids'] );
			foreach ( $resolved_ids as $resolved_id ) {
				$this->evidence->record( 'vuln_resolved', array( 'finding_id' => (int) $resolved_id ) );
				/**
				 * Fires when a previously-open vulnerability no longer matches.
				 *
				 * @param int $resolved_id Finding id.
				 */
				do_action( 'dragoncompliance_vuln_resolved', (int) $resolved_id );
			}
		}

		// Critical findings, and findings whose severity was not published.
		$alertable = array_values( array_filter( $new_findings, array( Alerts::class, 'alertable' ) ) );
		if ( array() !== $alertable ) {
			$failed = $this->alerts->alert( $alertable );
			if ( array() !== $failed ) {
				$this->evidence->record(
					'alert_not_delivered',
					array(
						'recipients' => $failed,
						'findings'   => count( $alertable ),
					)
				);
			}
		}

		$summary = array(
			'new'          => count( $new_findings ),
			'carried_over' => $carried,
			'resolved'     => count( $resolved_ids ),
			'open'         => count( $matched ),
			'unassessed'   => Matcher::unassessed( $components ),
			'not_checked'  => array_keys( $unchecked ),
			'feed_age'     => $this->feed->age(),
			'feed_error'   => $feed_error,
			'components'   => count( $components ),
		);

		update_option( 'dragoncompliance_last_scan', time(), false );
		$this->evidence->record( 'scan_complete', $summary );
		/**
		 * Fires when a scan finishes.
		 *
		 * @param array $summary Scan summary.
		 */
		do_action( 'dragoncompliance_scan_complete', $summary );

		return $summary;
	}
}
