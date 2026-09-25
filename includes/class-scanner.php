<?php
/**
 * Scan pipeline: feed → match → persist → evidence → alerts → hooks.
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
	 * Run a full scan.
	 *
	 * @return array Summary.
	 */
	public function run(): array {
		$components = $this->inventory->components();
		$slug_map   = Inventory::slug_map( $components );

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

		$index   = $this->feed->index();
		$matched = Matcher::matches( $index, $slug_map );

		// A scan may only resolve findings when it actually has vulnerability
		// data to compare against. With an empty index (never fetched, no token,
		// option wiped), an empty match set would otherwise mark every open
		// finding resolved — a false all-clear plus bogus resolution evidence,
		// the worst outcome for a compliance tool. A non-empty but stale index
		// (e.g. after a fetch error) is still real data, so it processes fully.
		$open_rows = array() !== $index ? $this->findings->open() : array();
		$diff      = array() !== $index
			? Matcher::diff( $open_rows, $matched )
			: array(
				'new'          => array(),
				'resolved_ids' => array(),
			);

		$this->record_version_changes( $open_rows, $matched );

		$new_findings = array();
		foreach ( $diff['new'] as $record ) {
			// Only open rows are diffed, so a vulnerability seen before arrives
			// here too: upsert() reopens a resolved row and leaves an ignored
			// one alone rather than colliding with the table's unique key.
			$upsert = $this->findings->upsert( $record );
			$id     = (int) $upsert['id'];
			if ( $id > 0 ) {
				$reopened             = 'reopened' === $upsert['action'];
				$record['finding_id'] = $id;
				$record['reopened']   = $reopened;
				$new_findings[]       = $record;
				$this->evidence->record(
					$reopened ? 'vuln_reopened' : 'vuln_detected',
					array(
						'finding_id' => $id,
						'vuln_id'    => (string) ( $record['vuln_id'] ?? '' ),
						'slug'       => (string) ( $record['slug'] ?? '' ),
						'severity'   => (string) ( $record['severity'] ?? '' ),
						'cve'        => (string) ( $record['cve'] ?? '' ),
					)
				);
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

		$criticals = array_values(
			array_filter(
				$new_findings,
				static function ( array $finding ): bool {
					return 'critical' === ( $finding['severity'] ?? '' );
				}
			)
		);
		if ( array() !== $criticals ) {
			$this->alerts->critical( $criticals );
		}

		$summary = array(
			'new'        => count( $new_findings ),
			'resolved'   => count( $resolved_ids ),
			'open'       => count( $matched ),
			'unassessed' => Matcher::unassessed( $components ),
			'feed_age'   => $this->feed->age(),
			'feed_error' => $feed_error,
			'components' => count( $components ),
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
