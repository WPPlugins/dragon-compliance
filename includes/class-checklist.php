<?php
/**
 * CRA readiness checklist.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Auto-detected checks plus manual attestations, with a completion score.
 */
class Checklist {

	/**
	 * Findings store (for the no-open-criticals check).
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
	 * Auto-check overrides for tests: id => callable(): bool.
	 *
	 * @var array<string,callable>
	 */
	private array $overrides;

	/**
	 * Constructor.
	 *
	 * @param Findings_Store $findings  Findings store.
	 * @param Evidence       $evidence  Evidence log.
	 * @param array          $overrides Auto-check overrides (tests).
	 */
	public function __construct( Findings_Store $findings, Evidence $evidence, array $overrides = array() ) {
		$this->findings  = $findings;
		$this->evidence  = $evidence;
		$this->overrides = $overrides;
	}

	/**
	 * Evaluated checklist items.
	 *
	 * Each: id, label, description, type (auto|manual), category,
	 * state (pass|fail|attested|unattested), detail.
	 *
	 * @return array<int,array<string,string>>
	 */
	public function items(): array {
		$attestations = (array) get_option( 'dragoncompliance_attestations', array() );
		$items        = array();

		foreach ( $this->auto_definitions() as $id => $def ) {
			$check   = $this->overrides[ $id ] ?? $def['check'];
			$passed  = (bool) call_user_func( $check );
			$items[] = array(
				'id'          => $id,
				'label'       => $def['label'],
				'description' => $def['description'],
				'type'        => 'auto',
				'category'    => $def['category'],
				'state'       => $passed ? 'pass' : 'fail',
				'detail'      => $passed ? $def['pass_detail'] : $def['fail_detail'],
			);
		}

		foreach ( $this->manual_definitions() as $id => $def ) {
			$entry    = $attestations[ $id ] ?? array();
			$attested = ! empty( $entry['attested'] );
			$items[]  = array(
				'id'          => $id,
				'label'       => $def['label'],
				'description' => $def['description'],
				'type'        => 'manual',
				'category'    => $def['category'],
				'state'       => $attested ? 'attested' : 'unattested',
				'detail'      => sanitize_text_field( (string) ( $entry['note'] ?? '' ) ),
			);
		}

		/**
		 * Filters the evaluated checklist items (Pro adds its own).
		 *
		 * @param array $items Checklist items.
		 */
		return (array) apply_filters( 'dragoncompliance_checklist_items', $items );
	}

	/**
	 * Evaluate, fire the seam hook, and return items + score.
	 *
	 * @return array{items:array,score:array}
	 */
	public function evaluate(): array {
		$items = $this->items();
		$score = self::score_of( $items );
		/**
		 * Fires after the checklist is evaluated.
		 *
		 * @param array $items Checklist items.
		 * @param array $score Score summary.
		 */
		do_action( 'dragoncompliance_checklist_evaluated', $items, $score );
		return array(
			'items' => $items,
			'score' => $score,
		);
	}

	/**
	 * Score for a set of items.
	 *
	 * @param array $items Evaluated items.
	 * @return array{passed:int,total:int,percent:int}
	 */
	public static function score_of( array $items ): array {
		$passed = 0;
		foreach ( $items as $item ) {
			if ( in_array( $item['state'] ?? '', array( 'pass', 'attested' ), true ) ) {
				++$passed;
			}
		}
		$total = count( $items );
		return array(
			'passed'  => $passed,
			'total'   => $total,
			'percent' => $total > 0 ? (int) round( 100 * $passed / $total ) : 0,
		);
	}

	/**
	 * Record a manual attestation.
	 *
	 * @param string $id    Item id.
	 * @param bool   $value Attested or not.
	 * @param string $note  Optional note.
	 * @return bool Whether the id names a manual item.
	 */
	public function attest( string $id, bool $value, string $note = '' ): bool {
		$id = sanitize_key( $id );
		if ( ! array_key_exists( $id, $this->manual_definitions() ) ) {
			return false;
		}
		$attestations        = (array) get_option( 'dragoncompliance_attestations', array() );
		$attestations[ $id ] = array(
			'attested' => $value,
			'note'     => sanitize_text_field( $note ),
			'time'     => time(),
		);
		update_option( 'dragoncompliance_attestations', $attestations );
		$this->evidence->record(
			'attestation_changed',
			array(
				'item'     => $id,
				'attested' => $value,
			)
		);
		return true;
	}

	/**
	 * Auto check definitions.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	private function auto_definitions(): array {
		$findings = $this->findings;
		return array(
			'https'               => array(
				'label'       => __( 'Site served over HTTPS', 'dragon-compliance' ),
				'description' => __( 'Transport encryption is a baseline CRA expectation.', 'dragon-compliance' ),
				'category'    => 'hardening',
				'pass_detail' => __( 'The site URL uses HTTPS.', 'dragon-compliance' ),
				'fail_detail' => __( 'The site URL does not use HTTPS.', 'dragon-compliance' ),
				'check'       => static function (): bool {
					return 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME );
				},
			),
			'core_auto_updates'   => array(
				'label'       => __( 'WordPress core auto-updates enabled', 'dragon-compliance' ),
				'description' => __( 'Security updates must be applied without delay.', 'dragon-compliance' ),
				'category'    => 'update-management',
				'pass_detail' => __( 'Core automatic updates are active.', 'dragon-compliance' ),
				'fail_detail' => __( 'Core automatic updates are disabled by a constant.', 'dragon-compliance' ),
				'check'       => static function (): bool {
					if ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) {
						return false;
					}
					return ! ( defined( 'WP_AUTO_UPDATE_CORE' ) && false === WP_AUTO_UPDATE_CORE );
				},
			),
			'plugin_auto_updates' => array(
				'label'       => __( 'All active plugins auto-update', 'dragon-compliance' ),
				'description' => __( 'Unpatched plugins are the leading WordPress attack vector.', 'dragon-compliance' ),
				'category'    => 'update-management',
				'pass_detail' => __( 'Every active plugin has auto-updates enabled.', 'dragon-compliance' ),
				'fail_detail' => __( 'Some active plugins do not auto-update.', 'dragon-compliance' ),
				'check'       => static function (): bool {
					$active       = (array) get_option( 'active_plugins', array() );
					$auto         = (array) get_option( 'auto_update_plugins', array() );
					$not_covered  = array_diff( $active, $auto );
					return array() === $not_covered;
				},
			),
			'debug_off'           => array(
				'label'       => __( 'Debug mode disabled', 'dragon-compliance' ),
				'description' => __( 'WP_DEBUG leaks paths and internals in production.', 'dragon-compliance' ),
				'category'    => 'hardening',
				'pass_detail' => __( 'WP_DEBUG is off.', 'dragon-compliance' ),
				'fail_detail' => __( 'WP_DEBUG is enabled.', 'dragon-compliance' ),
				'check'       => static function (): bool {
					return ! ( defined( 'WP_DEBUG' ) && WP_DEBUG );
				},
			),
			'file_edit_disabled'  => array(
				'label'       => __( 'Dashboard file editing disabled', 'dragon-compliance' ),
				'description' => __( 'DISALLOW_FILE_EDIT stops an admin compromise becoming code execution.', 'dragon-compliance' ),
				'category'    => 'hardening',
				'pass_detail' => __( 'DISALLOW_FILE_EDIT is set.', 'dragon-compliance' ),
				'fail_detail' => __( 'The plugin/theme file editor is available in wp-admin.', 'dragon-compliance' ),
				'check'       => static function (): bool {
					return defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
				},
			),
			'no_stale_admins'     => array(
				'label'       => __( 'No default "admin" account', 'dragon-compliance' ),
				'description' => __( 'The default admin login is the first username brute-force lists try.', 'dragon-compliance' ),
				'category'    => 'hardening',
				'pass_detail' => __( 'No user is named "admin".', 'dragon-compliance' ),
				'fail_detail' => __( 'A user with the login "admin" exists.', 'dragon-compliance' ),
				'check'       => static function (): bool {
					return false === get_user_by( 'login', 'admin' );
				},
			),
			'two_factor_present'  => array(
				'label'       => __( 'Two-factor authentication available', 'dragon-compliance' ),
				'description' => __( 'Strong authentication is expected under CRA and NIS2.', 'dragon-compliance' ),
				'category'    => 'hardening',
				'pass_detail' => __( 'A two-factor authentication plugin is active.', 'dragon-compliance' ),
				'fail_detail' => __( 'No known two-factor authentication plugin detected.', 'dragon-compliance' ),
				'check'       => static function (): bool {
					if ( class_exists( '\DragonLoginSecurity\Plugin' ) ) {
						return true;
					}
					$active = (array) get_option( 'active_plugins', array() );
					foreach ( array( 'two-factor/', 'wp-2fa/', 'wordfence-login-security/', 'wordfence/', 'miniorange-2-factor-authentication/' ) as $known ) {
						foreach ( $active as $file ) {
							if ( 0 === strpos( (string) $file, $known ) ) {
								return true;
							}
						}
					}
					return false;
				},
			),
			'no_open_criticals'   => array(
				'label'       => __( 'No open critical vulnerabilities', 'dragon-compliance' ),
				'description' => __( 'Known-exploitable components must be patched or removed.', 'dragon-compliance' ),
				'category'    => 'update-management',
				'pass_detail' => __( 'No open critical findings.', 'dragon-compliance' ),
				'fail_detail' => __( 'Critical findings are open — review the Findings tab.', 'dragon-compliance' ),
				'check'       => static function () use ( $findings ): bool {
					$by_severity = $findings->open_by_severity();
					return empty( $by_severity['critical'] );
				},
			),
		);
	}

	/**
	 * Manual attestation definitions.
	 *
	 * @return array<string,array<string,string>>
	 */
	private function manual_definitions(): array {
		return array(
			'update_policy'    => array(
				'label'       => __( 'Documented update policy', 'dragon-compliance' ),
				'description' => __( 'A written policy stating how quickly security updates are applied.', 'dragon-compliance' ),
				'category'    => 'process',
			),
			'security_contact' => array(
				'label'       => __( 'Published security contact', 'dragon-compliance' ),
				'description' => __( 'A route for reporting vulnerabilities in your site or product.', 'dragon-compliance' ),
				'category'    => 'process',
			),
			'backup_policy'    => array(
				'label'       => __( 'Working backup and restore process', 'dragon-compliance' ),
				'description' => __( 'Backups exist, run on a schedule, and a restore has been tested.', 'dragon-compliance' ),
				'category'    => 'process',
			),
			'staging_process'  => array(
				'label'       => __( 'Changes tested before production', 'dragon-compliance' ),
				'description' => __( 'Updates and changes are verified on staging before going live.', 'dragon-compliance' ),
				'category'    => 'process',
			),
		);
	}
}
