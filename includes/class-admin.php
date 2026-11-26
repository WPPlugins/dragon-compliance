<?php
/**
 * Admin UI: Tools > Compliance.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Renders the admin page and handles its actions.
 */
class Admin {

	/**
	 * Transient prefix for a refused settings save, completed with the user id.
	 */
	private const SETTINGS_ERROR = 'dragoncompliance_settings_error_';

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
	 * Feed.
	 *
	 * @var Feed
	 */
	private Feed $feed;

	/**
	 * Constructor.
	 *
	 * @param Findings_Store $findings Findings store.
	 * @param Evidence       $evidence Evidence log.
	 * @param Feed           $feed     Feed.
	 */
	public function __construct( Findings_Store $findings, Evidence $evidence, Feed $feed ) {
		$this->findings = $findings;
		$this->evidence = $evidence;
		$this->feed     = $feed;
	}

	/**
	 * Register hooks.
	 */
	public function init(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_post_dragoncompliance_export_sbom', array( $this, 'handle_export_sbom' ) );
		add_action( 'admin_post_dragoncompliance_save_settings', array( $this, 'handle_save_settings' ) );
		add_action( 'admin_post_dragoncompliance_save_attestations', array( $this, 'handle_save_attestations' ) );
		add_action( 'admin_post_dragoncompliance_finding_status', array( $this, 'handle_finding_status' ) );
		add_action( 'wp_ajax_dragoncompliance_scan_now', array( $this, 'handle_scan_now' ) );
	}

	/**
	 * Register the Tools submenu page.
	 */
	public function register_menu(): void {
		add_management_page(
			__( 'Dragon Compliance', 'dragon-compliance' ),
			__( 'Compliance', 'dragon-compliance' ),
			'manage_options',
			'dragon-compliance',
			array( $this, 'render_page' )
		);
	}

	/**
	 * Enqueue assets on our page only.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue( string $hook ): void {
		if ( 'tools_page_dragon-compliance' !== $hook ) {
			return;
		}
		wp_enqueue_style(
			'dragon-compliance-dragon-ui',
			DRAGONCOMPLIANCE_PLUGIN_URL . 'admin/css/dragon-ui.css',
			array(),
			DRAGONCOMPLIANCE_VERSION
		);

		wp_enqueue_style( 'dragon-compliance-admin', DRAGONCOMPLIANCE_PLUGIN_URL . 'admin/css/admin.css', array( 'dragon-compliance-dragon-ui' ), DRAGONCOMPLIANCE_VERSION );
		wp_enqueue_script( 'dragon-compliance-admin', DRAGONCOMPLIANCE_PLUGIN_URL . 'admin/js/admin.js', array( 'jquery' ), DRAGONCOMPLIANCE_VERSION, true );
		wp_localize_script(
			'dragon-compliance-admin',
			'dragoncomplianceAdmin',
			array(
				'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
				'nonce'    => wp_create_nonce( 'dragoncompliance_scan_now' ),
				'scanning' => __( 'Scanning…', 'dragon-compliance' ),
				'scanFail' => __( 'Scan failed. Check the evidence log.', 'dragon-compliance' ),
			)
		);
	}

	/**
	 * The tab list, filterable so an add-on can add tabs.
	 *
	 * @return array<string,string> slug => label.
	 */
	public function tabs(): array {
		$tabs = array(
			'dashboard' => __( 'Dashboard', 'dragon-compliance' ),
			'inventory' => __( 'Inventory & SBOM', 'dragon-compliance' ),
			'findings'  => __( 'Findings', 'dragon-compliance' ),
			'checklist' => __( 'Checklist', 'dragon-compliance' ),
			'evidence'  => __( 'Evidence', 'dragon-compliance' ),
			'settings'  => __( 'Settings', 'dragon-compliance' ),
		);
		/**
		 * Filters the admin tab list (an add-on can append tabs).
		 *
		 * @param array $tabs slug => label.
		 */
		return (array) apply_filters( 'dragoncompliance_admin_tab_list', $tabs );
	}

	/**
	 * Render the page shell and active tab.
	 */
	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'dragon-compliance' ) );
		}

		$tabs   = $this->tabs();
		$active = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'dashboard'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $tabs[ $active ] ) ) {
			$active = 'dashboard';
		}

		echo '<div class="wrap dragon-ui dragoncompliance-wrap">';
		echo '<h1 class="dragon-title"><span class="dragon-mark" aria-hidden="true"></span>' . esc_html__( 'Dragon Compliance', 'dragon-compliance' ) . '</h1>';

		echo '<nav class="nav-tab-wrapper">';
		foreach ( $tabs as $slug => $label ) {
			printf(
				'<a href="%s" class="nav-tab%s">%s</a>',
				esc_url( admin_url( 'tools.php?page=dragon-compliance&tab=' . $slug ) ),
				$active === $slug ? ' nav-tab-active' : '',
				esc_html( $label )
			);
		}
		echo '</nav>';

		$this->render_pro_notice();
		$this->render_notices();

		switch ( $active ) {
			case 'inventory':
				$this->render_inventory();
				break;
			case 'findings':
				$this->render_findings();
				break;
			case 'checklist':
				$this->render_checklist();
				break;
			case 'evidence':
				$this->render_evidence();
				break;
			case 'settings':
				$this->render_settings();
				break;
			case 'dashboard':
				$this->render_dashboard();
				break;
			default:
				/**
				 * Renders a tab added via the tab-list filter.
				 *
				 * @param string $active Active tab slug.
				 */
				do_action( 'dragoncompliance_admin_tabs', $active );
				break;
		}

		echo '</div>';
	}

	/**
	 * Ask to deactivate the Pro add-on while it is active.
	 */
	private function render_pro_notice(): void {
		if ( ! class_exists( '\DragonCompliancePro\Plugin' ) ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p>%s</p></div>',
			esc_html__( 'Dragon Compliance now monitors vulnerabilities without an account and can email several alert recipients. While the Dragon Compliance Pro add-on is active, the alert recipients saved here are not used. Deactivate the add-on to use the built-in alerts.', 'dragon-compliance' )
		);
	}

	/**
	 * One-shot admin notices from redirects.
	 */
	private function render_notices(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only notice flag.
		$notice = isset( $_GET['dragoncompliance_notice'] ) ? sanitize_key( wp_unslash( $_GET['dragoncompliance_notice'] ) ) : '';
		if ( '' === $notice ) {
			return;
		}
		if ( 'settings_refused' === $notice ) {
			$message = get_transient( self::SETTINGS_ERROR . get_current_user_id() );
			delete_transient( self::SETTINGS_ERROR . get_current_user_id() );
			if ( is_string( $message ) && '' !== $message ) {
				printf( '<div class="notice notice-error is-dismissible"><p>%s</p></div>', esc_html( $message ) );
			}
			return;
		}
		$messages = array(
			'settings_saved'     => __( 'Settings saved.', 'dragon-compliance' ),
			'attestations_saved' => __( 'Attestations saved.', 'dragon-compliance' ),
			'finding_updated'    => __( 'Finding updated.', 'dragon-compliance' ),
		);
		$errors   = array(
			'attestations_failed' => __( 'Attestations could not be saved: the database refused the write. Nothing was recorded in the evidence log. Please try again.', 'dragon-compliance' ),
			'finding_not_updated' => __( 'The finding was not updated. It may already have that status, or the database refused the write.', 'dragon-compliance' ),
			'settings_failed'     => __( 'Some settings could not be saved: the database refused the write. Please try again.', 'dragon-compliance' ),
		);
		if ( isset( $messages[ $notice ] ) ) {
			printf( '<div class="notice notice-success is-dismissible"><p>%s</p></div>', esc_html( $messages[ $notice ] ) );
		} elseif ( isset( $errors[ $notice ] ) ) {
			printf( '<div class="notice notice-error is-dismissible"><p>%s</p></div>', esc_html( $errors[ $notice ] ) );
		}
	}

	/**
	 * Stale-feed warning banner data, shared by tabs.
	 */
	private function feed_banner(): array {
		$age = $this->feed->age();
		return array(
			'age'       => $age,
			'stale'     => null !== $age && $age > 2 * DAY_IN_SECONDS,
			'has_token' => $this->feed->monitoring_ready(),
			// Configured but never successfully fetched: monitoring has no data yet.
			'no_data'   => null === $age,
			'error'     => $this->feed->last_error(),
			'provider'  => $this->feed->provider(),
			'unchecked' => self::unchecked_labels( $this->feed->unchecked() ),
		);
	}

	/**
	 * Readable names for components a scan could not check.
	 *
	 * @param array $unchecked "type|slug" => reason.
	 * @return string[] One "slug (type)" label each.
	 */
	public static function unchecked_labels( array $unchecked ): array {
		$labels = array();
		foreach ( array_keys( $unchecked ) as $key ) {
			$parts    = explode( '|', (string) $key, 2 );
			$labels[] = sprintf(
				/* translators: 1: component slug, 2: component type label. */
				__( '%1$s (%2$s)', 'dragon-compliance' ),
				$parts[1] ?? $parts[0],
				Labels::component_type( $parts[0] )
			);
		}
		return $labels;
	}

	/**
	 * Dashboard tab.
	 */
	private function render_dashboard(): void {
		$checklist = new Checklist( $this->findings, $this->evidence, array(), $this->feed );
		$result    = $checklist->evaluate();

		$dragoncompliance_view = array(
			'score'       => $result['score'],
			'by_severity' => $this->findings->open_by_severity(),
			'counts'      => $this->findings->counts(),
			'feed'        => $this->feed_banner(),
			'last_scan'   => (int) get_option( 'dragoncompliance_last_scan', 0 ),
		);
		require DRAGONCOMPLIANCE_PLUGIN_DIR . 'admin/views/dashboard.php';
	}

	/**
	 * Inventory tab.
	 */
	private function render_inventory(): void {
		$inventory             = new Inventory();
		$components            = $inventory->components();
		$dragoncompliance_view = array(
			'components'  => $components,
			'checks'      => self::check_states( $components, $this->feed ),
			'environment' => $inventory->environment(),
			'export_url'  => wp_nonce_url( admin_url( 'admin-post.php?action=dragoncompliance_export_sbom' ), 'dragoncompliance_export_sbom' ),
			/**
			 * Filters the available SBOM export formats (an add-on can add formats).
			 *
			 * @param array $formats format-slug => [label, url].
			 */
			'formats'     => (array) apply_filters( 'dragoncompliance_sbom_formats', array() ),
		);
		require DRAGONCOMPLIANCE_PLUGIN_DIR . 'admin/views/inventory.php';
	}

	/**
	 * Per-component state of the last vulnerability lookup, keyed by
	 * "type|slug" of each inventory row: 'checked' (looked up at the version
	 * now installed), 'not_listed' (checked at that version: its name cannot
	 * be a WordPress.org slug, so it is not in the database), 'not_checked'
	 * (the lookup failed), 'pending' (installed or updated since the last
	 * scan), or '' before any scan. Empty for the Wordfence feed, which covers
	 * every component at once.
	 *
	 * @param array $components Inventory components.
	 * @param Feed  $feed       Feed.
	 * @return array<string,string>
	 */
	public static function check_states( array $components, Feed $feed ): array {
		$states = array();
		if ( $feed->uses_wordfence() ) {
			return $states;
		}
		$scanned    = ! empty( Wpvulnerability::meta()['scanned_at'] );
		$checked    = Wpvulnerability::checked();
		$unchecked  = Wpvulnerability::unchecked();
		$not_listed = Wpvulnerability::not_listed();
		foreach ( $components as $component ) {
			$type    = (string) ( $component['type'] ?? '' );
			$slug    = (string) ( $component['slug'] ?? '' );
			$version = (string) ( $component['version'] ?? '' );

			// A single-file plugin with a known alias is looked up under the alias.
			$keys    = array( $type . '|' . $slug );
			$aliases = 'plugin' === $type ? Inventory::plugin_aliases( $slug ) : array();
			if ( array() !== $aliases ) {
				$keys = array();
				foreach ( $aliases as $alias ) {
					$keys[] = 'plugin|' . $alias;
				}
			}

			if ( ! $scanned ) {
				$state = '';
			} elseif ( isset( $not_listed[ $type . '|' . $slug ] ) && array() === $aliases ) {
				$state = $not_listed[ $type . '|' . $slug ] === $version ? 'not_listed' : 'pending';
			} else {
				$state = 'checked';
				foreach ( $keys as $key ) {
					if ( isset( $unchecked[ $key ] ) ) {
						$state = 'not_checked';
						break;
					}
					if ( ( $checked[ $key ] ?? null ) !== $version ) {
						$state = 'pending';
					}
				}
			}
			$states[ $type . '|' . $slug ] = $state;
		}
		return $states;
	}

	/**
	 * Findings tab.
	 */
	private function render_findings(): void {
		$dragoncompliance_view = array(
			'findings' => $this->findings->all(),
			'feed'     => $this->feed_banner(),
		);
		require DRAGONCOMPLIANCE_PLUGIN_DIR . 'admin/views/findings.php';
	}

	/**
	 * Checklist tab.
	 */
	private function render_checklist(): void {
		$checklist             = new Checklist( $this->findings, $this->evidence, array(), $this->feed );
		$dragoncompliance_view = array(
			'items' => $checklist->items(),
			'score' => Checklist::score_of( $checklist->items() ),
		);
		require DRAGONCOMPLIANCE_PLUGIN_DIR . 'admin/views/checklist.php';
	}

	/**
	 * Evidence tab.
	 */
	private function render_evidence(): void {
		$paged                 = isset( $_GET['paged'] ) ? max( 1, absint( wp_unslash( $_GET['paged'] ) ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$per_page              = 50;
		$dragoncompliance_view = array(
			'events'   => $this->evidence->query(
				array(
					'limit'  => $per_page,
					'offset' => ( $paged - 1 ) * $per_page,
				)
			),
			'total'    => $this->evidence->count(),
			'paged'    => $paged,
			'per_page' => $per_page,
		);
		require DRAGONCOMPLIANCE_PLUGIN_DIR . 'admin/views/evidence.php';
	}

	/**
	 * Settings tab.
	 */
	private function render_settings(): void {
		$dragoncompliance_view = array(
			'alert_enabled' => (bool) get_option( 'dragoncompliance_alert_enabled', 1 ),
			'has_token'     => $this->feed->token_set(),
			'provider'      => $this->feed->provider(),
			'recipients'    => implode( "\n", Alerts::saved_recipients() ),
			'admin_email'   => (string) get_option( 'admin_email', '' ),
		);
		require DRAGONCOMPLIANCE_PLUGIN_DIR . 'admin/views/settings.php';
	}

	/**
	 * Download the CycloneDX SBOM.
	 */
	public function handle_export_sbom(): void {
		check_admin_referer( 'dragoncompliance_export_sbom' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'dragon-compliance' ) );
		}

		$inventory = new Inventory();
		$document  = Sbom::cyclonedx(
			$inventory->components(),
			$inventory->environment(),
			wp_generate_uuid4(),
			gmdate( 'c' )
		);

		/**
		 * Fires when an SBOM download has been generated for an administrator.
		 */
		do_action( 'dragoncompliance_sbom_exported' );

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="sbom-' . gmdate( 'Y-m-d' ) . '.cdx.json"' );
		echo wp_json_encode( $document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON download.
		exit;
	}

	/**
	 * Save settings (source, Wordfence token, alerts, uninstall opt-in).
	 *
	 * The recipient list is validated first: a list containing markup, or an
	 * entry that is not an email address, refuses the whole form so nothing
	 * is half-saved.
	 */
	public function handle_save_settings(): void {
		check_admin_referer( 'dragoncompliance_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'dragon-compliance' ) );
		}

		$typed  = isset( $_POST['dragoncompliance_alert_recipients'] ) && is_string( $_POST['dragoncompliance_alert_recipients'] )
			? filter_var( wp_unslash( $_POST['dragoncompliance_alert_recipients'] ), FILTER_VALIDATE_REGEXP, array( 'options' => array( 'regexp' => '/^[^<>]*$/D' ) ) )
			: '';
		$parsed = false === $typed
			? array(
				'emails' => array(),
				'error'  => __( 'The alert recipients contain "<" or ">". Enter plain email addresses only.', 'dragon-compliance' ),
			)
			: Alerts::parse_recipients( (string) $typed );
		if ( '' !== $parsed['error'] ) {
			set_transient(
				self::SETTINGS_ERROR . get_current_user_id(),
				sprintf(
					/* translators: %s: what is wrong with the alert recipients, a full sentence. */
					__( 'The settings were not saved. Alert recipients: %s', 'dragon-compliance' ),
					$parsed['error']
				),
				60
			);
			wp_safe_redirect( admin_url( 'tools.php?page=dragon-compliance&tab=settings&dragoncompliance_notice=settings_refused' ) );
			exit;
		}

		$provider = isset( $_POST['dragoncompliance_feed_provider'] ) ? sanitize_key( wp_unslash( $_POST['dragoncompliance_feed_provider'] ) ) : '';
		if ( ! in_array( $provider, array( Feed::PROVIDER_WPVULNERABILITY, Feed::PROVIDER_WORDFENCE ), true ) ) {
			$provider = $this->feed->provider();
		}
		$previous = $this->feed->provider();

		update_option( 'dragoncompliance_alert_enabled', empty( $_POST['dragoncompliance_alert_enabled'] ) ? 0 : 1 );
		update_option( 'dragoncompliance_delete_data_on_uninstall', empty( $_POST['dragoncompliance_delete_data_on_uninstall'] ) ? 0 : 1 );
		update_option( Alerts::RECIPIENTS_OPTION, $parsed['emails'], false );
		update_option( Feed::PROVIDER_OPTION, $provider );

		if ( ! empty( $_POST['dragoncompliance_clear_token'] ) ) {
			delete_option( 'dragoncompliance_api_token' );
		} elseif ( isset( $_POST['dragoncompliance_api_token'] ) ) {
			$token = sanitize_text_field( wp_unslash( $_POST['dragoncompliance_api_token'] ) );
			if ( '' !== $token ) {
				update_option( 'dragoncompliance_api_token', Crypto::encrypt( $token ), false );
			}
		}

		// update_option() is also false for an unchanged value, so read back.
		$source_stored = get_option( Feed::PROVIDER_OPTION ) === $provider;
		$stored        = $source_stored && Alerts::saved_recipients() === $parsed['emails'];

		if ( $source_stored && $previous !== $provider ) {
			$this->evidence->record(
				'feed_source_changed',
				array(
					'from' => $previous,
					'to'   => $provider,
				)
			);
			// The next scan with data closes the old source's findings.
			Feed::note_source_change( $previous, $provider );
		}

		$notice = $stored ? 'settings_saved' : 'settings_failed';
		wp_safe_redirect( admin_url( 'tools.php?page=dragon-compliance&tab=settings&dragoncompliance_notice=' . $notice ) );
		exit;
	}

	/**
	 * Save manual attestations.
	 */
	public function handle_save_attestations(): void {
		check_admin_referer( 'dragoncompliance_save_attestations' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'dragon-compliance' ) );
		}

		$checklist = new Checklist( $this->findings, $this->evidence, array(), $this->feed );
		$attested  = isset( $_POST['dragoncompliance_attested'] ) ? (array) map_deep( wp_unslash( $_POST['dragoncompliance_attested'] ), 'sanitize_text_field' ) : array();
		$notes     = isset( $_POST['dragoncompliance_note'] ) ? (array) map_deep( wp_unslash( $_POST['dragoncompliance_note'] ), 'sanitize_text_field' ) : array();

		$items = array();
		foreach ( array( 'update_policy', 'security_contact', 'backup_policy', 'staging_process' ) as $id ) {
			$items[ $id ] = array(
				'attested' => ! empty( $attested[ $id ] ),
				'note'     => is_string( $notes[ $id ] ?? null ) ? $notes[ $id ] : '',
			);
		}

		// One option write for all four items, so a refused write stores none
		// of them and the failure notice is accurate.
		$notice = $checklist->attest_many( $items ) ? 'attestations_saved' : 'attestations_failed';
		wp_safe_redirect( admin_url( 'tools.php?page=dragon-compliance&tab=checklist&dragoncompliance_notice=' . $notice ) );
		exit;
	}

	/**
	 * Ignore / unignore a finding.
	 */
	public function handle_finding_status(): void {
		check_admin_referer( 'dragoncompliance_finding_status' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'dragon-compliance' ) );
		}

		$id      = isset( $_POST['finding_id'] ) ? absint( wp_unslash( $_POST['finding_id'] ) ) : 0;
		$ignored = ! empty( $_POST['ignore'] );
		$changed = $id > 0 && $this->findings->set_ignored( $id, $ignored );
		if ( $changed ) {
			$this->evidence->record(
				'finding_status_changed',
				array(
					'finding_id' => $id,
					'ignored'    => $ignored,
				)
			);
		}

		$notice = $changed ? 'finding_updated' : 'finding_not_updated';
		wp_safe_redirect( admin_url( 'tools.php?page=dragon-compliance&tab=findings&dragoncompliance_notice=' . $notice ) );
		exit;
	}

	/**
	 * AJAX: run a scan now.
	 */
	public function handle_scan_now(): void {
		check_ajax_referer( 'dragoncompliance_scan_now', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'dragon-compliance' ) ) );
		}

		$summary = Plugin::make_scanner()->run();
		wp_send_json_success( $summary );
	}
}
