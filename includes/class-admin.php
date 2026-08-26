<?php
/**
 * Admin UI: Tools → Compliance.
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
	 * The tab list, filterable so Pro can add tabs.
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
			'license'   => __( 'License', 'dragon-compliance' ),
		);
		/**
		 * Filters the admin tab list (Pro appends its tabs).
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
			case 'license':
				/**
				 * Filters whether the Pro plugin is active and licensed-capable.
				 *
				 * @param bool $active Whether Pro handles the license tab.
				 */
				if ( apply_filters( 'dragoncompliance_pro_active', false ) ) {
					/** This action is documented in includes/class-admin.php */
					do_action( 'dragoncompliance_admin_tabs', 'license' );
				} else {
					require DRAGONCOMPLIANCE_PLUGIN_DIR . 'admin/views/license-upsell.php';
				}
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
	 * One-shot admin notices from redirects.
	 */
	private function render_notices(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only notice flag.
		$notice = isset( $_GET['dragoncompliance_notice'] ) ? sanitize_key( wp_unslash( $_GET['dragoncompliance_notice'] ) ) : '';
		if ( '' === $notice ) {
			return;
		}
		$messages = array(
			'settings_saved'     => __( 'Settings saved.', 'dragon-compliance' ),
			'attestations_saved' => __( 'Attestations saved.', 'dragon-compliance' ),
			'finding_updated'    => __( 'Finding updated.', 'dragon-compliance' ),
		);
		if ( isset( $messages[ $notice ] ) ) {
			printf( '<div class="notice notice-success is-dismissible"><p>%s</p></div>', esc_html( $messages[ $notice ] ) );
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
			'has_token' => $this->feed->has_token(),
			// Configured but never successfully fetched: monitoring has no data yet.
			'no_data'   => null === $age,
			'error'     => $this->feed->last_error(),
		);
	}

	/**
	 * Dashboard tab.
	 */
	private function render_dashboard(): void {
		$checklist = new Checklist( $this->findings, $this->evidence );
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
		$dragoncompliance_view = array(
			'components'  => $inventory->components(),
			'environment' => $inventory->environment(),
			'export_url'  => wp_nonce_url( admin_url( 'admin-post.php?action=dragoncompliance_export_sbom' ), 'dragoncompliance_export_sbom' ),
			/**
			 * Filters the available SBOM export formats (Pro adds SPDX).
			 *
			 * @param array $formats format-slug => [label, url].
			 */
			'formats'     => (array) apply_filters( 'dragoncompliance_sbom_formats', array() ),
		);
		require DRAGONCOMPLIANCE_PLUGIN_DIR . 'admin/views/inventory.php';
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
		$checklist             = new Checklist( $this->findings, $this->evidence );
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
			'proxied'       => $this->feed->is_proxied(),
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

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="sbom-' . gmdate( 'Y-m-d' ) . '.cdx.json"' );
		echo wp_json_encode( $document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON download.
		exit;
	}

	/**
	 * Save settings (alert toggle + Wordfence token).
	 */
	public function handle_save_settings(): void {
		check_admin_referer( 'dragoncompliance_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'dragon-compliance' ) );
		}

		update_option( 'dragoncompliance_alert_enabled', empty( $_POST['dragoncompliance_alert_enabled'] ) ? 0 : 1 );
		update_option( 'dragoncompliance_delete_data_on_uninstall', empty( $_POST['dragoncompliance_delete_data_on_uninstall'] ) ? 0 : 1 );

		if ( ! empty( $_POST['dragoncompliance_clear_token'] ) ) {
			delete_option( 'dragoncompliance_api_token' );
		} elseif ( isset( $_POST['dragoncompliance_api_token'] ) ) {
			$token = sanitize_text_field( wp_unslash( $_POST['dragoncompliance_api_token'] ) );
			if ( '' !== $token ) {
				update_option( 'dragoncompliance_api_token', Crypto::encrypt( $token ), false );
			}
		}

		wp_safe_redirect( admin_url( 'tools.php?page=dragon-compliance&tab=settings&dragoncompliance_notice=settings_saved' ) );
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

		$checklist = new Checklist( $this->findings, $this->evidence );
		$attested  = isset( $_POST['dragoncompliance_attested'] ) ? (array) wp_unslash( $_POST['dragoncompliance_attested'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Items sanitized in attest().
		$notes     = isset( $_POST['dragoncompliance_note'] ) ? (array) wp_unslash( $_POST['dragoncompliance_note'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Items sanitized in attest().

		foreach ( array( 'update_policy', 'security_contact', 'backup_policy', 'staging_process' ) as $id ) {
			$checklist->attest(
				$id,
				! empty( $attested[ $id ] ),
				sanitize_text_field( (string) ( $notes[ $id ] ?? '' ) )
			);
		}

		wp_safe_redirect( admin_url( 'tools.php?page=dragon-compliance&tab=checklist&dragoncompliance_notice=attestations_saved' ) );
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
		if ( $id > 0 ) {
			$this->findings->set_ignored( $id, $ignored );
			$this->evidence->record(
				'finding_status_changed',
				array(
					'finding_id' => $id,
					'ignored'    => $ignored,
				)
			);
		}

		wp_safe_redirect( admin_url( 'tools.php?page=dragon-compliance&tab=findings&dragoncompliance_notice=finding_updated' ) );
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
