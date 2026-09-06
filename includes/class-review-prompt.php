<?php
/**
 * WordPress.org review prompt.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Asks for a WordPress.org review once, on the plugin's own screen only, and
 * only after the plugin has done real work on the site. "No thanks" is
 * permanent, "Maybe later" snoozes for a month, and opening the review page
 * counts as done. Nothing is shown anywhere else in wp-admin.
 */
class Review_Prompt {

	/**
	 * Option holding the prompt state.
	 */
	public const OPTION = 'dragoncompliance_review_prompt';

	/**
	 * The admin-post action that records a choice.
	 */
	private const ACTION = 'dragoncompliance_review_prompt';

	/**
	 * Screen id of the plugin's own Tools page.
	 */
	private const SCREEN = 'tools_page_dragon-compliance';

	/**
	 * Days the plugin must have been in use before a single value event
	 * is enough to ask.
	 */
	private const MIN_AGE_DAYS = 3;

	/**
	 * Value events that justify asking before MIN_AGE_DAYS has passed.
	 */
	private const EARLY_EVENTS = 3;

	/**
	 * Length of a "Maybe later" snooze, in days.
	 */
	private const SNOOZE_DAYS = 30;

	/**
	 * Actions that mean the plugin has just done something useful.
	 *
	 * @var string[]
	 */
	private const VALUE_HOOKS = array( 'dragoncompliance_scan_complete', 'dragoncompliance_sbom_exported' );

	/**
	 * Register hooks.
	 */
	public function init_hooks(): void {
		foreach ( self::VALUE_HOOKS as $hook ) {
			add_action( $hook, array( __CLASS__, 'record_value' ) );
		}
		add_action( 'admin_notices', array( $this, 'render' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle' ) );
	}

	/**
	 * Count one value event. Stops writing once the prompt has been answered
	 * or the count already satisfies the early threshold, so a busy site
	 * writes this option at most a handful of times in its life. The
	 * read-modify-write is not locked: an event landing in the same
	 * millisecond as a dismissal can lose one of the two, which only affects
	 * this prompt's preferences.
	 */
	public static function record_value(): void {
		$state = self::state();
		if ( $state['dismissed'] || (int) $state['events'] >= self::EARLY_EVENTS ) {
			return;
		}
		++$state['events'];
		update_option( self::OPTION, $state, false );
	}

	/**
	 * Whether the prompt is due, from a state array and the current time.
	 * Pure so it can be unit-tested.
	 *
	 * @param array<string,mixed> $state State as stored in the option.
	 * @param int                 $now   Current Unix time.
	 */
	public static function is_due( array $state, int $now ): bool {
		if ( ! empty( $state['dismissed'] ) ) {
			return false;
		}
		if ( (int) ( $state['snoozed_until'] ?? 0 ) > $now ) {
			return false;
		}
		$events = (int) ( $state['events'] ?? 0 );
		if ( $events < 1 ) {
			return false;
		}
		$first_use = (int) ( $state['first_use'] ?? 0 );
		if ( $first_use <= 0 ) {
			return false;
		}
		$old_enough = ( $first_use + self::MIN_AGE_DAYS * DAY_IN_SECONDS ) <= $now;

		return $old_enough || $events >= self::EARLY_EVENTS;
	}

	/**
	 * Print the notice on the plugin's own screen when it is due.
	 */
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || self::SCREEN !== $screen->id ) {
			return;
		}
		if ( ! self::is_due( self::state(), time() ) ) {
			return;
		}
		?>
		<div class="notice notice-info dragon-compliance-review-prompt">
			<p>
				<strong><?php esc_html_e( 'Is Dragon Compliance earning its keep?', 'dragon-compliance' ); ?></strong>
				<?php esc_html_e( 'A short review on WordPress.org helps other people find it. It takes about a minute, and we read every one.', 'dragon-compliance' ); ?>
			</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( self::choice_url( 'review' ) ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Leave a review', 'dragon-compliance' ); ?></a>
				<a class="button" href="<?php echo esc_url( self::choice_url( 'later' ) ); ?>"><?php esc_html_e( 'Maybe later', 'dragon-compliance' ); ?></a>
				<a href="<?php echo esc_url( self::choice_url( 'never' ) ); ?>"><?php esc_html_e( 'No thanks', 'dragon-compliance' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * Record the visitor's choice and send them on.
	 */
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'dragon-compliance' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );

		$choice = isset( $_GET['choice'] ) ? sanitize_key( wp_unslash( $_GET['choice'] ) ) : '';
		$state  = self::state();

		if ( 'later' === $choice ) {
			$state['snoozed_until'] = time() + self::SNOOZE_DAYS * DAY_IN_SECONDS;
		} elseif ( 'never' === $choice || 'review' === $choice ) {
			$state['dismissed'] = true;
		}
		update_option( self::OPTION, $state, false );

		if ( 'review' === $choice ) {
			add_filter( 'allowed_redirect_hosts', array( __CLASS__, 'allow_wporg_host' ) );
			wp_safe_redirect( 'https://wordpress.org/support/plugin/dragon-compliance/reviews/#new-post' );
			exit;
		}

		$back = wp_get_referer();
		wp_safe_redirect( $back ? $back : admin_url( 'tools.php?page=dragon-compliance' ) );
		exit;
	}

	/**
	 * Let wp_safe_redirect() send the reviewer to wordpress.org.
	 *
	 * @param string[] $hosts Allowed hosts.
	 * @return string[]
	 */
	public static function allow_wporg_host( array $hosts ): array {
		$hosts[] = 'wordpress.org';
		return $hosts;
	}

	/**
	 * Nonce-protected admin-post URL for one choice.
	 *
	 * @param string $choice review|later|never.
	 */
	private static function choice_url( string $choice ): string {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action' => self::ACTION,
					'choice' => $choice,
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION
		);
	}

	/**
	 * Current state with defaults. The first call stamps first_use, so the
	 * clock starts when the plugin is first used rather than when the file
	 * landed on disk.
	 *
	 * @return array<string,mixed>
	 */
	private static function state(): array {
		$defaults = array(
			'first_use'     => 0,
			'events'        => 0,
			'dismissed'     => false,
			'snoozed_until' => 0,
		);
		$stored   = get_option( self::OPTION, array() );
		$state    = array_merge( $defaults, is_array( $stored ) ? $stored : array() );

		if ( (int) $state['first_use'] <= 0 ) {
			$state['first_use'] = time();
			update_option( self::OPTION, $state, false );
		}

		return $state;
	}
}
