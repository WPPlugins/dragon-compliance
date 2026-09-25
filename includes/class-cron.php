<?php
/**
 * Cron wiring.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Runs the daily scan.
 */
class Cron {

	/**
	 * Scanner factory, called lazily so cron requests only build the
	 * pipeline when the event actually fires.
	 *
	 * @var callable
	 */
	private $scanner_factory;

	/**
	 * Set once the plugin is deactivated in this request: core deactivates a
	 * batch one plugin at a time, so later plugins in the batch still fire
	 * deactivated_plugin while these hooks are loaded.
	 *
	 * @var bool
	 */
	private static bool $stopped = false;

	/**
	 * Stop scheduling for the rest of the request.
	 */
	public static function stop(): void {
		self::$stopped = true;
	}

	/**
	 * Constructor.
	 *
	 * @param callable $scanner_factory Returns a Scanner.
	 */
	public function __construct( callable $scanner_factory ) {
		$this->scanner_factory = $scanner_factory;
	}

	/**
	 * Register hooks.
	 */
	public function init(): void {
		add_action( 'dragoncompliance_daily_scan', array( $this, 'run_daily' ) );
		add_action( 'dragoncompliance_change_scan', array( $this, 'run_daily' ) );

		// Activation schedules the scan once, and on a network activation only
		// for the site it ran on; every site checks its own event here.
		add_action( 'init', array( $this, 'ensure_scheduled' ) );

		// A daily-only scan leaves a plugin/theme installed or updated today
		// invisible until tomorrow — a false-negative window that matters for a
		// compliance product. Queue a debounced rescan whenever the installed
		// software changes; the vulnerability feed refreshes on a slug-map change.
		add_action( 'upgrader_process_complete', array( $this, 'schedule_change_scan' ) );
		add_action( 'activated_plugin', array( $this, 'schedule_change_scan' ) );
		add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivated' ) );
		add_action( 'deleted_plugin', array( $this, 'schedule_change_scan' ) );
		add_action( 'switch_theme', array( $this, 'schedule_change_scan' ) );
	}

	/**
	 * Schedule the daily scan for the current site when it is missing.
	 */
	public function ensure_scheduled(): void {
		if ( self::$stopped ) {
			return;
		}
		if ( ! wp_next_scheduled( 'dragoncompliance_daily_scan' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'dragoncompliance_daily_scan' );
		}
	}

	/**
	 * Queue a single rescan shortly after a software change, debounced so a batch
	 * of changes (e.g. updating several plugins at once) coalesces into one scan.
	 */
	public function schedule_change_scan(): void {
		if ( self::$stopped ) {
			return;
		}
		if ( wp_next_scheduled( 'dragoncompliance_change_scan' ) ) {
			return;
		}
		wp_schedule_single_event( time() + 2 * MINUTE_IN_SECONDS, 'dragoncompliance_change_scan' );
	}

	/**
	 * Queue a rescan when another plugin is deactivated. Core fires
	 * deactivated_plugin after this plugin's own deactivation hook, so a
	 * rescan queued for itself would outlive the plugin.
	 *
	 * @param string $plugin Basename of the deactivated plugin.
	 */
	public function on_plugin_deactivated( $plugin = '' ): void {
		if ( defined( 'DRAGONCOMPLIANCE_PLUGIN_BASENAME' ) && DRAGONCOMPLIANCE_PLUGIN_BASENAME === $plugin ) {
			return;
		}
		$this->schedule_change_scan();
	}

	/**
	 * Cron callback.
	 */
	public function run_daily(): void {
		$scanner = call_user_func( $this->scanner_factory );
		if ( $scanner instanceof Scanner ) {
			$scanner->run();
		}
	}
}
