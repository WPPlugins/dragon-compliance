<?php
/**
 * Main plugin singleton.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Wires the plugin's classes together.
 */
final class Plugin {

	/**
	 * Singleton instance.
	 *
	 * @var Plugin|null
	 */
	private static ?Plugin $instance = null;

	/**
	 * Get the singleton instance.
	 */
	public static function instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Load classes and register hooks.
	 */
	private function __construct() {
		$this->init_hooks();
	}

	/**
	 * Build the scan pipeline.
	 */
	public static function make_scanner(): Scanner {
		return new Scanner(
			new Inventory(),
			new Feed(),
			new Findings_Store(),
			new Evidence(),
			new Alerts()
		);
	}

	/**
	 * Register WordPress hooks.
	 */
	private function init_hooks(): void {
		$cron = new Cron( array( self::class, 'make_scanner' ) );
		$cron->init();

		if ( is_admin() ) {
			$admin = new Admin( new Findings_Store(), new Evidence(), new Feed() );
			$admin->init();
		}
	}
}
