<?php
/**
 * Plugin Name: Dragon Compliance
 * Plugin URI: https://dragoncore.ltd/plugins/dragon-compliance
 * Description: CRA & NIS2 compliance for WordPress — software inventory, CycloneDX SBOM export, known-vulnerability monitoring, readiness checklist and evidence log. All processing stays on your server.
 * Version: 1.0.5
 * Requires at least: 6.2
 * Requires PHP: 8.0
 * Author: Dragon Core
 * Author URI: https://dragoncore.ltd
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: dragon-compliance
 * Domain Path: /languages
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound
define( 'DRAGONCOMPLIANCE_VERSION', '1.0.5' );
define( 'DRAGONCOMPLIANCE_DB_VERSION', '2' );
define( 'DRAGONCOMPLIANCE_PLUGIN_FILE', __FILE__ );
define( 'DRAGONCOMPLIANCE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'DRAGONCOMPLIANCE_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'DRAGONCOMPLIANCE_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound

require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-installer.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-crypto.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-inventory.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-sbom.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-feed.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-matcher.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-findings-store.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-evidence.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-checklist.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-alerts.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-scanner.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-cron.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-admin.php';
require_once DRAGONCOMPLIANCE_PLUGIN_DIR . 'includes/class-plugin.php';

/**
 * Activation: create tables, seed options, schedule the daily scan.
 */
function dragoncompliance_activate(): void {
	Installer::install();
	if ( ! wp_next_scheduled( 'dragoncompliance_daily_scan' ) ) {
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'dragoncompliance_daily_scan' );
	}
}
register_activation_hook( __FILE__, __NAMESPACE__ . '\dragoncompliance_activate' );

/**
 * Deactivation: clear the daily scan cron.
 */
function dragoncompliance_deactivate(): void {
	$timestamp = wp_next_scheduled( 'dragoncompliance_daily_scan' );
	if ( $timestamp ) {
		wp_unschedule_event( $timestamp, 'dragoncompliance_daily_scan' );
	}
	wp_clear_scheduled_hook( 'dragoncompliance_change_scan' );
}
register_deactivation_hook( __FILE__, __NAMESPACE__ . '\dragoncompliance_deactivate' );

/**
 * Boot the plugin.
 */
function dragoncompliance_init(): void {
	Installer::maybe_upgrade();
	Plugin::instance();
}
add_action( 'plugins_loaded', __NAMESPACE__ . '\dragoncompliance_init' );
