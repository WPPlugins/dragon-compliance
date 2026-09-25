<?php
/**
 * Software inventory: core, plugins, themes, environment.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Builds the component list the SBOM, scanner and admin views consume.
 */
class Inventory {

	/**
	 * Returns plugin data arrays keyed by plugin file.
	 *
	 * @var callable
	 */
	private $plugins_provider;

	/**
	 * Returns theme data arrays keyed by stylesheet.
	 *
	 * @var callable
	 */
	private $themes_provider;

	/**
	 * Returns whether a plugin file is active.
	 *
	 * @var callable
	 */
	private $active_check;

	/**
	 * Constructor. Providers are injectable for tests.
	 *
	 * @param callable|null $plugins_provider Plugin list provider.
	 * @param callable|null $themes_provider  Theme list provider.
	 * @param callable|null $active_check     Plugin-active check.
	 */
	public function __construct( ?callable $plugins_provider = null, ?callable $themes_provider = null, ?callable $active_check = null ) {
		$this->plugins_provider = $plugins_provider ? $plugins_provider : array( $this, 'wp_plugins' );
		$this->themes_provider  = $themes_provider ? $themes_provider : array( $this, 'wp_themes' );
		$this->active_check     = $active_check ? $active_check : 'is_plugin_active';
	}

	/**
	 * Full component list: core first, then plugins and themes alphabetically.
	 *
	 * Each component: type, slug, name, version, author, license, uri, active.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function components(): array {
		$components = array(
			array(
				'type'    => 'core',
				'slug'    => 'wordpress',
				'name'    => 'WordPress',
				'version' => get_bloginfo( 'version' ),
				'author'  => 'WordPress.org',
				'license' => 'GPL-2.0-or-later',
				'uri'     => 'https://wordpress.org/',
				'active'  => true,
			),
		);

		$plugins = array();
		foreach ( call_user_func( $this->plugins_provider ) as $file => $data ) {
			// Folder plugins are keyed by their folder, a single-file plugin by
			// its file name (hello.php). The key stays stable because stored SBOM
			// snapshots and bom-refs use it; slug_map() adds the names the
			// vulnerability feed uses for single-file plugins.
			$slug      = strtok( $file, '/' );
			$plugins[] = array(
				'type'    => 'plugin',
				'slug'    => (string) $slug,
				'name'    => (string) ( $data['Name'] ?? $slug ),
				'version' => (string) ( $data['Version'] ?? '' ),
				'author'  => sanitize_text_field( (string) ( $data['Author'] ?? '' ) ),
				'license' => (string) ( $data['License'] ?? '' ),
				'uri'     => (string) ( $data['PluginURI'] ?? '' ),
				'active'  => (bool) call_user_func( $this->active_check, $file ),
			);
		}

		$themes = array();
		foreach ( call_user_func( $this->themes_provider ) as $stylesheet => $data ) {
			$themes[] = array(
				'type'    => 'theme',
				'slug'    => (string) $stylesheet,
				'name'    => (string) ( $data['Name'] ?? $stylesheet ),
				'version' => (string) ( $data['Version'] ?? '' ),
				'author'  => sanitize_text_field( (string) ( $data['Author'] ?? '' ) ),
				'license' => (string) ( $data['License'] ?? '' ),
				'uri'     => (string) ( $data['ThemeURI'] ?? '' ),
				'active'  => (bool) ( $data['Active'] ?? false ),
			);
		}

		usort( $plugins, array( self::class, 'by_slug' ) );
		usort( $themes, array( self::class, 'by_slug' ) );

		return array_merge( $components, $plugins, $themes );
	}

	/**
	 * Environment facts for the SBOM metadata and dashboard.
	 *
	 * @return array<string,mixed>
	 */
	public function environment(): array {
		global $wpdb;

		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '';

		return array(
			'php'        => PHP_VERSION,
			'db_version' => is_object( $wpdb ) && method_exists( $wpdb, 'db_version' ) ? (string) $wpdb->db_version() : '',
			'web_server' => $server,
			'https'      => is_ssl(),
			'wp_version' => get_bloginfo( 'version' ),
			'site_url'   => home_url(),
		);
	}

	/**
	 * Map components to the shape the feed indexer consumes:
	 * [ 'plugin' => [ slug => version ], 'theme' => [...], 'core' => [ slug => version ] ].
	 * The core entry is keyed by its slug (see components(), which uses the lower-
	 * case core slug).
	 *
	 * @param array $components Component list from components().
	 * @return array<string,array<string,string>>
	 */
	public static function slug_map( array $components ): array {
		$map = array(
			'core'   => array(),
			'plugin' => array(),
			'theme'  => array(),
		);
		foreach ( $components as $component ) {
			$type = (string) ( $component['type'] ?? '' );
			if ( isset( $map[ $type ] ) ) {
				$map[ $type ][ (string) $component['slug'] ] = (string) $component['version'];
			}
		}

		// Aliases go in after every real slug so they never shadow a folder
		// plugin of the same name.
		foreach ( $map['plugin'] as $slug => $version ) {
			foreach ( self::plugin_aliases( (string) $slug ) as $alias ) {
				if ( ! isset( $map['plugin'][ $alias ] ) ) {
					$map['plugin'][ $alias ] = $version;
				}
			}
		}
		return $map;
	}

	/**
	 * Feed lookup names for a single-file plugin keyed by its file name.
	 *
	 * The feed names plugins by their WordPress.org slug, and WordPress.org
	 * plugins ship in folders, so only a known single file is mapped (hello.php
	 * is hello-dolly). Any other single file is a custom plugin: matching it by
	 * its bare name would report an unrelated WordPress.org plugin's flaws.
	 *
	 * @param string $slug Inventory slug.
	 * @return string[] Extra lookup keys, empty for folder and custom plugins.
	 */
	public static function plugin_aliases( string $slug ): array {
		$known = array(
			'hello.php' => 'hello-dolly',
		);
		$key   = strtolower( $slug );
		return isset( $known[ $key ] ) ? array( $known[ $key ] ) : array();
	}

	/**
	 * Sort helper.
	 *
	 * @param array $a First component.
	 * @param array $b Second component.
	 */
	private static function by_slug( array $a, array $b ): int {
		return strcmp( (string) $a['slug'], (string) $b['slug'] );
	}

	/**
	 * Live plugin list with the License header included.
	 *
	 * @return array<string,array<string,string>>
	 */
	private function wp_plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = get_plugins();
		foreach ( $plugins as $file => $data ) {
			$headers                     = get_file_data( WP_PLUGIN_DIR . '/' . $file, array( 'License' => 'License' ) );
			$plugins[ $file ]['License'] = $headers['License'] ?? '';
		}
		return $plugins;
	}

	/**
	 * Live theme list flattened to plain arrays.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	private function wp_themes(): array {
		$current = get_stylesheet();
		$themes  = array();
		foreach ( wp_get_themes() as $stylesheet => $theme ) {
			$themes[ $stylesheet ] = array(
				'Name'     => $theme->get( 'Name' ),
				'Version'  => $theme->get( 'Version' ),
				'Author'   => $theme->get( 'Author' ),
				'License'  => (string) $theme->get( 'License' ),
				'ThemeURI' => (string) $theme->get( 'ThemeURI' ),
				'Active'   => $stylesheet === $current,
			);
		}
		return $themes;
	}
}
