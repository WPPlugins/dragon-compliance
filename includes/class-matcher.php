<?php
/**
 * Version-range matching and findings diffing.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Decides which indexed vulnerabilities affect the installed versions,
 * and diffs the result against the currently-open findings.
 */
final class Matcher {

	/**
	 * Whether a version falls inside an affected range.
	 *
	 * `*` means an open end. Unparseable versions never match — the caller
	 * surfaces those components as "unassessed" instead of guessing.
	 *
	 * @param string $version Installed version.
	 * @param array  $range   ['from','from_inclusive','to','to_inclusive'].
	 */
	public static function version_in_range( string $version, array $range ): bool {
		if ( '' === trim( $version ) ) {
			return false;
		}

		$from = (string) ( $range['from'] ?? '*' );
		$to   = (string) ( $range['to'] ?? '*' );

		if ( '*' !== $from ) {
			$op = ! empty( $range['from_inclusive'] ) ? '>=' : '>';
			if ( true !== version_compare( $version, $from, $op ) ) {
				return false;
			}
		}
		if ( '*' !== $to ) {
			$op = ! empty( $range['to_inclusive'] ) ? '<=' : '<';
			if ( true !== version_compare( $version, $to, $op ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Whether an installed version is affected by an index record.
	 *
	 * @param string $installed_version Installed version.
	 * @param array  $record            Compact feed index record.
	 */
	public static function is_vulnerable( string $installed_version, array $record ): bool {
		foreach ( (array) ( $record['affected'] ?? array() ) as $range ) {
			if ( is_array( $range ) && self::version_in_range( $installed_version, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Match the whole index against installed versions.
	 *
	 * @param array $index    Compact feed index records.
	 * @param array $slug_map ['core'=>[slug=>version], 'plugin'=>…, 'theme'=>…].
	 * @return array Matched records, each with 'installed_version' added.
	 */
	public static function matches( array $index, array $slug_map ): array {
		$matched = array();
		foreach ( $index as $record ) {
			if ( ! is_array( $record ) || ! isset( $record['type'], $record['slug'] ) ) {
				continue;
			}
			$version = $slug_map[ $record['type'] ][ $record['slug'] ] ?? null;
			if ( null === $version ) {
				continue;
			}
			if ( self::is_vulnerable( (string) $version, $record ) ) {
				$record['installed_version'] = (string) $version;
				$matched[]                   = $record;
			}
		}
		return $matched;
	}

	/**
	 * Diff matched vulnerabilities against currently-open finding rows.
	 *
	 * @param array $open_rows Open findings (each has vuln_id, component_slug).
	 * @param array $matched   Matched records from matches().
	 * @return array{new:array,resolved_ids:array}
	 */
	public static function diff( array $open_rows, array $matched ): array {
		$matched_keys = array();
		foreach ( $matched as $record ) {
			$matched_keys[ $record['vuln_id'] . '|' . $record['slug'] ] = true;
		}

		$open_keys = array();
		$resolved  = array();
		foreach ( $open_rows as $row ) {
			$key               = (string) $row['vuln_id'] . '|' . (string) $row['component_slug'];
			$open_keys[ $key ] = true;
			if ( ! isset( $matched_keys[ $key ] ) ) {
				$resolved[] = (int) $row['id'];
			}
		}

		$new = array();
		foreach ( $matched as $record ) {
			if ( ! isset( $open_keys[ $record['vuln_id'] . '|' . $record['slug'] ] ) ) {
				$new[] = $record;
			}
		}

		return array(
			'new'          => $new,
			'resolved_ids' => $resolved,
		);
	}

	/**
	 * Components whose version string version_compare cannot evaluate.
	 *
	 * @param array $components Inventory components.
	 * @return array Slugs of unassessable components.
	 */
	public static function unassessed( array $components ): array {
		$slugs = array();
		foreach ( $components as $component ) {
			$version = trim( (string) ( $component['version'] ?? '' ) );
			if ( '' === $version ) {
				$slugs[] = (string) $component['slug'];
			}
		}
		return $slugs;
	}
}
