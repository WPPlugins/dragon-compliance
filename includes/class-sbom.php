<?php
/**
 * CycloneDX SBOM serializer.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Turns the inventory into a CycloneDX 1.6 document.
 */
final class Sbom {

	/**
	 * Build a CycloneDX 1.6 document as an associative array.
	 *
	 * @param array  $components  Component list from Inventory::components().
	 * @param array  $environment Environment from Inventory::environment().
	 * @param string $serial_uuid UUIDv4 for the serialNumber.
	 * @param string $timestamp   ISO-8601 timestamp.
	 * @return array<string,mixed>
	 */
	public static function cyclonedx( array $components, array $environment, string $serial_uuid, string $timestamp ): array {
		$entries = array();
		foreach ( $components as $component ) {
			$entry = array(
				'type'     => 'core' === $component['type'] ? 'application' : 'library',
				'bom-ref'  => sprintf( '%s:%s@%s', $component['type'], $component['slug'], $component['version'] ),
				'name'     => (string) $component['name'],
				'version'  => (string) $component['version'],
				'supplier' => array( 'name' => '' !== (string) $component['author'] ? (string) $component['author'] : 'Unknown' ),
			);
			if ( '' !== (string) ( $component['license'] ?? '' ) ) {
				$entry['licenses'] = array(
					array( 'license' => array( 'name' => (string) $component['license'] ) ),
				);
			}
			$entry['properties'] = array(
				array(
					'name'  => 'dragoncompliance:type',
					'value' => (string) $component['type'],
				),
				array(
					'name'  => 'dragoncompliance:active',
					'value' => ! empty( $component['active'] ) ? 'true' : 'false',
				),
			);
			$entries[]           = $entry;
		}

		return array(
			'bomFormat'    => 'CycloneDX',
			'specVersion'  => '1.6',
			'serialNumber' => 'urn:uuid:' . $serial_uuid,
			'version'      => 1,
			'metadata'     => array(
				'timestamp' => $timestamp,
				'tools'     => array(
					'components' => array(
						array(
							'type'    => 'application',
							'name'    => 'dragon-compliance',
							'version' => DRAGONCOMPLIANCE_VERSION,
						),
					),
				),
				'component' => array(
					'type'       => 'application',
					'bom-ref'    => 'site:' . (string) ( $environment['site_url'] ?? '' ),
					'name'       => (string) ( $environment['site_url'] ?? 'WordPress site' ),
					'version'    => (string) ( $environment['wp_version'] ?? '' ),
					'properties' => array(
						array(
							'name'  => 'dragoncompliance:php',
							'value' => (string) ( $environment['php'] ?? '' ),
						),
						array(
							'name'  => 'dragoncompliance:https',
							'value' => ! empty( $environment['https'] ) ? 'true' : 'false',
						),
					),
				),
			),
			'components'   => $entries,
		);
	}
}
