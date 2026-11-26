<?php
/**
 * Display labels for stored codes.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Maps stored codes (severity, status, component type, evidence event) to
 * translated labels at display time. Unknown codes fall back to the raw code.
 */
final class Labels {

	/**
	 * Severity label.
	 *
	 * @param string $code Severity code.
	 */
	public static function severity( string $code ): string {
		$labels = array(
			'critical' => __( 'Critical', 'dragon-compliance' ),
			'high'     => __( 'High', 'dragon-compliance' ),
			'medium'   => __( 'Medium', 'dragon-compliance' ),
			'low'      => __( 'Low', 'dragon-compliance' ),
			'unknown'  => __( 'Unknown', 'dragon-compliance' ),
		);
		return $labels[ $code ] ?? $code;
	}

	/**
	 * Finding status label.
	 *
	 * @param string $code Status code.
	 */
	public static function finding_status( string $code ): string {
		$labels = array(
			'open'           => __( 'Open', 'dragon-compliance' ),
			'ignored'        => __( 'Ignored', 'dragon-compliance' ),
			'resolved'       => __( 'Resolved', 'dragon-compliance' ),
			'source_changed' => __( 'Closed: data source changed', 'dragon-compliance' ),
		);
		return $labels[ $code ] ?? $code;
	}

	/**
	 * Component type label.
	 *
	 * @param string $code Component type code.
	 */
	public static function component_type( string $code ): string {
		$labels = array(
			'core'   => __( 'WordPress core', 'dragon-compliance' ),
			'plugin' => __( 'Plugin', 'dragon-compliance' ),
			'theme'  => __( 'Theme', 'dragon-compliance' ),
		);
		return $labels[ $code ] ?? $code;
	}

	/**
	 * Evidence event label.
	 *
	 * @param string $code Event type code.
	 */
	public static function evidence_event( string $code ): string {
		$labels = array(
			'scan_complete'           => __( 'Scan completed', 'dragon-compliance' ),
			'vuln_detected'           => __( 'Vulnerability detected', 'dragon-compliance' ),
			'vuln_resolved'           => __( 'Vulnerability resolved', 'dragon-compliance' ),
			'vuln_reopened'           => __( 'Vulnerability reopened', 'dragon-compliance' ),
			'finding_status_changed'  => __( 'Finding status changed', 'dragon-compliance' ),
			'finding_version_changed' => __( 'Installed version updated on an open finding', 'dragon-compliance' ),
			'attestation_changed'     => __( 'Attestation changed', 'dragon-compliance' ),
			'feed_fetch_failed'       => __( 'Vulnerability feed fetch failed', 'dragon-compliance' ),
			'report_send_failed'      => __( 'Scheduled report not delivered', 'dragon-compliance' ),
			'vuln_check_incomplete'   => __( 'Some components could not be checked', 'dragon-compliance' ),
			'alert_not_delivered'     => __( 'Alert email not accepted for delivery', 'dragon-compliance' ),
			'feed_source_changed'     => __( 'Vulnerability data source changed', 'dragon-compliance' ),
			'finding_source_changed'  => __( 'Finding closed: vulnerability data source changed', 'dragon-compliance' ),
		);
		return $labels[ $code ] ?? $code;
	}

	/**
	 * Vulnerability data source label.
	 *
	 * @param string $code Source code.
	 */
	public static function feed_provider( string $code ): string {
		$labels = array(
			'wpvulnerability' => __( 'WPVulnerability', 'dragon-compliance' ),
			'wordfence'       => __( 'Wordfence Intelligence', 'dragon-compliance' ),
		);
		return $labels[ $code ] ?? $code;
	}

	/**
	 * Format a stored UTC MySQL datetime for display.
	 *
	 * @param string $value Datetime as stored (UTC).
	 * @param bool   $utc   Show in UTC rather than the site timezone.
	 */
	public static function datetime( string $value, bool $utc = false ): string {
		$ts = strtotime( $value . ' UTC' );
		if ( '' === $value || false === $ts ) {
			return $value;
		}
		$format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		$out    = $utc ? wp_date( $format, $ts, new \DateTimeZone( 'UTC' ) ) : wp_date( $format, $ts );
		return false === $out ? $value : $out;
	}
}
