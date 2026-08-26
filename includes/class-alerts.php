<?php
/**
 * Critical-finding email alert.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Sends one plain-text email to the site admin when new critical
 * vulnerabilities are detected. Pro replaces this with routed channels.
 */
class Alerts {

	/**
	 * Mailer, injectable for tests. Signature matches wp_mail.
	 *
	 * @var callable
	 */
	private $mailer;

	/**
	 * Constructor.
	 *
	 * @param callable|null $mailer Mailer override for tests.
	 */
	public function __construct( ?callable $mailer = null ) {
		$this->mailer = $mailer ? $mailer : 'wp_mail';
	}

	/**
	 * Email the admin about new critical findings.
	 *
	 * @param array $findings New critical findings (matched-record shape).
	 */
	public function critical( array $findings ): void {
		if ( array() === $findings || ! get_option( 'dragoncompliance_alert_enabled', 1 ) ) {
			return;
		}

		$lines = array(
			__( 'Dragon Compliance detected new critical vulnerabilities on your site:', 'dragon-compliance' ),
			'',
		);
		foreach ( $findings as $finding ) {
			$lines[] = sprintf(
				'- [%1$s] %2$s%3$s',
				(string) ( $finding['slug'] ?? '' ),
				(string) ( $finding['title'] ?? '' ),
				! empty( $finding['cve'] ) ? ' (' . (string) $finding['cve'] . ')' : ''
			);
		}
		$lines[] = '';
		$lines[] = __( 'Review them in wp-admin under Tools → Compliance.', 'dragon-compliance' );

		call_user_func(
			$this->mailer,
			get_option( 'admin_email' ),
			sprintf(
				/* translators: %s: site name. */
				__( '[%s] Critical vulnerability detected', 'dragon-compliance' ),
				get_bloginfo( 'name' )
			),
			implode( "\n", $lines )
		);
	}
}
