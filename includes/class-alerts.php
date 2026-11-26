<?php
/**
 * New-finding email alerts.
 *
 * @package DragonCompliance
 */

namespace DragonCompliance;

defined( 'ABSPATH' ) || exit;

/**
 * Sends one plain-text email per recipient when new critical vulnerabilities,
 * or new ones with no published severity, are detected: to the addresses
 * saved under Settings, or to the site admin when none are saved.
 */
class Alerts {

	/**
	 * Option holding the alert recipients (a list of addresses).
	 */
	public const RECIPIENTS_OPTION = 'dragoncompliance_alert_recipients';

	/**
	 * Most addresses one list may hold.
	 */
	public const MAX_RECIPIENTS = 20;

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
	 * Whether text holds a control character. is_email() accepts one before
	 * the "@" when it is a trailing new line.
	 *
	 * @param string $text Text.
	 */
	private static function has_control_character( string $text ): bool {
		return 1 === preg_match( '/[\x00-\x1F\x7F]/', $text );
	}

	/**
	 * Read a typed list of addresses, separated by commas or new lines.
	 *
	 * A list with an entry that is not an email address, or with more than
	 * MAX_RECIPIENTS addresses, is refused whole: no address is dropped or
	 * rewritten to make the rest fit. Duplicates are kept once.
	 *
	 * @param string $text The list as typed.
	 * @return array{emails:string[],error:string} The addresses, or none and one sentence naming what was refused.
	 */
	public static function parse_recipients( string $text ): array {
		$emails = array();

		foreach ( explode( ',', str_replace( array( "\r", "\n" ), ',', $text ) ) as $entry ) {
			$entry = trim( $entry, " \t" );
			if ( '' === $entry ) {
				continue;
			}

			if ( self::has_control_character( $entry ) || ! is_email( $entry ) ) {
				return array(
					'emails' => array(),
					/* translators: %s: what was typed. */
					'error'  => sprintf( __( '"%s" is not an email address.', 'dragon-compliance' ), trim( (string) preg_replace( '/[\x00-\x1F\x7F]+/', ' ', $entry ) ) ),
				);
			}

			$key = strtolower( $entry );
			if ( ! isset( $emails[ $key ] ) ) {
				$emails[ $key ] = $entry;
			}
		}

		if ( count( $emails ) > self::MAX_RECIPIENTS ) {
			$max = self::MAX_RECIPIENTS;
			return array(
				'emails' => array(),
				'error'  => sprintf(
					/* translators: %s: the largest number of addresses accepted. */
					_n( 'Enter at most %s address.', 'Enter at most %s addresses.', $max, 'dragon-compliance' ),
					number_format_i18n( $max )
				),
			);
		}

		return array(
			'emails' => array_values( $emails ),
			'error'  => '',
		);
	}

	/**
	 * The saved recipients, keeping only valid addresses.
	 *
	 * @return string[]
	 */
	public static function saved_recipients(): array {
		$saved  = get_option( self::RECIPIENTS_OPTION, array() );
		$emails = array();
		foreach ( is_array( $saved ) ? $saved : array() as $email ) {
			if ( is_string( $email ) && ! self::has_control_character( $email ) && is_email( $email ) ) {
				$emails[ strtolower( $email ) ] = $email;
			}
		}
		return array_values( $emails );
	}

	/**
	 * Where alerts go: the saved recipients, or the site admin when none are
	 * saved. With the Pro add-on active, only the site admin, so the two
	 * never both route the same alert.
	 *
	 * @return string[]
	 */
	public static function recipients(): array {
		$saved = class_exists( '\DragonCompliancePro\Plugin' ) ? array() : self::saved_recipients();
		if ( array() !== $saved ) {
			return $saved;
		}
		$admin = (string) get_option( 'admin_email', '' );
		return '' !== $admin && is_email( $admin ) ? array( $admin ) : array();
	}

	/**
	 * Whether a new finding is emailed: a critical one, or one whose severity
	 * the source has not published, which could be anything up to critical.
	 *
	 * @param array $finding Matched record.
	 */
	public static function alertable( array $finding ): bool {
		$severity = (string) ( $finding['severity'] ?? '' );
		return in_array( $severity, array( 'critical', 'unknown', '' ), true );
	}

	/**
	 * One plain-text line for a finding.
	 *
	 * @param array $finding Matched record.
	 */
	private static function line( array $finding ): string {
		return sprintf(
			'- [%1$s] %2$s%3$s',
			(string) ( $finding['slug'] ?? '' ),
			// Plain-text mail: sanitize_text_field() stored "<=" as "&lt;=".
			wp_specialchars_decode( (string) ( $finding['title'] ?? '' ), ENT_QUOTES ),
			! empty( $finding['cve'] ) ? ' (' . (string) $finding['cve'] . ')' : ''
		);
	}

	/**
	 * Email the recipients about new findings: critical ones first, then the
	 * ones with no published severity, each marked for review.
	 *
	 * @param array $findings New findings (matched-record shape); those alertable() refuses are left out.
	 * @return string[] Addresses the mailer refused (empty when every mail was accepted or alerts are off).
	 */
	public function alert( array $findings ): array {
		$findings = array_filter( $findings, array( self::class, 'alertable' ) );
		if ( array() === $findings || ! get_option( 'dragoncompliance_alert_enabled', 1 ) ) {
			return array();
		}

		$criticals = array();
		$unknown   = array();
		foreach ( $findings as $finding ) {
			if ( 'critical' === ( $finding['severity'] ?? '' ) ) {
				$criticals[] = $finding;
			} else {
				$unknown[] = $finding;
			}
		}

		$lines = array();
		if ( array() !== $criticals ) {
			$lines[] = __( 'Dragon Compliance detected new critical vulnerabilities on your site:', 'dragon-compliance' );
			$lines[] = '';
			foreach ( $criticals as $finding ) {
				$lines[] = self::line( $finding );
			}
			$lines[] = '';
		}
		if ( array() !== $unknown ) {
			$lines[] = __( 'Dragon Compliance detected new vulnerabilities on your site whose severity has not been published:', 'dragon-compliance' );
			$lines[] = '';
			foreach ( $unknown as $finding ) {
				$lines[] = self::line( $finding ) . ' - ' . __( 'severity not published - review it', 'dragon-compliance' );
			}
			$lines[] = '';
		}
		$lines[] = __( 'Review them in wp-admin under Tools → Compliance.', 'dragon-compliance' );

		$site    = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$subject = array() !== $criticals
			? sprintf(
				/* translators: %s: site name. */
				__( '[%s] Critical vulnerability detected', 'dragon-compliance' ),
				$site
			)
			: sprintf(
				/* translators: %s: site name. */
				__( '[%s] New vulnerability detected - severity not published', 'dragon-compliance' ),
				$site
			);
		$body = implode( "\n", $lines );

		$failed = array();
		foreach ( self::recipients() as $recipient ) {
			if ( true !== call_user_func( $this->mailer, $recipient, $subject, $body ) ) {
				$failed[] = $recipient;
			}
		}
		return $failed;
	}
}
