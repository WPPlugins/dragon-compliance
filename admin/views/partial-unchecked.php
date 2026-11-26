<?php
/**
 * Notice listing the components the last scan could not check.
 *
 * @package DragonCompliance
 * @var array $dragoncompliance_feed Feed banner data.
 */

defined( 'ABSPATH' ) || exit;

$dragoncompliance_unchecked = (array) ( $dragoncompliance_feed['unchecked'] ?? array() );
$dragoncompliance_count     = count( $dragoncompliance_unchecked );
?>
<?php if ( $dragoncompliance_count > 0 ) : ?>
	<div class="notice notice-warning inline">
		<p>
			<?php
			printf(
				/* translators: 1: number of components, 2: list of component names. */
				esc_html( _n( '%1$s component could not be checked for vulnerabilities in the last scan, so it is shown as not checked rather than clear: %2$s.', '%1$s components could not be checked for vulnerabilities in the last scan, so they are shown as not checked rather than clear: %2$s.', $dragoncompliance_count, 'dragon-compliance' ) ),
				esc_html( number_format_i18n( $dragoncompliance_count ) ),
				esc_html( implode( wp_get_list_item_separator(), $dragoncompliance_unchecked ) )
			);
			?>
			<?php esc_html_e( 'Their open findings stay open, and the next scan tries again.', 'dragon-compliance' ); ?>
		</p>
	</div>
<?php endif; ?>
