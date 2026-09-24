<?php
/**
 * Dashboard tab.
 *
 * @package DragonCompliance
 * @var array $dragoncompliance_view
 */

defined( 'ABSPATH' ) || exit;

$dragoncompliance_score  = $dragoncompliance_view['score'];
$dragoncompliance_sev    = $dragoncompliance_view['by_severity'];
$dragoncompliance_counts = $dragoncompliance_view['counts'];
$dragoncompliance_feed   = $dragoncompliance_view['feed'];
?>

<?php if ( ! $dragoncompliance_feed['has_token'] ) : ?>
	<div class="notice notice-warning">
		<p>
			<?php esc_html_e( 'Vulnerability monitoring is not active yet: add your free Wordfence Intelligence API token under Settings.', 'dragon-compliance' ); ?>
		</p>
	</div>
<?php elseif ( $dragoncompliance_feed['no_data'] ) : ?>
	<div class="notice notice-warning">
		<p>
			<?php esc_html_e( 'Vulnerability monitoring is configured but no vulnerability data has been downloaded yet, so nothing has been checked. The feed is fetched by the daily scan - or press "Scan now".', 'dragon-compliance' ); ?>
			<?php if ( $dragoncompliance_feed['error'] ) : ?>
				<br />
				<?php
				printf(
					/* translators: %s: error message. */
					esc_html__( 'Last attempt failed: %s', 'dragon-compliance' ),
					esc_html( $dragoncompliance_feed['error']['message'] )
				);
				?>
			<?php endif; ?>
		</p>
	</div>
<?php elseif ( $dragoncompliance_feed['stale'] ) : ?>
	<div class="notice notice-warning">
		<p>
			<?php
			printf(
				/* translators: %s: human-readable age. */
				esc_html__( 'Vulnerability data is stale - last refreshed %s ago.', 'dragon-compliance' ),
				esc_html( human_time_diff( time() - (int) $dragoncompliance_feed['age'] ) )
			);
			if ( $dragoncompliance_feed['error'] ) {
				echo '<br />';
				printf(
					/* translators: %s: error message. */
					esc_html__( 'Last attempt failed: %s', 'dragon-compliance' ),
					esc_html( $dragoncompliance_feed['error']['message'] )
				);
			}
			?>
		</p>
	</div>
<?php endif; ?>

<div class="dragoncompliance-cards">
	<div class="dragoncompliance-card">
		<h2><?php esc_html_e( 'Readiness score', 'dragon-compliance' ); ?></h2>
		<p class="dragoncompliance-big">
			<?php
			printf(
				/* translators: %s: readiness percentage. */
				esc_html__( '%s%%', 'dragon-compliance' ),
				esc_html( number_format_i18n( (int) $dragoncompliance_score['percent'] ) )
			);
			?>
		</p>
		<p>
			<?php
			printf(
				/* translators: 1: number of checks satisfied, 2: total number of checks. */
				esc_html( _n( '%1$s of %2$s check satisfied', '%1$s of %2$s checks satisfied', (int) $dragoncompliance_score['total'], 'dragon-compliance' ) ),
				esc_html( number_format_i18n( (int) $dragoncompliance_score['passed'] ) ),
				esc_html( number_format_i18n( (int) $dragoncompliance_score['total'] ) )
			);
			?>
		</p>
	</div>
	<div class="dragoncompliance-card">
		<h2><?php esc_html_e( 'Open findings', 'dragon-compliance' ); ?></h2>
		<p class="dragoncompliance-big"><?php echo esc_html( number_format_i18n( (int) ( $dragoncompliance_counts['open'] ?? 0 ) ) ); ?></p>
		<p>
			<?php foreach ( array( 'critical', 'high', 'medium', 'low', 'unknown' ) as $dragoncompliance_level ) : ?>
				<?php if ( ! empty( $dragoncompliance_sev[ $dragoncompliance_level ] ) ) : ?>
					<span class="dragoncompliance-badge dragoncompliance-badge-<?php echo esc_attr( $dragoncompliance_level ); ?>">
						<?php
						printf(
							/* translators: 1: severity label, 2: number of open findings. */
							esc_html__( '%1$s: %2$s', 'dragon-compliance' ),
							esc_html( \DragonCompliance\Labels::severity( $dragoncompliance_level ) ),
							esc_html( number_format_i18n( (int) $dragoncompliance_sev[ $dragoncompliance_level ] ) )
						);
						?>
					</span>
				<?php endif; ?>
			<?php endforeach; ?>
		</p>
	</div>
	<div class="dragoncompliance-card">
		<h2><?php esc_html_e( 'Monitoring', 'dragon-compliance' ); ?></h2>
		<p>
			<?php if ( $dragoncompliance_view['last_scan'] > 0 ) : ?>
				<?php
				printf(
					/* translators: %s: human-readable age. */
					esc_html__( 'Last scan: %s ago.', 'dragon-compliance' ),
					esc_html( human_time_diff( $dragoncompliance_view['last_scan'] ) )
				);
				?>
			<?php else : ?>
				<?php esc_html_e( 'No scan has run yet.', 'dragon-compliance' ); ?>
			<?php endif; ?>
		</p>
		<p>
			<?php if ( null !== $dragoncompliance_feed['age'] ) : ?>
				<?php
				printf(
					/* translators: %s: human-readable age. */
					esc_html__( 'Vulnerability data age: %s.', 'dragon-compliance' ),
					esc_html( human_time_diff( time() - (int) $dragoncompliance_feed['age'] ) )
				);
				?>
			<?php endif; ?>
		</p>
		<p>
			<button type="button" class="button button-primary" id="dragoncompliance-scan-now">
				<?php esc_html_e( 'Scan now', 'dragon-compliance' ); ?>
			</button>
			<span id="dragoncompliance-scan-result" role="status"></span>
		</p>
	</div>
</div>
