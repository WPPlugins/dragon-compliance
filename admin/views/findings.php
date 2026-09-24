<?php
/**
 * Findings tab.
 *
 * @package DragonCompliance
 * @var array $dragoncompliance_view
 */

defined( 'ABSPATH' ) || exit;
?>

<?php if ( ! $dragoncompliance_view['feed']['has_token'] ) : ?>
	<div class="notice notice-warning inline">
		<p><?php esc_html_e( 'Add your free Wordfence Intelligence API token under Settings to activate vulnerability monitoring.', 'dragon-compliance' ); ?></p>
	</div>
<?php elseif ( $dragoncompliance_view['feed']['no_data'] ) : ?>
	<div class="notice notice-warning inline">
		<p>
			<?php esc_html_e( 'No vulnerability data has been downloaded yet, so these results are not complete. Run a scan to fetch the feed.', 'dragon-compliance' ); ?>
			<?php if ( $dragoncompliance_view['feed']['error'] ) : ?>
				<?php
				printf(
					/* translators: %s: error message. */
					esc_html__( 'Last attempt failed: %s', 'dragon-compliance' ),
					esc_html( $dragoncompliance_view['feed']['error']['message'] )
				);
				?>
			<?php endif; ?>
		</p>
	</div>
<?php endif; ?>

<?php if ( array() === $dragoncompliance_view['findings'] ) : ?>
	<p><?php esc_html_e( 'No findings recorded. That is a good thing - keep the daily scan running.', 'dragon-compliance' ); ?></p>
<?php else : ?>
	<table class="widefat striped">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Severity', 'dragon-compliance' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Component', 'dragon-compliance' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Vulnerability', 'dragon-compliance' ); ?></th>
				<th scope="col"><?php esc_html_e( 'CVE', 'dragon-compliance' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Detected', 'dragon-compliance' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'dragon-compliance' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Action', 'dragon-compliance' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $dragoncompliance_view['findings'] as $dragoncompliance_finding ) : ?>
				<tr>
					<td>
						<span class="dragoncompliance-badge dragoncompliance-badge-<?php echo esc_attr( (string) $dragoncompliance_finding['severity'] ); ?>">
							<?php echo esc_html( \DragonCompliance\Labels::severity( (string) $dragoncompliance_finding['severity'] ) ); ?>
						</span>
						<?php if ( $dragoncompliance_finding['cvss'] > 0 ) : ?>
							<small><?php echo esc_html( number_format_i18n( (float) $dragoncompliance_finding['cvss'], 1 ) ); ?></small>
						<?php endif; ?>
					</td>
					<td>
						<?php
						printf(
							/* translators: 1: component slug, 2: component version. */
							esc_html__( '%1$s @ %2$s', 'dragon-compliance' ),
							'<code>' . esc_html( (string) $dragoncompliance_finding['component_slug'] ) . '</code>',
							esc_html( (string) $dragoncompliance_finding['component_version'] )
						);
						?>
					</td>
					<td><?php echo esc_html( (string) $dragoncompliance_finding['title'] ); ?></td>
					<td>
						<?php if ( '' !== (string) $dragoncompliance_finding['cve'] ) : ?>
							<a href="<?php echo esc_url( 'https://www.cve.org/CVERecord?id=' . rawurlencode( (string) $dragoncompliance_finding['cve'] ) ); ?>" target="_blank" rel="noopener noreferrer">
								<?php echo esc_html( (string) $dragoncompliance_finding['cve'] ); ?>
							</a>
						<?php else : ?>
							&mdash;
						<?php endif; ?>
					</td>
					<td><?php echo esc_html( \DragonCompliance\Labels::datetime( (string) $dragoncompliance_finding['detected_at'] ) ); ?></td>
					<td><?php echo esc_html( \DragonCompliance\Labels::finding_status( (string) $dragoncompliance_finding['status'] ) ); ?></td>
					<td>
						<?php if ( in_array( $dragoncompliance_finding['status'], array( 'open', 'ignored' ), true ) ) : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
								<?php wp_nonce_field( 'dragoncompliance_finding_status' ); ?>
								<input type="hidden" name="action" value="dragoncompliance_finding_status" />
								<input type="hidden" name="finding_id" value="<?php echo esc_attr( (string) $dragoncompliance_finding['id'] ); ?>" />
								<?php if ( 'open' === $dragoncompliance_finding['status'] ) : ?>
									<input type="hidden" name="ignore" value="1" />
									<button type="submit" class="button button-small"><?php esc_html_e( 'Ignore', 'dragon-compliance' ); ?></button>
								<?php else : ?>
									<button type="submit" class="button button-small"><?php esc_html_e( 'Unignore', 'dragon-compliance' ); ?></button>
								<?php endif; ?>
							</form>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
<?php endif; ?>

<p class="description dragoncompliance-attribution">
	<?php
	printf(
		/* translators: 1: opening link tag to the Wordfence Intelligence license, 2: closing link tag, 3: opening link tag to the MITRE CVE terms, 4: closing link tag. */
		esc_html__( 'Vulnerability data © Defiant Inc., provided via Wordfence Intelligence and used under its %1$sCommunity Edition license%2$s. CVE records © The MITRE Corporation, used under the %3$sCVE Terms of Use%4$s.', 'dragon-compliance' ),
		'<a href="https://www.wordfence.com/wti-community-edition-terms-and-conditions/" target="_blank" rel="noopener noreferrer">',
		'</a>',
		'<a href="https://www.cve.org/Legal/TermsOfUse" target="_blank" rel="noopener noreferrer">',
		'</a>'
	);
	?>
</p>
