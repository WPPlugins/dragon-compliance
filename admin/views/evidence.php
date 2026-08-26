<?php
/**
 * Evidence tab.
 *
 * @package DragonCompliance
 * @var array $dragoncompliance_view
 */

defined( 'ABSPATH' ) || exit;

$dragoncompliance_pages = (int) ceil( $dragoncompliance_view['total'] / $dragoncompliance_view['per_page'] );
?>

<p>
	<?php
	printf(
		/* translators: %d: number of events. */
		esc_html__( '%d evidence entries. Every scan, detection, resolution and attestation is recorded here with a timestamp.', 'dragon-compliance' ),
		(int) $dragoncompliance_view['total']
	);
	?>
</p>

<table class="widefat striped">
	<thead>
		<tr>
			<th scope="col"><?php esc_html_e( 'ID', 'dragon-compliance' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Event', 'dragon-compliance' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Detail', 'dragon-compliance' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Recorded (UTC)', 'dragon-compliance' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Sealed', 'dragon-compliance' ); ?></th>
		</tr>
	</thead>
	<tbody>
		<?php if ( empty( $dragoncompliance_view['events'] ) ) : ?>
			<tr>
				<td colspan="5">
					<?php esc_html_e( 'Nothing recorded yet. Evidence entries appear automatically as scans run and findings change.', 'dragon-compliance' ); ?>
				</td>
			</tr>
		<?php endif; ?>
		<?php foreach ( $dragoncompliance_view['events'] as $dragoncompliance_event ) : ?>
			<tr>
				<td><?php echo esc_html( (string) $dragoncompliance_event['id'] ); ?></td>
				<td><code><?php echo esc_html( (string) $dragoncompliance_event['event_type'] ); ?></code></td>
				<td><code class="dragoncompliance-payload"><?php echo esc_html( (string) wp_json_encode( $dragoncompliance_event['payload'] ) ); ?></code></td>
				<td><?php echo esc_html( (string) $dragoncompliance_event['created_at'] ); ?></td>
				<td><?php echo null !== $dragoncompliance_event['hash'] ? '&#128274;' : '&mdash;'; ?></td>
			</tr>
		<?php endforeach; ?>
	</tbody>
</table>

<?php if ( $dragoncompliance_pages > 1 ) : ?>
	<p class="dragoncompliance-pagination">
		<?php for ( $dragoncompliance_i = 1; $dragoncompliance_i <= $dragoncompliance_pages; $dragoncompliance_i++ ) : ?>
			<?php if ( $dragoncompliance_i === $dragoncompliance_view['paged'] ) : ?>
				<span class="dragoncompliance-page-current"><?php echo esc_html( (string) $dragoncompliance_i ); ?></span>
			<?php else : ?>
				<a href="<?php echo esc_url( admin_url( 'tools.php?page=dragon-compliance&tab=evidence&paged=' . $dragoncompliance_i ) ); ?>"><?php echo esc_html( (string) $dragoncompliance_i ); ?></a>
			<?php endif; ?>
		<?php endfor; ?>
	</p>
<?php endif; ?>
