<?php
/**
 * Inventory & SBOM tab.
 *
 * @package DragonCompliance
 * @var array $dragoncompliance_view
 */

defined( 'ABSPATH' ) || exit;

$dragoncompliance_env = $dragoncompliance_view['environment'];
?>

<p>
	<a href="<?php echo esc_url( $dragoncompliance_view['export_url'] ); ?>" class="button button-primary">
		<?php esc_html_e( 'Download SBOM (CycloneDX JSON)', 'dragon-compliance' ); ?>
	</a>
	<?php foreach ( $dragoncompliance_view['formats'] as $dragoncompliance_format ) : ?>
		<a href="<?php echo esc_url( (string) ( $dragoncompliance_format['url'] ?? '' ) ); ?>" class="button">
			<?php echo esc_html( (string) ( $dragoncompliance_format['label'] ?? '' ) ); ?>
		</a>
	<?php endforeach; ?>
</p>

<h2><?php esc_html_e( 'Environment', 'dragon-compliance' ); ?></h2>
<table class="widefat striped dragoncompliance-env">
	<tbody>
		<tr><td><?php esc_html_e( 'WordPress', 'dragon-compliance' ); ?></td><td><?php echo esc_html( (string) $dragoncompliance_env['wp_version'] ); ?></td></tr>
		<tr><td><?php esc_html_e( 'PHP', 'dragon-compliance' ); ?></td><td><?php echo esc_html( (string) $dragoncompliance_env['php'] ); ?></td></tr>
		<tr><td><?php esc_html_e( 'Database', 'dragon-compliance' ); ?></td><td><?php echo esc_html( (string) $dragoncompliance_env['db_version'] ); ?></td></tr>
		<tr><td><?php esc_html_e( 'Web server', 'dragon-compliance' ); ?></td><td><?php echo esc_html( (string) $dragoncompliance_env['web_server'] ); ?></td></tr>
		<tr><td><?php esc_html_e( 'HTTPS', 'dragon-compliance' ); ?></td><td><?php echo $dragoncompliance_env['https'] ? esc_html__( 'Yes', 'dragon-compliance' ) : esc_html__( 'No', 'dragon-compliance' ); ?></td></tr>
	</tbody>
</table>

<h2><?php esc_html_e( 'Components', 'dragon-compliance' ); ?></h2>
<table class="widefat striped">
	<thead>
		<tr>
			<th scope="col"><?php esc_html_e( 'Type', 'dragon-compliance' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Name', 'dragon-compliance' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Slug', 'dragon-compliance' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Version', 'dragon-compliance' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Author', 'dragon-compliance' ); ?></th>
			<th scope="col"><?php esc_html_e( 'License', 'dragon-compliance' ); ?></th>
			<th scope="col"><?php esc_html_e( 'Active', 'dragon-compliance' ); ?></th>
			<?php if ( array() !== $dragoncompliance_view['checks'] ) : ?>
				<th scope="col"><?php esc_html_e( 'Vulnerability check', 'dragon-compliance' ); ?></th>
			<?php endif; ?>
		</tr>
	</thead>
	<tbody>
		<?php if ( empty( $dragoncompliance_view['components'] ) ) : ?>
			<tr>
				<td colspan="<?php echo esc_attr( array() !== $dragoncompliance_view['checks'] ? '8' : '7' ); ?>">
					<?php esc_html_e( 'No inventory yet - run your first scan from the Dashboard tab to record what this site is running.', 'dragon-compliance' ); ?>
				</td>
			</tr>
		<?php endif; ?>
		<?php foreach ( $dragoncompliance_view['components'] as $dragoncompliance_component ) : ?>
			<tr>
				<td><?php echo esc_html( \DragonCompliance\Labels::component_type( (string) $dragoncompliance_component['type'] ) ); ?></td>
				<td><?php echo esc_html( (string) $dragoncompliance_component['name'] ); ?></td>
				<td><code><?php echo esc_html( (string) $dragoncompliance_component['slug'] ); ?></code></td>
				<td><?php echo esc_html( (string) $dragoncompliance_component['version'] ); ?></td>
				<td><?php echo esc_html( wp_strip_all_tags( (string) $dragoncompliance_component['author'] ) ); ?></td>
				<td><?php echo esc_html( (string) $dragoncompliance_component['license'] ); ?></td>
				<td><?php echo $dragoncompliance_component['active'] ? esc_html__( 'Yes', 'dragon-compliance' ) : esc_html__( 'No', 'dragon-compliance' ); ?></td>
				<?php if ( array() !== $dragoncompliance_view['checks'] ) : ?>
					<?php $dragoncompliance_check = (string) ( $dragoncompliance_view['checks'][ $dragoncompliance_component['type'] . '|' . $dragoncompliance_component['slug'] ] ?? '' ); ?>
					<td>
						<?php if ( 'checked' === $dragoncompliance_check ) : ?>
							<span class="dragon-pill dragon-pill--ok"><?php esc_html_e( 'Checked', 'dragon-compliance' ); ?></span>
						<?php elseif ( 'not_listed' === $dragoncompliance_check ) : ?>
							<span class="dragon-pill dragon-pill--ok"><?php esc_html_e( 'Checked - not in the database', 'dragon-compliance' ); ?></span>
						<?php elseif ( 'not_checked' === $dragoncompliance_check ) : ?>
							<span class="dragon-pill dragon-pill--warning"><?php esc_html_e( 'Not checked', 'dragon-compliance' ); ?></span>
						<?php elseif ( 'pending' === $dragoncompliance_check ) : ?>
							<span class="dragon-pill dragon-pill--muted"><?php esc_html_e( 'Not checked yet', 'dragon-compliance' ); ?></span>
						<?php else : ?>
							<span class="dragon-pill dragon-pill--muted"><?php esc_html_e( 'No scan yet', 'dragon-compliance' ); ?></span>
						<?php endif; ?>
					</td>
				<?php endif; ?>
			</tr>
		<?php endforeach; ?>
	</tbody>
</table>
