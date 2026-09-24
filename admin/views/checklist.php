<?php
/**
 * Checklist tab.
 *
 * @package DragonCompliance
 * @var array $dragoncompliance_view
 */

defined( 'ABSPATH' ) || exit;

$dragoncompliance_auto   = array_filter(
	$dragoncompliance_view['items'],
	static function ( array $item ): bool {
		return 'auto' === $item['type'];
	}
);
$dragoncompliance_manual = array_filter(
	$dragoncompliance_view['items'],
	static function ( array $item ): bool {
		return 'manual' === $item['type'];
	}
);
?>

<p>
	<?php
	printf(
		/* translators: 1: readiness percentage, 2: number of checks satisfied, 3: total number of checks. */
		esc_html( _n( 'Readiness: %1$s%% (%2$s of %3$s check satisfied).', 'Readiness: %1$s%% (%2$s of %3$s checks satisfied).', (int) $dragoncompliance_view['score']['total'], 'dragon-compliance' ) ),
		esc_html( number_format_i18n( (int) $dragoncompliance_view['score']['percent'] ) ),
		esc_html( number_format_i18n( (int) $dragoncompliance_view['score']['passed'] ) ),
		esc_html( number_format_i18n( (int) $dragoncompliance_view['score']['total'] ) )
	);
	?>
</p>

<h2><?php esc_html_e( 'Automatic checks', 'dragon-compliance' ); ?></h2>
<table class="widefat striped">
	<tbody>
		<?php foreach ( $dragoncompliance_auto as $dragoncompliance_item ) : ?>
			<tr>
				<td class="dragoncompliance-state-cell">
					<span class="dragoncompliance-state dragoncompliance-state-<?php echo esc_attr( $dragoncompliance_item['state'] ); ?>">
						<?php echo 'pass' === $dragoncompliance_item['state'] ? '&#10003;' : '&#10007;'; ?>
					</span>
				</td>
				<td>
					<strong><?php echo esc_html( $dragoncompliance_item['label'] ); ?></strong>
					<p class="description"><?php echo esc_html( $dragoncompliance_item['description'] ); ?></p>
				</td>
				<td><?php echo esc_html( $dragoncompliance_item['detail'] ); ?></td>
			</tr>
		<?php endforeach; ?>
	</tbody>
</table>

<h2><?php esc_html_e( 'Attestations', 'dragon-compliance' ); ?></h2>
<p class="description"><?php esc_html_e( 'These are process facts the plugin cannot detect. Attesting them records a timestamped evidence entry.', 'dragon-compliance' ); ?></p>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'dragoncompliance_save_attestations' ); ?>
	<input type="hidden" name="action" value="dragoncompliance_save_attestations" />
	<table class="widefat striped">
		<tbody>
			<?php foreach ( $dragoncompliance_manual as $dragoncompliance_item ) : ?>
				<tr>
					<td class="dragoncompliance-state-cell">
						<label>
							<input type="checkbox" name="dragoncompliance_attested[<?php echo esc_attr( $dragoncompliance_item['id'] ); ?>]" value="1" <?php checked( 'attested', $dragoncompliance_item['state'] ); ?> />
						</label>
					</td>
					<td>
						<strong><?php echo esc_html( $dragoncompliance_item['label'] ); ?></strong>
						<p class="description"><?php echo esc_html( $dragoncompliance_item['description'] ); ?></p>
					</td>
					<td>
						<label class="screen-reader-text" for="dragoncompliance-note-<?php echo esc_attr( $dragoncompliance_item['id'] ); ?>"><?php esc_html_e( 'Note for this checklist item', 'dragon-compliance' ); ?></label>
						<input type="text" class="regular-text" id="dragoncompliance-note-<?php echo esc_attr( $dragoncompliance_item['id'] ); ?>" name="dragoncompliance_note[<?php echo esc_attr( $dragoncompliance_item['id'] ); ?>]" value="<?php echo esc_attr( $dragoncompliance_item['detail'] ); ?>" placeholder="<?php esc_attr_e( 'Note (where is it documented?)', 'dragon-compliance' ); ?>" />
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
	<p><button type="submit" class="button button-primary"><?php esc_html_e( 'Save attestations', 'dragon-compliance' ); ?></button></p>
</form>
