<?php
/**
 * Settings tab.
 *
 * @package DragonCompliance
 * @var array $dragoncompliance_view
 */

defined( 'ABSPATH' ) || exit;
?>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'dragoncompliance_save_settings' ); ?>
	<input type="hidden" name="action" value="dragoncompliance_save_settings" />

	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Wordfence Intelligence API token', 'dragon-compliance' ); ?></th>
			<td>
				<?php if ( $dragoncompliance_view['proxied'] ) : ?>
					<p>
						<span class="dragoncompliance-state dragoncompliance-state-pass">&#10003;</span>
						<?php esc_html_e( 'The vulnerability feed is provided by your Dragon Compliance Pro licence — no Wordfence token is needed. A token entered here is kept as a fallback.', 'dragon-compliance' ); ?>
					</p>
				<?php endif; ?>
				<?php if ( $dragoncompliance_view['has_token'] ) : ?>
					<p>
						<span class="dragoncompliance-state dragoncompliance-state-pass">&#10003;</span>
						<?php esc_html_e( 'A token is configured (stored encrypted).', 'dragon-compliance' ); ?>
					</p>
					<label>
						<input type="checkbox" name="dragoncompliance_clear_token" value="1" />
						<?php esc_html_e( 'Remove the stored token', 'dragon-compliance' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'Enter a new token below to replace the stored one.', 'dragon-compliance' ); ?></p>
				<?php endif; ?>
				<input type="password" class="regular-text" name="dragoncompliance_api_token" value="" autocomplete="off" />
				<p class="description">
					<?php esc_html_e( 'Vulnerability data comes from the free Wordfence Intelligence Community Edition feed. Create a free wordfence.com account, then generate a token under Dashboard → Integrations.', 'dragon-compliance' ); ?>
				</p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Critical alerts', 'dragon-compliance' ); ?></th>
			<td>
				<label>
					<input type="checkbox" name="dragoncompliance_alert_enabled" value="1" <?php checked( $dragoncompliance_view['alert_enabled'] ); ?> />
					<?php esc_html_e( 'Email the site admin when a new critical vulnerability is detected', 'dragon-compliance' ); ?>
				</label>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Delete data on uninstall', 'dragon-compliance' ); ?></th>
			<td>
				<label>
					<input type="checkbox" name="dragoncompliance_delete_data_on_uninstall" value="1" <?php checked( get_option( 'dragoncompliance_delete_data_on_uninstall' ) ); ?> />
					<?php esc_html_e( 'Remove all settings, findings and the evidence log when the plugin is deleted. Leave off to keep your compliance trail through a reinstall.', 'dragon-compliance' ); ?>
				</label>
			</td>
		</tr>
	</table>

	<p><button type="submit" class="button button-primary"><?php esc_html_e( 'Save settings', 'dragon-compliance' ); ?></button></p>
</form>
