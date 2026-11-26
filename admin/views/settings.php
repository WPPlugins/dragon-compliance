<?php
/**
 * Settings tab.
 *
 * @package DragonCompliance
 * @var array $dragoncompliance_view
 */

defined( 'ABSPATH' ) || exit;

$dragoncompliance_wordfence = 'wordfence' === $dragoncompliance_view['provider'];
?>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'dragoncompliance_save_settings' ); ?>
	<input type="hidden" name="action" value="dragoncompliance_save_settings" />

	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Vulnerability data source', 'dragon-compliance' ); ?></th>
			<td>
				<fieldset>
					<legend class="screen-reader-text"><?php esc_html_e( 'Vulnerability data source', 'dragon-compliance' ); ?></legend>
					<p>
						<label>
							<input type="radio" name="dragoncompliance_feed_provider" value="wpvulnerability" <?php checked( ! $dragoncompliance_wordfence ); ?> />
							<?php esc_html_e( 'WPVulnerability (no account needed)', 'dragon-compliance' ); ?>
						</label>
					</p>
					<p class="description">
						<?php esc_html_e( 'Each scan asks www.wpvulnerability.net about every installed plugin and theme by its slug, and about WordPress core by its version. Your site address is not sent. Answers are kept for 12 hours.', 'dragon-compliance' ); ?>
					</p>
					<p>
						<label>
							<input type="radio" name="dragoncompliance_feed_provider" value="wordfence" <?php checked( $dragoncompliance_wordfence ); ?> />
							<?php esc_html_e( 'Wordfence Intelligence (needs your own free API token)', 'dragon-compliance' ); ?>
						</label>
					</p>
					<p class="description">
						<?php esc_html_e( 'Each scan downloads the whole Wordfence Intelligence Community Edition feed with your token and matches it on your server. Only the token is sent.', 'dragon-compliance' ); ?>
					</p>
				</fieldset>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Wordfence Intelligence API token', 'dragon-compliance' ); ?></th>
			<td>
				<?php if ( $dragoncompliance_view['has_token'] ) : ?>
					<p>
						<span class="dragon-pill dragon-pill--ok"><?php esc_html_e( 'Saved', 'dragon-compliance' ); ?></span>
						<?php esc_html_e( 'A token is configured (stored encrypted).', 'dragon-compliance' ); ?>
					</p>
					<label>
						<input type="checkbox" name="dragoncompliance_clear_token" value="1" />
						<?php esc_html_e( 'Remove the stored token', 'dragon-compliance' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'Enter a new token below to replace the stored one.', 'dragon-compliance' ); ?></p>
				<?php elseif ( $dragoncompliance_wordfence ) : ?>
					<p>
						<span class="dragon-pill dragon-pill--warning"><?php esc_html_e( 'Missing', 'dragon-compliance' ); ?></span>
						<?php esc_html_e( 'Wordfence Intelligence is selected but no token is saved, so scans cannot fetch vulnerability data.', 'dragon-compliance' ); ?>
					</p>
				<?php endif; ?>
				<input type="password" class="regular-text" name="dragoncompliance_api_token" value="" autocomplete="off" />
				<p class="description">
					<?php esc_html_e( 'Only needed for the Wordfence source. Create a free wordfence.com account, then generate a token under Dashboard → Integrations.', 'dragon-compliance' ); ?>
				</p>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_html_e( 'Vulnerability alerts', 'dragon-compliance' ); ?></th>
			<td>
				<label>
					<input type="checkbox" name="dragoncompliance_alert_enabled" value="1" <?php checked( $dragoncompliance_view['alert_enabled'] ); ?> />
					<?php esc_html_e( 'Send an email when a new critical vulnerability, or one whose severity has not been published, is detected', 'dragon-compliance' ); ?>
				</label>
			</td>
		</tr>
		<tr>
			<th scope="row"><label for="dragoncompliance-alert-recipients"><?php esc_html_e( 'Alert recipients', 'dragon-compliance' ); ?></label></th>
			<td>
				<textarea name="dragoncompliance_alert_recipients" id="dragoncompliance-alert-recipients" class="large-text code" rows="3" autocomplete="off" spellcheck="false" placeholder="<?php echo esc_attr( $dragoncompliance_view['admin_email'] ); ?>"><?php echo esc_textarea( $dragoncompliance_view['recipients'] ); ?></textarea>
				<p class="description">
					<?php
					printf(
						/* translators: 1: the site admin email address, 2: the largest number of addresses accepted. */
						esc_html__( 'Email addresses, one per line or separated by commas. Leave empty to send alerts to the site admin (%1$s). Up to %2$s addresses; each gets its own email.', 'dragon-compliance' ),
						esc_html( $dragoncompliance_view['admin_email'] ),
						esc_html( number_format_i18n( \DragonCompliance\Alerts::MAX_RECIPIENTS ) )
					);
					?>
				</p>
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
