<?php
/**
 * License upsell (shown when Pro is not active).
 *
 * @package DragonCompliance
 */

defined( 'ABSPATH' ) || exit;

$dragoncompliance_pro_installed = class_exists( 'DragonCompliancePro\Plugin' );
?>
<div class="dragoncompliance-license-upsell">
	<?php if ( $dragoncompliance_pro_installed ) : ?>
		<div class="notice notice-warning inline">
			<p>
				<strong><?php esc_html_e( 'Pro installed', 'dragon-compliance' ); ?></strong><br />
				<?php esc_html_e( 'Dragon Compliance Pro is installed. Enter your license key in the Pro settings to activate it.', 'dragon-compliance' ); ?>
			</p>
		</div>
	<?php else : ?>
		<div class="dragoncompliance-card">
			<h2><?php esc_html_e( 'Unlock Dragon Compliance Pro', 'dragon-compliance' ); ?></h2>
			<ul>
				<li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Client-ready, white-label scheduled compliance reports', 'dragon-compliance' ); ?></li>
				<li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'SBOM snapshots with diffs, plus SPDX 2.3 export', 'dragon-compliance' ); ?></li>
				<li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Tamper-evident hash-chained evidence log with CSV export', 'dragon-compliance' ); ?></li>
				<li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Time-to-patch metrics that prove updates happen without delay', 'dragon-compliance' ); ?></li>
				<li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Alert routing: multiple recipients, signed webhooks, Slack', 'dragon-compliance' ); ?></li>
				<li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'NIS2 Article 21 mapping view', 'dragon-compliance' ); ?></li>
				<li><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Priority support', 'dragon-compliance' ); ?></li>
			</ul>
			<a href="https://dragoncore.ltd/plugins/dragon-compliance-pro" class="button button-primary button-hero" target="_blank" rel="noopener noreferrer">
				<?php esc_html_e( 'Get Dragon Compliance Pro', 'dragon-compliance' ); ?>
			</a>
		</div>
	<?php endif; ?>
</div>
