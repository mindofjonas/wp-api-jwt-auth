<h2><?php _e( 'API Tokens', 'jwt-auth' ); ?></h2>
<table class="table widefat striped">
	<thead>
		<tr>
			<th><?php _e( 'Token UUID', 'jwt-auth' ); ?></th>
			<th><?php _e( 'Expires', 'jwt-auth' ); ?></th>
			<th><?php _e( 'Last used', 'jwt-auth' ); ?></th>
			<th><?php _e( 'By IP', 'jwt-auth' ); ?></th>
			<th><?php _e( 'Browser', 'jwt-auth' ); ?></th>
			<th></th>
		</tr>
	</thead>
	<tbody>
		<?php if ( ! empty( $tokens ) ) : ?>
			<?php foreach( $tokens as $token ) : ?>
				<?php
				$ua_info = parse_user_agent( $token['ua'] );
				$revoke_url = home_url() . add_query_arg( array(
					'revoke_token' => $token['uuid'],
				) );
				?>
				<tr>
					<td><?php echo $token['uuid']; ?></td>
					<td><?php echo date_i18n( 'Y-m-d H:i:s', $token['expires'] ); ?></td>
					<td><?php echo date_i18n( 'Y-m-d H:i:s', $token['last_used'] ); ?></td>
					<td><?php echo $token['ip']; ?> <a href="<?php echo sprintf( 'https://ipinfo.io/%s', $token['ip'] ); ?>" target="_blank" title="Look up IP location" class="button-link"><?php _e( 'Lookup', 'jwt-auth' ); ?></a></td>
					<td><?php echo sprintf( __( '<strong>Platform</strong> %s. <strong>Browser:</strong> %s. <strong>Browser version:</strong> %s', 'jwt-auth' ), $ua_info['platform'], $ua_info['browser'], $ua_info['version'] ); ?></td>
					<td>
						<a href="<?php echo $revoke_url; ?>" title="<?php _e( 'Revokes this token from being used any further.', 'jwt-auth' ); ?>" class="button-secondary"><?php _e( 'Revoke', 'jwt-auth' ); ?></a>
					</td>
				</tr>
			<?php endforeach; ?>
			<tr>
				<td colspan="6" align="right">
					<a href="<?php echo home_url() . add_query_arg( 'revoke_all_tokens', '1' ); ?>" class="button-secondary" title="<?php _e( 'Doing this will require the user to login again on all devices.', 'jwt-auth' ); ?>"><?php _e( 'Revoke all tokens', 'jwt-auth' ); ?></a>
					<a href="<?php echo home_url() . add_query_arg( 'remove_expired_tokens', '1' ); ?>" class="button-secondary" title="<?php _e( 'Doing this will not affect logged in devices for this user.', 'jwt-auth' ); ?>"><?php _e( 'Remove all expired tokens', 'jwt-auth' ); ?></a>
				</td>
			</tr>
		<?php else : ?>
			<tr>
				<td><?php _e( 'No tokens generated.', 'jwt-auth' ); ?></td>
			</tr>
		<?php endif; ?>
	</tbody>
</table>
