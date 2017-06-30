<?php

/** Requiere the JWT library. */
use \Firebase\JWT\JWT;

/**
 * The public-facing functionality of the plugin.
 *
 * @link       https://enriquechavez.co
 * @since      1.0.0
 */

/**
 * The public-facing functionality of the plugin.
 *
 * Defines the plugin name, version, and two examples hooks for how to
 * enqueue the admin-specific stylesheet and JavaScript.
 *
 * @author     Enrique Chavez <noone@tmeister.net>
 */
class Jwt_Auth_Public
{
    /**
     * The ID of this plugin.
     *
     * @since    1.0.0
     *
     * @var string The ID of this plugin.
     */
    private $plugin_name;

    /**
     * The version of this plugin.
     *
     * @since    1.0.0
     *
     * @var string The current version of this plugin.
     */
    private $version;

    /**
     * The namespace to add to the api calls.
     *
     * @var string The namespace to add to the api call
     */
    private $namespace;

    /**
     * Store errors to display if the JWT is wrong
     *
     * @var WP_Error
     */
    private $jwt_error = null;

    /**
     * Initialize the class and set its properties.
     *
     * @since    1.0.0
     *
     * @param string $plugin_name The name of the plugin.
     * @param string $version     The version of this plugin.
     */
    public function __construct($plugin_name, $version)
    {
        $this->plugin_name = $plugin_name;
        $this->version = $version;
        $this->namespace = $this->plugin_name.'/v'.intval($this->version);
    }

    /**
     * Add the endpoints to the API
     */
    public function add_api_routes()
    {
        register_rest_route($this->namespace, 'token', [
            'methods' => 'POST',
            'callback' => array($this, 'generate_token'),
        ]);

        register_rest_route($this->namespace, 'token/validate', array(
            'methods' => 'POST',
            'callback' => array($this, 'validate_token'),
        ));

        register_rest_route($this->namespace, 'token/revoke', array(
            'methods' => 'POST',
            'callback' => array($this, 'revoke_token'),
        ));

        register_rest_route($this->namespace, 'token/resetpassword', array(
            'methods' => 'POST',
            'callback' => array($this, 'reset_password'),
        ));
    }

    /**
     * Add CORs suppot to the request.
     */
    public function add_cors_support()
    {
        $enable_cors = defined('JWT_AUTH_CORS_ENABLE') ? JWT_AUTH_CORS_ENABLE : false;
        if ($enable_cors) {
            $headers = apply_filters('jwt_auth_cors_allow_headers', 'Access-Control-Allow-Headers, Content-Type, Authorization');
            header(sprintf('Access-Control-Allow-Headers: %s', $headers));
        }
    }

    /**
     * Get the user and password in the request body and generate a JWT
     *
     * @param [type] $request [description]
     *
     * @return [type] [description]
     */
    public function generate_token($request)
    {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        $username = $request->get_param('username');
        $password = $request->get_param('password');

        /** First thing, check the secret key if not exist return a error*/
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        }
        /** Try to authenticate the user with the passed credentials*/
        $user = wp_authenticate($username, $password);

        /** If the authentication fails return a error*/
        if (is_wp_error($user)) {
            $error_code = $user->get_error_code();
            return new WP_Error(
                '[jwt_auth] '.$error_code,
                $user->get_error_message($error_code),
                array(
                    'status' => 403,
                )
            );
        }

        /** Valid credentials, the user exists create the according Token */
        $issuedAt = time();
        $notBefore = apply_filters('jwt_auth_not_before', $issuedAt, $issuedAt);
        $expire = apply_filters('jwt_auth_expire', $issuedAt + (DAY_IN_SECONDS * 7), $issuedAt);

		// Generate UID for this token
		$uuid = wp_generate_uuid4();

        $token = array(
			'uuid' => $uuid,
            'iss' => get_bloginfo('url'),
            'iat' => $issuedAt,
            'nbf' => $notBefore,
            'exp' => $expire,
            'data' => array(
                'user' => array(
                    'id' => $user->data->ID,
                ),
            ),
        );

        /** Let the user modify the token data before the sign. */
        $token = JWT::encode(apply_filters('jwt_auth_token_before_sign', $token, $user), $secret_key);

		$jwt_data = get_user_meta( $user->data->ID, 'jwt_data', true ) ?: array();
		$user_ip = ! empty( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : __( 'Unknown', 'jwt-auth' );
		$jwt_data[] = array(
			'uuid' => $uuid,
			'issued_at' => $issuedAt,
			'expires' => $expire,
			'ip' => $user_ip,
			'ua' => $_SERVER['HTTP_USER_AGENT'],
            'last_used' => time(),
		);
		update_user_meta( $user->data->ID, 'jwt_data', $jwt_data );

        /** The token is signed, now create the object with no sensible user data to the client*/
        $data = array(
            'token' => $token,
			'user_id' => $user->data->ID,
            'user_email' => $user->data->user_email,
            'user_nicename' => $user->data->user_nicename,
            'user_display_name' => $user->data->display_name,
			'token_expires' => $expire,
        );

        /** Let the user modify the data before send it back */
        return apply_filters('jwt_auth_token_before_dispatch', $data, $user);
    }

    /**
     * This is our Middleware to try to authenticate the user according to the
     * token send.
     *
     * @param (int|bool) $user Logged User ID
     *
     * @return (int|bool)
     */
    public function determine_current_user($user)
    {
        /**
         * This hook only should run on the REST API requests to determine
         * if the user in the Token (if any) is valid, for any other
         * normal call ex. wp-admin/.* return the user.
         *
         * @since 1.2.3
         **/
        $rest_api_slug = rest_get_url_prefix();
        $valid_api_uri = strpos($_SERVER['REQUEST_URI'], $rest_api_slug);
        if(!$valid_api_uri){
            return $user;
        }

        /*
         * if the request URI is for validate the token don't do anything,
         * this avoid double calls to the validate_token function.
         */
        $validate_uri = strpos($_SERVER['REQUEST_URI'], 'token/validate');
        if ($validate_uri > 0) {
            return $user;
        }

        $token = $this->validate_token(false);

        if (is_wp_error($token)) {
            if ($token->get_error_code() != 'jwt_auth_no_auth_header') {
                /** If there is a error, store it to show it after see rest_pre_dispatch */
                $this->jwt_error = $token;
                return $user;
            } else {
                return $user;
            }
        }

        /** Everything is ok, return the user ID stored in the token*/
        return $token->data->user->id;
    }

    /**
     * Main validation function, this function try to get the Autentication
     * headers and decoded.
     *
     * @param bool $output
     *
     * @return WP_Error | Object
     */
    public function validate_token($output = true)
    {
        /*
         * Looking for the HTTP_AUTHORIZATION header, if not present just
         * return the user.
         */
        $auth = isset($_SERVER['HTTP_AUTHORIZATION']) ?  $_SERVER['HTTP_AUTHORIZATION'] : false;


        /* Double check for different auth header string (server dependent) */
        if (!$auth) {
            $auth = isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ?  $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : false;
        }

        if (!$auth) {
            return new WP_Error(
                'jwt_auth_no_auth_header',
                __('Authorization header not found.', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        /*
         * The HTTP_AUTHORIZATION is present verify the format
         * if the format is wrong return the user.
         */
        list($token) = sscanf($auth, 'Bearer %s');
        if (!$token) {
            return new WP_Error(
                'jwt_auth_bad_auth_header',
                __('Authorization header malformed.', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        /** Get the Secret Key */
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;
        if (!$secret_key) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __('JWT is not configurated properly, please contact the admin', 'wp-api-jwt-auth'),
                array(
                    'status' => 403,
                )
            );
        }

        /** Try to decode the token */
        try {
            $token = JWT::decode($token, $secret_key, array('HS256'));
            /** The Token is decoded now validate the iss */
            if ($token->iss != get_bloginfo('url')) {
                /** The iss do not match, return error */
                return new WP_Error(
                    'jwt_auth_bad_iss',
                    __('The iss do not match with this server', 'wp-api-jwt-auth'),
                    array(
                        'status' => 403,
                    )
                );
            }
            /** So far so good, validate the user id in the token */
            if (!isset($token->data->user->id)) {
                /** No user id in the token, abort!! */
                return new WP_Error(
                    'jwt_auth_bad_request',
                    __('User ID not found in the token', 'wp-api-jwt-auth'),
                    array(
                        'status' => 403,
                    )
                );
            }

			// Custom validation against an UUID on user meta data.
			$jwt_data = get_user_meta( $token->data->user->id, 'jwt_data', true ) ?: false;
			if ( false === $jwt_data ) {
				return new WP_Error(
	                'jwt_auth_token_revoked',
	                __('Token has been revoked.', 'jwt-auth'),
	                array(
	                    'status' => 403,
	                )
	            );
			}

			/**
			 * Loop through and check wether we have the current token uuid in the users meta.
			 */
			foreach( $jwt_data as $key => $token_data ) {
                if ( $token_data['uuid'] == $token->uuid ) {
                    $user_ip = ! empty( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : __( 'Unknown', 'jwt-auth' );
                    $jwt_data[ $key ]['last_used'] = time();
                    $jwt_data[ $key ]['ua'] = $_SERVER['HTTP_USER_AGENT'];
                    $jwt_data[ $key ]['ip'] = $user_ip;
                    $valid_token = true;
                    break;
                }
                $valid_token = false;
            }

			// Found no valid token. Return error.
			if ( false == $valid_token ) {
				return new WP_Error(
	                'jwt_auth_token_revoked',
	                __('Token has been revoked.', 'jwt-auth'),
	                array(
	                    'status' => 403,
	                )
	            );
			}


            /** Everything looks good return the decoded token if the $output is false */
            if (!$output) {
                return $token;
            }
            /** If the output is true return an answer to the request to show it */
             return array(
                 'code' => 'jwt_auth_valid_token',
                 'data' => array(
                     'status' => 200,
                 ),
             );
         } catch (Exception $e) {
            /** Something is wrong trying to decode the token, send back the error */
             return new WP_Error(
                 'jwt_auth_invalid_token',
                 $e->getMessage(),
                 array(
                     'status' => 403,
                 )
             );
         }
    }


    /**
	 * Check if we should revoke a token.
	 *
	 */
	public function revoke_token( ) {

        $token = $this->validate_token( false );

        if ( is_wp_error( $token ) ) {
            if ($token->get_error_code() != 'jwt_auth_no_auth_header') {
                /** If there is a error, store it to show it after see rest_pre_dispatch */
                $this->jwt_error = $token;
                return false;
            } else {
                return false;
            }
        }

        $tokens = get_user_meta( $token->data->user->id, 'jwt_data', true ) ?: false;
        $token_uuid = $token->uuid;

        if ( $tokens ) {
            foreach ( $tokens as $key => $token_data ) {
                if ( $token_data['uuid'] == $token_uuid ) {
                    unset( $tokens[ $key ] );
                    update_user_meta( $token->data->user->id , 'jwt_data', $tokens );
                    return array(
                        'code' => 'jwt_auth_revoked_token',
                        'data' => array(
                            'status' => 200,
                        ),
                    );
                }
            }
        }

        return array(
            'code' => 'jwt_auth_no_token_to_revoke',
            'data' => array(
                'status' => 403,
            ),
        );

	}


    /**
     * Endpoint for requesting a password reset link.
     * This is a slightly modified version of what WP core uses.
     * @param object $request the request object that come in from WP Rest API.
     */
    public function reset_password( $request ) {
        $username = $request->get_param( 'username' );
        if ( ! $username ) {
            return array(
                'code' => 'jwt_auth_invalid_username',
                'message' => __( '<strong>Error:</strong> Username or email not specified.', 'jwt-auth' ),
                'data' => array(
                    'status' => 403,
                ),
            );
        } elseif ( strpos( $username, '@' ) ) {
            $user_data = get_user_by( 'email', trim( $username ) );
        } else {
            $user_data = get_user_by( 'login', trim( $username ) );
        }

        global $wpdb, $current_site;

        do_action('lostpassword_post');
        if ( !$user_data ) {
            return array(
                'code' => 'jwt_auth_invalid_username',
                'message' => __( '<strong>Error:</strong> Invalid username.', 'jwt-auth' ),
                'data' => array(
                    'status' => 403,
                ),
            );
        }

        // redefining user_login ensures we return the right case in the email
        $user_login = $user_data->user_login;
        $user_email = $user_data->user_email;

        do_action('retreive_password', $user_login);  // Misspelled and deprecated
        do_action('retrieve_password', $user_login);

        $allow = apply_filters('allow_password_reset', true, $user_data->ID);

        if ( ! $allow ) {
            return array(
                'code' => 'jwt_auth_reset_password_not_allowed',
                'message' => __( '<strong>Error:</strong> Resetting password is not allowed.', 'jwt-auth' ),
                'data' => array(
                    'status' => 403,
                ),
            );
        } else if ( is_wp_error( $allow ) ) {
            return array(
                'code' => 'jwt_auth_reset_password_not_allowed',
                'message' => __( '<strong>Error:</strong> Resetting password is not allowed.', 'jwt-auth' ),
                'data' => array(
                    'status' => 403,
                ),
            );
        }

        $key = $wpdb->get_var($wpdb->prepare("SELECT user_activation_key FROM $wpdb->users WHERE user_login = %s", $user_login));
        if ( empty($key) ) {
            // Generate something random for a key...
            $key = wp_generate_password(20, false);
            do_action('retrieve_password_key', $user_login, $key);
            // Now insert the new md5 key into the db
            $wpdb->update($wpdb->users, array('user_activation_key' => $key), array('user_login' => $user_login));
        }
        $message = __('Someone requested that the password be reset for the following account:') . "\r\n\r\n";
        $message .= network_home_url( '/' ) . "\r\n\r\n";
        $message .= sprintf(__('Username: %s'), $user_login) . "\r\n\r\n";
        $message .= __('If this was a mistake, just ignore this email and nothing will happen.') . "\r\n\r\n";
        $message .= __('To reset your password, visit the following address:') . "\r\n\r\n";
        $message .= '<' . network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($user_login), 'login') . ">\r\n";

        if ( is_multisite() )
            $blogname = $GLOBALS['current_site']->site_name;
        else
            // The blogname option is escaped with esc_html on the way into the database in sanitize_option
            // we want to reverse this for the plain text arena of emails.
            $blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);

        $title = sprintf( __('[%s] Password Reset'), $blogname );

        $title = apply_filters('retrieve_password_title', $title);
        $message = apply_filters('retrieve_password_message', $message, $key);

        if ( $message && !wp_mail($user_email, $title, $message) )
            wp_die( __('The e-mail could not be sent.') . "<br />\n" . __('Possible reason: your host may have disabled the mail() function...') );

        return array(
            'code' => 'jwt_auth_password_reset',
            'message' => __( '<strong>Success:</strong> an email for selecting a new password has been sent.', 'jwt-auth' ),
            'data' => array(
                'status' => 200,
            ),
        );
    }

    /**
     * Filter to hook the rest_pre_dispatch, if the is an error in the request
     * send it, if there is no error just continue with the current request.
     *
     * @param $request
     */
    public function rest_pre_dispatch($request)
    {
        if (is_wp_error($this->jwt_error)) {
            return $this->jwt_error;
        }
        return $request;
    }



	/**
	 * Adds a token UI metabox to each user.
	 *
	 */
	public function user_token_ui( $user ) {
		if ( current_user_can( 'edit_user' ) ) {
			$tokens = get_user_meta( $user->ID, 'jwt_data', true ) ?: false;
			include plugin_dir_path( __FILE__ ) . 'views/user-token-ui.php';

		}

	}


	/**
	 * Check if we should revoke a token.
	 *
	 */
	public function maybe_revoke_token( $user ) {
		if ( current_user_can( 'edit_user' ) && ! empty( $_GET['revoke_token'] ) ) {

			$tokens = get_user_meta( $user->ID, 'jwt_data', true ) ?: false;
			$request_token = $_GET['revoke_token'];

            if ( $tokens ) {
                foreach ( $tokens as $key => $token ) {
                    if ( $token['uuid'] == $_GET['revoke_token'] ) {
                        unset( $tokens[ $key ] );
                        update_user_meta( $user->ID , 'jwt_data', $tokens );
                        break;
                    }
                }
            }

			$redirect_url = home_url() . remove_query_arg( array( 'revoke_token' ) );
			wp_safe_redirect( $redirect_url );
			exit;

		}

	}


    /**
	 * Check if we should revoke a token.
	 *
	 */
	public function maybe_revoke_all_tokens( $user ) {
		if ( current_user_can( 'edit_user' ) && ! empty( $_GET['revoke_all_tokens'] ) ) {
            delete_user_meta( $user->ID, 'jwt_data');

			$redirect_url = home_url() . remove_query_arg( array( 'revoke_all_tokens' ) );
			wp_safe_redirect( $redirect_url );
			exit;

		}

	}


    /**
	 * Check if we should revoke a token.
	 *
	 */
	public function maybe_remove_expired_tokens( $user ) {
		if ( current_user_can( 'edit_user' ) && ! empty( $_GET['remove_expired_tokens'] ) ) {

			$tokens = get_user_meta( $user->ID, 'jwt_data', true ) ?: false;
            if ( $tokens ) {
                foreach ( $tokens as $key => $token ) {
                    if ( $token['expires'] < time() ) {
                        unset( $tokens[ $key ] );
                    }
                }
                update_user_meta( $user->ID , 'jwt_data', $tokens );
            }

			$redirect_url = home_url() . remove_query_arg( array( 'remove_expired_tokens' ) );
			wp_safe_redirect( $redirect_url );
			exit;

		}

	}


	/**
	 * Get current user IP.
	 *
	 */
	private function get_IP() {
	    foreach (array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR') as $key) {
	        if (array_key_exists($key, $_SERVER) === true) {
	            foreach (array_map('trim', explode(',', $_SERVER[$key])) as $ip) {
	                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
	                    return $ip;
	                }
	            }
	        }
	    }
	}


}
