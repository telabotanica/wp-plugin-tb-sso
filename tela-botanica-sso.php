<?php
/*
 * @wordpress-plugin
 * Plugin Name:       Tela Botanica SSO
 * Plugin URI:        https://github.com/telabotanica/wp-tb-sso
 * GitHub Plugin URI: https://github.com/telabotanica/wp-tb-sso
 * Description:       Intégration du login Wordpress (authentification de l'utilisateur) avec le SSO (Single Sign On) de Tela Botanica
 * Version:           0.1 dev
 * Author:            Tela Botanica
 * Author URI:        https://github.com/telabotanica
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       tela-botanica-plugin
 * Domain Path:       /languages
 */

/**
 * Décode le jeton JWT présent dans le cookie.
 * 
 * ATTENTION le jeton n'est pas validé par l'annuaire (risque de boucle infinie
 * car l'API WP chargée par l'annuaire charge ce plugin), on considère qu'il est
 * forcément valide car il est détenu par un cookie HTTPS; pour cette raison la
 * date d'expiration du jeton est souvent dépassée (stratégie des 15mn), on ne
 * peut donc pas se baser dessus : on considère que si le cookie existe, c'est
 * que l'authentification n'est pas caduque (l'auteur de Munority Report).
 * 
 * Retourne les données contenues dans le jeton (payload / claims)
 */
function TB_SSO_decode_token($token) {
	$parts = explode('.', $token);
	$payload = $parts[1];
	$payload = base64_decode($payload);
	$payload = json_decode($payload, true);

	return $payload;
}

if (! function_exists('wp_validate_auth_cookie')) :
/**
 * Fonction qui détecte l'état de l'authentification utilisateur; ajout de
 * la détection du cookie SSO tb_auth
 */
function wp_validate_auth_cookie($cookie = '', $scheme = '') {
	//echo "Je rgad si ya pas un cookie<br/>";
	//var_dump($cookie); echo "<br/>";

	// vérifier d'abord si un cookie SSO TB est présent
	if (! empty($_COOKIE['tb_auth'])) { // @TODO config
		//echo "Il y a un cookie SSO !<br/>";
		$userData = TB_SSO_decode_token($_COOKIE['tb_auth']);
		//var_dump($userData);
		// le jeton a-t-il été décodé correctement ?
		if (empty($userData) || ! is_array($userData)) {
			do_action( 'auth_cookie_malformed', $cookie, $scheme );
			return false;
		}
		// le jeton est-il encore valide ? @TODO marchera pas sans vérification annuaire
		/*$expirationDate = $userData['exp'];
		if ($expirationDate < time()) {
			do_action( 'auth_cookie_expired', $cookie_elements );
			return false;
		}*/
		// récupération de l'objet utilisateur WP
		$user = get_user_by('id', $userData['id']);
		//var_dump($user);
		if ( ! $user ) {
			do_action( 'auth_cookie_bad_username', $cookie_elements );
			return false;
		}
		// fabrication d'un $cookie_elements compatible avec la suite du traitement
		$cookie_elements = array(
			'username' => $user->data->user_login,
			'expiration' => null,
			'token' => null,
			'hmac' => null,
			'scheme' => 'auth'
		);

		/**
		 * Suppression des cookies WP qui pouvaient traîner : si on est connecté
		 * à l'aide du SSO, on ne doit plus être connecté d'une autre manière;
		 * évite de rester connecté, voire changer d'utilisateur, lorsqu'on se
		 * déconnecte du SSO
		 */
		wp_clear_auth_cookie();

	} else { // traitement WP par défaut
		// @WARNING même déconnecté du SSO, si on a encore un cookie WP on reste
		// connecté à WP - ce cookie WP n'est pas toujours posé - ??
		if ( ! $cookie_elements = wp_parse_auth_cookie($cookie, $scheme) ) {
			/**
			 * Fires if an authentication cookie is malformed.
			 *
			 * @since 2.7.0
			 *
			 * @param string $cookie Malformed auth cookie.
			 * @param string $scheme Authentication scheme. Values include 'auth', 'secure_auth',
			 *                       or 'logged_in'.
			 */
			do_action( 'auth_cookie_malformed', $cookie, $scheme );
			return false;
		}

		$scheme = $cookie_elements['scheme'];
		$username = $cookie_elements['username'];
		$hmac = $cookie_elements['hmac'];
		$token = $cookie_elements['token'];
		$expired = $expiration = $cookie_elements['expiration'];

		// Allow a grace period for POST and Ajax requests
		if ( defined('DOING_AJAX') || 'POST' == $_SERVER['REQUEST_METHOD'] ) {
			$expired += HOUR_IN_SECONDS;
		}

		// Quick check to see if an honest cookie has expired
		if ( $expired < time() ) {
			/**
			 * Fires once an authentication cookie has expired.
			 *
			 * @since 2.7.0
			 *
			 * @param array $cookie_elements An array of data for the authentication cookie.
			 */
			do_action( 'auth_cookie_expired', $cookie_elements );
			return false;
		}

		$user = get_user_by('login', $username);
		if ( ! $user ) {
			/**
			 * Fires if a bad username is entered in the user authentication process.
			 *
			 * @since 2.7.0
			 *
			 * @param array $cookie_elements An array of data for the authentication cookie.
			 */
			do_action( 'auth_cookie_bad_username', $cookie_elements );
			return false;
		}

		$pass_frag = substr($user->user_pass, 8, 4);

		$key = wp_hash( $username . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme );

		// If ext/hash is not present, compat.php's hash_hmac() does not support sha256.
		$algo = function_exists( 'hash' ) ? 'sha256' : 'sha1';
		$hash = hash_hmac( $algo, $username . '|' . $expiration . '|' . $token, $key );

		if ( ! hash_equals( $hash, $hmac ) ) {
			/**
			 * Fires if a bad authentication cookie hash is encountered.
			 *
			 * @since 2.7.0
			 *
			 * @param array $cookie_elements An array of data for the authentication cookie.
			 */
			do_action( 'auth_cookie_bad_hash', $cookie_elements );
			return false;
		}

		$manager = WP_Session_Tokens::get_instance( $user->ID );
		if ( ! $manager->verify( $token ) ) {
			do_action( 'auth_cookie_bad_session_token', $cookie_elements );
			return false;
		}
		// Ajax/POST grace period set above
		if ( $expiration < time() ) {
			$GLOBALS['login_grace_period'] = 1;
		}
		// fin traitement WP par défaut
	}

	/**
	 * Fires once an authentication cookie has been validated.
	 *
	 * @since 2.7.0
	 *
	 * @param array   $cookie_elements An array of data for the authentication cookie.
	 * @param WP_User $user            User object.
	 */
	do_action( 'auth_cookie_valid', $cookie_elements, $user );

	return $user->ID;
}
endif;

if (! function_exists('wp_logout')) :
/**
 * Déconnecte l'utilisateur de Wordpress et du SSO
 */
function wp_logout() {
	echo "Je me déconnecte comme un p'tit fou :-)";

	// mécanisme par défaut : suppression des cookies WP
	wp_destroy_current_session();
	wp_clear_auth_cookie();

	// suppression du cookie SSO
	setcookie('tb_auth', '', -1, '/', null, false); // @TODO config

	// hook
	do_action( 'wp_logout' );
}
endif;

if (! function_exists('wp_signon')) :
/**
 * Connecte l'utilisateur à Wordpress et au SSO
 */
function wp_signon() {
	echo "Je me connecte comme un guedin :-)";

	//$verificationServiceURL = $this->config['annuaireURL'];
	/*$verificationServiceURL = 'http://localhost/service:annuaire:auth';
	$verificationServiceURL = trim($verificationServiceURL, '/') . "/deconnexion";

	$ch = curl_init();
	$timeout = 5;
	curl_setopt($ch, CURLOPT_URL, $verificationServiceURL);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);

	// equivalent of "-k", ignores SSL self-signed certificate issues
	// (for local testing only)
	if (! empty($this->config['ignoreSSLIssues']) && $this->config['ignoreSSLIssues'] === true) {
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	}

	$data = curl_exec($ch);
	curl_close($ch);
	//var_dump($data);
	//return ($info === true);
	//exit;
	 */
}
endif;