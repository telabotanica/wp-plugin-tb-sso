<?php
/*
 * @wordpress-plugin
 * Plugin Name:       Tela Botanica SSO
 * Plugin URI:        https://github.com/telabotanica/wp-plugin-tb-sso
 * GitHub Plugin URI: https://github.com/telabotanica/wp-plugin-tb-sso
 * Description:       Intégration du login Wordpress (authentification de l'utilisateur) avec le SSO (Single Sign On) de Tela Botanica
 * Version:           0.1 dev
 * Author:            Tela Botanica
 * Author URI:        https://github.com/telabotanica
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       telabotanica
 * Domain Path:       /languages
 */

// menu d'administration
require_once __DIR__ . '/admin.php';

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
function tb_sso_decode_token($token) {
	$parts = explode('.', $token);
	$payload = $parts[1];
	$payload = urlsafeB64Decode($payload);
	$payload = json_decode($payload, true);

	return $payload;
}

// copié depuis firebase/JWT
function urlsafeB64Decode($input) {
	$remainder = strlen($input) % 4;
	if ($remainder) {
		$padlen = 4 - $remainder;
		$input .= str_repeat('=', $padlen);
	}
	return base64_decode(strtr($input, '-_', '+/'));
}

if (! function_exists('wp_validate_auth_cookie')) :
/**
 * Fonction qui détecte l'état de l'authentification utilisateur; ajout de
 * la détection du cookie SSO
 */
function wp_validate_auth_cookie($cookie = '', $scheme = '') {
	// chargement config
	$configSSO = tb_sso_charger_config();
	$nomCookie = $configSSO['cookieName'];

	// vérifier d'abord si un cookie SSO TB est présent
	if (! empty($_COOKIE[$nomCookie])) {
		//echo "Il y a un cookie SSO !<br/>";
		$userData = tb_sso_decode_token($_COOKIE[$nomCookie]);
		//var_dump($userData);
		// le jeton a-t-il été décodé correctement ?
		if (empty($userData) || ! is_array($userData)) {
			do_action('auth_cookie_malformed', $cookie, $scheme);
			return false;
		}
		// le jeton est-il encore valide ? @TODO ne marchera pas sans vérification annuaire
		/*$expirationDate = $userData['exp'];
		if ($expirationDate < time()) {
			do_action( 'auth_cookie_expired', $cookie_elements );
			return false;
		}*/
		// récupération de l'objet utilisateur WP
		$user = get_user_by('id', $userData['id']);
		//var_dump($user);
		if ( ! $user ) {
			do_action('auth_cookie_bad_username', null);
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
		 * déconnecte du SSO;
		 * n'interdit pas de se connecter avec WP en cas de panne du SSO
		 */
		wp_clear_auth_cookie();

	} else { // traitement WP par défaut
		// Indépendamment du SSO, si on est en possession d'un cookie WP on est
		// considéré comme connecté (sécurité en cas de panne du SSO)
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
	do_action('auth_cookie_valid', $cookie_elements, $user);

	return $user->ID;
}
endif;

if (! function_exists('wp_logout')) :
/**
 * Déconnecte l'utilisateur de Wordpress et du SSO
 */
function wp_logout() {
	// chargement config
	$configSSO = tb_sso_charger_config();
	$nomCookie = $configSSO['cookieName'];
	$adresseServiceSSO = $configSSO['rootURI'];

	// mécanisme par défaut : suppression des cookies WP
	wp_destroy_current_session();
	wp_clear_auth_cookie();
	
	// déconnexion du SSO
	$deconnexionServiceURL = $adresseServiceSSO;
	$deconnexionServiceURL = trim($deconnexionServiceURL, '/') . "/deconnexion";

	$ch = curl_init();
	$timeout = 5;
	curl_setopt($ch, CURLOPT_URL, $deconnexionServiceURL);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
	$reponse = curl_exec($ch);

	// séparation du corps et des entêtes
	$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
	$entetes = substr($reponse, 0, $header_size);
	//$jsonData = substr($reponse, $header_size); // corps
	curl_close($ch);

	//var_dump($jsonData);
	//var_dump($entetes);
	// transmission de la suppression du cookie SSO par le service Auth
	tb_sso_cookie_proxy($entetes, array($nomCookie));
	// on ne s'occupe pas du corps de la réponse : la déconnexion n'a aucune
	// raison d'échouer @TODO vérifier cette stratégie (si l'appel échoue ?)
	//exit;

	// décodage du retour du service
	//$data = json_decode($jsonData, true);

	// hook
	do_action('wp_logout');
}
endif;

/**
 * Ajout du champ "partenaire" au formulaire de connexion
 */
add_action('login_form', 'telabotanica_login_form');

function telabotanica_login_form() {
	// partenaire sélectionné précédemment, ou par un paramètre GET
	$partenaire = '';
	if (isset($_REQUEST['provider'])) {
		$partenaire = $_REQUEST['provider'];
	} ?>
	<p class="login-providers">
		<?php _e('Se connecter via un compte partenaire', 'telabotanica'); ?><br />
		<label class="login-provider-default">
			<input name="provider" value="" type="radio" <?php echo ($partenaire == '') ? 'checked' : '' ?>>
			<?php _e('non', 'telabotanica'); ?>
		</label>
		<label class="login-provider-plantnet">
			<input name="provider" value="plantnet" type="radio" <?php echo ($partenaire == 'plantnet') ? 'checked' : '' ?>>
			Pl@ntNet
		</label>
		<label class="login-provider-recolnat">
			<input name="provider" value="recolnat" type="radio" <?php echo ($partenaire == 'recolnat') ? 'checked' : '' ?>>
			eRecolnat
		</label>
	</p>
<?php }

/**
 * Authentification par le SSO
 * 
 * Filtre appelé par wp_authenticate($username, $password) au moment où
 * l'utilisateur valide le formulaire d'authentification
 * 
 * Si l'authentification SSO échoue, les autres méthodes d'authentification
 * seront essayées - permet de se connecter en cas de panne du SSO
 * 
 * Une priorité de 10 suffit à l'exécuter avant l'authentification par défaut
 */
add_filter('authenticate', 'tb_sso_auth', 10, 3);

function tb_sso_auth($user, $username, $password) {
	// chargement config
	$configSSO = tb_sso_charger_config();
	$nomCookie = $configSSO['cookieName'];
	$adresseServiceSSO = $configSSO['rootURI'];

	// a-t-on choisi de se connecter avec un compte partenaire ?
	$partenaire = ''; // chaîne vide = aucun partenaire (Tela Botanica)
	if (isset($_REQUEST['provider'])) {
		$partenaire = $_REQUEST['provider'];
	}

	// copié depuis wp_authenticate_username_password()
	if (empty($username) || empty($password)) {
		$error = new WP_Error();
		if (empty($username)) {
			$error->add('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));
		}
		if (empty($password)) {
			$error->add('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));
		}
		return $error;
	}

	// connexion au SSO - $username doit toujours être une adresse email
	$connexionServiceURL = $adresseServiceSSO;
	$connexionServiceURL = trim($connexionServiceURL, '/') . "/connexion";
	$connexionServiceURL .= '?login=' . $username . '&password=' . urlencode($password);
	if ($partenaire != '') {
		$connexionServiceURL .= '&partner=' . $partenaire;
	}

	$ch = curl_init();
	$timeout = 5;
	curl_setopt($ch, CURLOPT_URL, $connexionServiceURL);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
	$reponse = curl_exec($ch);

	// séparation du corps et des entêtes
	$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
	$entetes = substr($reponse, 0, $header_size);
	$jsonData = substr($reponse, $header_size); // corps
	curl_close($ch);

	// récupération et transmission du cookie SSO posé par le service Auth
	tb_sso_cookie_proxy($entetes, array($nomCookie));

	// décodage du retour du service
	$data = json_decode($jsonData, true);

	// si la connexion est acceptée ("session": true et jeton non vide)
	if (isset($data['session']) && $data['session'] === true && ! empty($data['token'])) {
		// décodage du jeton
		$userData = tb_sso_decode_token($data['token']);
		// le jeton a-t-il été décodé correctement ?
		if (empty($userData) || ! is_array($userData)) {
			$user = new WP_Error('empty_username', __('<strong>ERREUR</strong>: The username field is empty.'));
		} else {
			// récupération de l'objet utilisateur WP
			$user = get_user_by('id', $userData['id']);
			if ($user === false) {
				// ne devrait jamais se produire tant que le SSO repose sur la
				// table des utilisateurs WP
				$user = new WP_Error('unknown_user_id', __('<strong>ERREUR</strong>: Utilisateur ' . $userData['id'] . ' introuvable.'));
			}
		}
	} else {
		$user = new WP_Error('invalid_token', __('<strong>ERREUR</strong>: Échec de la connexion au SSO.'));
	}

	// empêche WP de logger l'utilisateur avec son mécanisme par défaut et force
	// le SSO; mais en cas de panne de celui-ci, risque d'empêcher de se logger
	// en admin pour corriger l'erreur - mieux vaut éviter
	//remove_action('authenticate', 'wp_authenticate_username_password', 20);

	return $user;
}

/**
 * Récupère dans les entêtes renvoyés par cURL le cookie SSO posé par le service
 * Auth, et le transmet au client (proxy de cookie)
 * 
 * @param string $entetes une chaîne d'entêtes renvoyée par cURL
 */
function tb_sso_cookie_proxy($entetes, $noms) {
	$cookies = curl_header_parse_cookies($entetes);
	//echo "<pre>"; var_dump($cookies); echo "</pre>";
	foreach ($cookies as $cookie) {
		if (in_array($cookie['name'], $noms)) {
			//echo "Pose de <pre>"; var_dump($cookie); echo "</pre>";
			// répercussion du cookie @TODO vérifier que tout marche ("domain" et "secure" notamment)
			setcookie($cookie['name'], $cookie['value'], $cookie['expires'], $cookie['path'], $cookie['domain'], $cookie['secure'], $cookie['httponly']);
		}
	}
}

/**
 * Découpe une chaîne d'entêtes cURL pour en extraire les directives "SetCookie"
 * puis les renvoie sous forme d'un tableau de cookies
 * 
 * @TODO filtrer sur le[sous-]domaine pour éviter de transmettre des cookies
 * qui ne concernent pas le client (@WARNING faille de sécurité ?)
 * 
 * @param string $entetes une chaîne d'entêtes renvoyée par cURL
 * @return array un tableau de cookies
 */
function curl_header_parse_cookies($entetes) {
	// découpage des entêtes
	$matches = array();
	preg_match_all('/^Set-Cookie:\s*(.*)/mi', $entetes, $matches);

	// extraction des cookies
	$cookies = array();
	foreach($matches[1] as $item) {
		//var_dump($item);
		$itemParts = explode('; ', $item);
		//echo "<pre>"; var_dump($itemParts); echo "</pre>";
		$cookieNameAndValue = explode('=', trim(array_shift($itemParts)));
		// formatage et propriétés par défaut
		$cookie = array(
			'name' => $cookieNameAndValue[0],
			'value' => $cookieNameAndValue[1],
			'expires' => null,
			'max-age' => null,
			'path' => null,
			'domain' => null,
			'secure' => false,
			'httponly' => false
		);
		// autres propriétés
		foreach ($itemParts as $ip) {
			$kv = explode('=', $ip);
			if (is_array($kv) && count($kv) == 2) {
				$k = strtolower(trim($kv[0]));
				$v = trim($kv[1]);
				// traitements spécifiques
				switch ($k) {
					case 'expires':
						$v = strtotime($v);
						break;
					default:
				}
				//echo "K:[$k] / V:[$v]   ";
				$cookie[$k] = $v;
			} else {
				// propriété unique (ex: "secure")
				$ip = trim($ip);
				$cookie[$ip] = true;
			}
		}
		//echo "-----------------------<pre>"; var_dump($cookie); echo "\n</pre>-------------------";
		$cookies[] = $cookie;
	}

	return $cookies;
}
