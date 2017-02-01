<?php
// Hook pour le menu Admin
add_action('admin_menu', 'tb_sso_ajout_pages');

// Actions du hook
function tb_sso_ajout_pages() {

	add_menu_page(
		'SSO',
		'SSO',
		'manage_options',
		'telabotanica_sso',
		'',
		'dashicons-admin-network'
	);

	// Ajoute un sous-menu 'SSO' dans 'Tela Botanica'
	add_submenu_page(
		'telabotanica_sso',
		'SSO',
		'SSO',
		'manage_options',
		'telabotanica_sso', // On donne le même 'menu_slug' que celui du menu pour écraser le sous-menu automatique
		'tb_menu_sso'
	);
}

/**
 * Charge la confiuration du SSO depus la base de données Wordpress; si cette
 * config n'est pas présente, charge la config par défaut depuis le fichier
 * "config-defaut.json"
 * 
 * @return array la configuration du SSO
 */
function tb_sso_charger_config() {
	$opt_name_sso = 'tb_sso_config';

	// chargement de la config actuelle
	$configActuelleSSO = json_decode(get_option($opt_name_sso), true);

	// si la config actuelle est vide, on charge la config par défaut
	if (empty($configActuelleSSO)) {
		// config par défaut de l'outil
		$cheminConfigDefautSSO = __DIR__ . '/config-defaut.json';
		$configDefautSSO = json_decode(file_get_contents($cheminConfigDefautSSO), true);
		$configActuelleSSO = $configDefautSSO;
	}

	return $configActuelleSSO;
}

function tb_menu_sso() {
?>
	<div class="wrap">
		<?php
		if (!current_user_can('manage_options'))
		{
			wp_die( __('Vous n\'avez pas les droits suffisants pour accéder à cette page.') );
		}
		?>
		<?php screen_icon(); ?>

		<!-- Titre -->
		<h2><?php _e("Configuration du SSO Tela Botanica", 'telabotanica') ?></h2>

		<!-- Description -->
		<div class="description">
			<p>
				<?php _e("Permet de synchroniser le login Wordpress avec le login du SSO Tela Botanica", 'telabotanica') ?>
			</p>
		</div>

		<?php settings_errors(); ?>

		<?php
			$opt_name_sso = 'tb_sso_config';
			$hidden_field_name = 'tb_submit_hidden';

			// chargement de la config actuelle
			$configActuelleSSO = tb_sso_charger_config();
			//var_dump($configActuelleSSO);

			// enregistre les changements de config en BdD
			if (isset($_POST[$hidden_field_name]) && $_POST[$hidden_field_name] == 'Y') {
				$configActuelleSSO['cookieName'] = $_POST['cookieName'];
				$configActuelleSSO['rootURI'] = $_POST['rootURI'];

				update_option($opt_name_sso, json_encode($configActuelleSSO));
		?>
				<!-- Confirmation de l'enregistrement -->
				<div class="updated">
					<p><strong><?php _e("Changes saved") ?></strong></p>
				</div>
		<?php }	?>

		<form method="post" action="">
			<input type="hidden" name="<?php echo $hidden_field_name; ?>" value="Y">
			<table class="form-table">
				<tbody>
					<tr>
						<th scope="row">
							<label><?php _e("URL du service d'authentification SSO", 'telabotanica') ?></label>
						</th>
						<td>
							<input class="regular-text" type="text" name="rootURI" value="<?php echo $configActuelleSSO['rootURI']; ?>" />
							<p class="description"><?php _e('Ne pas mettre de "/" (slash) à la fin', 'telabotanica') ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label><?php _e("Nom du cookie posé par le SSO", 'telabotanica') ?></label>
						</th>
						<td>
							<input type="text" placeholder="ex: tb_auth" name="cookieName" value="<?php echo $configActuelleSSO['cookieName']; ?>" />
							<p class="description"><?php _e("Le nom du cookie doit être le même que dans la configuration de l'annuaire TB", 'telabotanica') ?></p>
						</td>
					</tr>
				</tbody>
			</table>
			<hr/>

			<p class="submit">
				<input type="submit" name="Submit" class="button-primary" value="<?php esc_attr_e('Save Changes') ?>" />
			</p>
		</form>
<?php
}