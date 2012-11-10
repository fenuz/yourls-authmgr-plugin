<?php
/*
Plugin Name: Authorization Manager
Plugin URI: http://code.google.com/p/yourls-authmgr-plugin/
Description: Restrict classes of users to specific functions
Version: 1.0
Author: nicwaller
Author URI: http://code.google.com/u/101717938102134699062/
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

// Define constants for critical filters
define( 'AUTHMGR_ALLOW', 'filter_authmgr_allow' );
define( 'AUTHMGR_HASROLE', 'filter_authmgr_hasrole' );

// Define constants used for naming roles (but they don't work in config.php)
class AuthmgrRoles {
	const Administrator = 'Administrator';
	const Editor = 'Editor';
	const Contributor = 'Contributor';
}

// Define constants used for naming capabilities
class AuthmgrCapability {
	const ShowAdmin = 'ShowAdmin'; // only display admin panel
	const AddURL = 'AddURL';
	const DeleteURL = 'DeleteURL';
	const EditURL = 'EditURL';
	const ManagePlugins = 'ManagePlugins';
        const API = 'API';
	const ViewStats = 'ViewStats';
}	

function authmgr_environment_check() {
	global $authmgr_anon_capabilities;
	global $authmgr_role_capabilities;
	global $authmgr_role_assignment;

	if ( !isset( $authmgr_anon_capabilities) ) {
		$authmgr_anon_capabilities = array(
			AuthmgrCapability::API,
			AuthmgrCapability::ShowAdmin,//TODO: hack! how to allow logon page?
		);
	}

	if ( !isset( $authmgr_role_capabilities) ) {
		$authmgr_role_capabilities = array(
			AuthmgrRoles::Administrator => array(
				AuthmgrCapability::ShowAdmin,
				AuthmgrCapability::AddURL,
				AuthmgrCapability::DeleteURL,
				AuthmgrCapability::EditURL,
				AuthmgrCapability::ManagePlugins,
				AuthmgrCapability::API,
                                AuthmgrCapability::ViewStats,
			),
			AuthmgrRoles::Editor => array(
				AuthmgrCapability::ShowAdmin,
				AuthmgrCapability::AddURL,
				AuthmgrCapability::EditURL,
				AuthmgrCapability::DeleteURL,
                                AuthmgrCapability::ViewStats,
			),
			AuthmgrRoles::Contributor => array(
				AuthmgrCapability::ShowAdmin,
				AuthmgrCapability::AddURL,
				AuthmgrCapability::ViewStats,
			),
		);
	}

	if ( !isset( $authmgr_role_assignment ) ) {
		$authmgr_role_assignment = array();
	}

	if ( !isset( $authmgr_iprange_roles ) ) {
		$authmgr_admin_ipranges = array(
			'127.0.0.0/8',
		);
	}

	// convert role assignment table to lower case if it hasn't been done already
	// this makes searches much easier!
	$authmgr_role_assignment_lower = array();
	foreach ( $authmgr_role_assignment as $key => $value ) {
		$t_key = strtolower( $key );
		$t_value = array_map('strtolower', $value);
		$authmgr_role_assignment_lower[$t_key] = $t_value;
	}
	$authmgr_role_assignment = $authmgr_role_assignment_lower;
	unset($authmgr_role_assignment_lower);

	return true;
}

/********** Inject authorization checks into CORE functionality ********/

yourls_add_action( 'load_template_infos', 'authmgr_intercept_stats' );
function authmgr_intercept_stats() { authmgr_require_capability( AuthmgrCapability::ViewStats ); }

yourls_add_action( 'api', 'authmgr_intercept_api' );
function authmgr_intercept_api() { authmgr_require_capability( AuthmgrCapability::API ); }

yourls_add_action( 'admin_init', 'authmgr_intercept_admin' );
function authmgr_intercept_admin() {
	authmgr_require_capability( AuthmgrCapability::ShowAdmin );

        // we use this GET param to send up a feedback notice to user
        if ( isset( $_GET['access'] ) && $_GET['access']=='denied' ) {
                yourls_add_notice('Access Denied');
        }

        $action_capability_map = array(
      		'add' => AuthmgrCapability::AddURL,
        	'delete' => AuthmgrCapability::DeleteURL,
        	'edit_display' => AuthmgrCapability::EditURL,
        	'edit_save' => AuthmgrCapability::EditURL,
        	'activate' => AuthmgrCapability::ManagePlugins,
        	'deactivate' => AuthmgrCapability::ManagePlugins,
	);

	// intercept requests for plugin management
	if ( isset( $_REQUEST['plugin'] ) ) {
                $action_keyword = $_REQUEST['action'];
                $cap_needed = $action_capability_map[$action_keyword];
                if ( $cap_needed !== NULL && authmgr_have_capability( $cap_needed ) !== true) {
                        yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
                }
	}

	// also intercept AJAX requests
	if ( yourls_is_Ajax() ) {
		$action_keyword = $_REQUEST['action'];
		$cap_needed = $action_capability_map[$action_keyword];
		if ( authmgr_have_capability( $cap_needed ) !== true) {
			$err = array();
			$err['status'] = 'fail';
			$err['code'] = 'error:authorization';
			$err['message'] = 'Access Denied';
			$err['errorCode'] = '403';
			echo json_encode( $err );
			die();
		}
	}
}

/**************** FILTER USERS **************/

/*
 * If capability is not permitted in current context, then abort.
 * This is the most basic way to intercept unauthorized usage.
 */
function authmgr_require_capability( $capability ) {
	if ( !authmgr_have_capability( $capability ) ) {
		// TODO: display a much nicer error page
		//die('Sorry, you are not authorized for the action: '.$capability);
                yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
		die();
	}
}

/*
 * Is the requested capability permitted in this context?
 * (By filtering AUTHMGR_ALLOW, you can grant capabilities without using roles.)
 */
function authmgr_have_capability( $capability ) {
        return yourls_apply_filter( AUTHMGR_ALLOW, false, $capability);
}


/*
 * Determine whether a specific user has a role.
 * If you want to grant roles from a plugin, just handle this filter.
 * Any filter handlers should execute as quickly as possible.
 * (By filtering AUTHMGR_HASROLE, you can connect internal roles to something else.)
 */
function authmgr_user_has_role( $username, $rolename ) {
	// cache responses to improve execution time
	static $rolecache = array();
	$cachekey = $username . $rolename;
	if ( isset( $rolecache[$cachekey] ) && $rolecache[$cachekey] === true )
		return true;

	// cache miss? process normally.
	$hasrole = yourls_apply_filter( AUTHMGR_HASROLE, false, $username, $rolename );
	$rolecache[$username . $rolename] = $hasrole;

	return $hasrole;
}

/*
 * What roles does this user have?
 * Check all the roles to see if that user is a member of each one.
 * Returns an array of strings.
 */
function authmgr_get_roles_for_user( $username ) {
        global $authmgr_role_capabilities;

	$user_roles = array();

        foreach ( $authmgr_role_capabilities as $rolename => $rolecaps ) {
                if ( authmgr_user_has_role( $username, $rolename ) ) {
			$user_roles[] = $rolename;
		}
        }

	return $user_roles;
}

/*
 * What capabilities does a particular user have?
 */
function authmgr_get_caps_for_user( $username ) {
        global $authmgr_role_capabilities;
        $user_caps = array();

        foreach ( $authmgr_role_capabilities as $rolename => $rolecaps ) {
                if ( authmgr_user_has_role( $username, $rolename ) ) {
                        $user_caps = array_merge( $user_caps, $rolecaps );
                }
        }
        $user_caps = array_unique( $user_caps );

        return $user_caps;
}

/***************** FILTER DEFINITIONS **************/

/*
 * Can a specified capability be used by anonymous users?
 */
yourls_add_filter( AUTHMGR_ALLOW, 'authmgr_check_anon_capability', 5 );
function authmgr_check_anon_capability( $original, $capability ) {
        global $authmgr_anon_capabilities;

        // Shortcut - trust approval given by earlier filters
        if ( $original === true ) return true;

	// Make sure the anon rights list has been setup
	authmgr_environment_check();

	// Check list of capabilities that don't require authentication
	return in_array( $capability, $authmgr_anon_capabilities );
}

/*
 * Is the current user permitted to use the specified capability?
 */
yourls_add_filter( AUTHMGR_ALLOW, 'authmgr_check_user_capability', 10 );
function authmgr_check_user_capability( $original, $capability ) {
	global $authmgr_role_capabilities;

	// Shortcut - trust approval given by earlier filters
	if ( $original === true ) return true;

	// ensure $authmgr_role_capabilities has been set up
	authmgr_environment_check();

	// Check authentication. If none, then don't grant anything.
        // TODO: call is_valid_user directly once the filtering code is moved
        // into the core function, so we don't have to. Core Issue 1229
        $authenticated = yourls_apply_filter( 'is_valid_user', yourls_is_valid_user() );
	if ( $authenticated !== true )
		return false;

	$user_capabilities = authmgr_get_caps_for_user( YOURLS_USER );
	return in_array( $capability, $user_capabilities );
}

/*
 * Is the user connecting from an IP range that gives automatic admin?
 * If the user is connecting from an IP range designated for admins, then
 * automatically grant all capabilities. 
 */
yourls_add_filter( AUTHMGR_ALLOW, 'authmgr_check_admin_ipranges', 15 );
function authmgr_check_admin_ipranges( $original, $capability ) {
	global $authmgr_admin_ipranges;

        // Shortcut - trust approval given by earlier filters
        if ( $original === true ) return true;

        // ensure $authmgr_admin_ipranges is setup
        authmgr_environment_check();

	foreach ($authmgr_admin_ipranges as $range) {
		if ( authmgr_cidr_match( $_SERVER['REMOTE_ADDR'], $range ) )
			return true;
	}

	return $original; // effectively returns false
}

/*
 * Borrowed from:
 * http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
 */
function authmgr_cidr_match($ip, $range)
{
    list ($subnet, $bits) = split('/', $range);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
    return ($ip & $mask) == $subnet;
}

/*
 * Is the API user (or signature) allowed to use this capability?
 */
function authmgr_check_apiuser_capability( $original, $capability ) {
        // Shortcut - trust approval given by earlier filters
        if ( $original === true ) return true;

	// In API mode and not using user/path authn? Let it go.
	if ( yourls_is_API() && !isset($_REQUEST['username']) )
		return true;
	// TODO: add controls for actions, like
	// shorturl, stats, db-stats, url-stats, expand

	return $original;
}

// TODO: add a capability filter for IP ranges whitelist/blacklist

/*
 * Returns true if user is assigned to specified role in user/config.php
 */
yourls_add_filter( AUTHMGR_HASROLE, 'authmgr_user_has_role_in_config');
function authmgr_user_has_role_in_config( $original, $username, $rolename ) {
	global $authmgr_role_assignment;

	// if no role assignments are created, grant everything
	// this is a failsafe in case configuration was done wrong
	if ( empty( $authmgr_role_assignment ) )
		return true;

	// do this the case-insensitive way
	// the entire array was made lowercase in environment check
	$username = strtolower($username);
	$rolename = strtolower($rolename);

	// if the role doesn't exist, give up now.
	if ( !in_array( $rolename, array_keys( $authmgr_role_assignment ) ) )
		return false;

	$users_in_role = $authmgr_role_assignment[$rolename];
	return in_array( $username, $users_in_role );	
}

/*********************** Cosmetic stuff ************************/

yourls_add_filter( 'logout_link', 'authmgr_html_append_roles' );
function authmgr_html_append_roles( $original ) {
	// TODO: another place to get rid of this extra filter call, once
	// the core function is fixed.
        $authenticated = yourls_apply_filter( 'is_valid_user', yourls_is_valid_user() );
        if ( $authenticated === true ) {
		$listroles = implode(', ', authmgr_get_roles_for_user( YOURLS_USER ));
		$listcaps = implode(', ', authmgr_get_caps_for_user( YOURLS_USER ));
		$append = '<div class="authmgr-roles" title="'.$listcaps.'">'.$listroles.'</div>';
		return $original . $append;
	} else {
		return $original;
	}
}
