<?php

/**
 * @author Jerome Mouneyrac
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package moodle multiauth
 *
 * Authentication Plugin: Google/Facebook/Messenger Authentication
 * If the email doesn't exist, then the auth plugin creates the user.
 * If the email exist (and the user has for auth plugin this current one),
 * then the plugin login the user related to this email.
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once($CFG->libdir.'/authlib.php');

/**
 * Google/Facebook/Messenger Oauth2 authentication plugin.
 */
class auth_plugin_googleoauth2 extends auth_plugin_base {

    /**
     * Constructor.
     */
    function auth_plugin_googleoauth2() {
        $this->authtype = 'googleoauth2';
        $this->roleauth = 'auth_googleoauth2';
        $this->errorlogtag = '[AUTH GOOGLEOAUTH2] ';
        $this->config = get_config('auth/googleoauth2');
    }

    /**
     * Prevent authenticate_user_login() to update the password in the DB
     * @return boolean
     */
    function prevent_local_passwords() {
        return true;
    }

    /**
     * Authenticates user against the selected authentication provide (Google, Facebook...)
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
        global $DB, $CFG;

        //retrieve the user matching username
        $user = $DB->get_record('user', array('username' => $username,
            'mnethostid' => $CFG->mnet_localhost_id));

        //username must exist and have the right authentication method
        if (!empty($user) && ($user->auth == 'googleoauth2')) {
            $code = optional_param('code', false, PARAM_TEXT);
            if($code === false){
                return false;
            }
            return true;
        }

        return false;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return false;
    }

    /**
     * Authentication hook - is called every time user hit the login page
     * The code is run only if the param code is mentionned.
     */
    function loginpage_hook() {
        global $USER, $SESSION, $CFG, $DB;

        //check the Google authorization code
        $authorizationcode = optional_param('code', '', PARAM_TEXT);
        if (!empty($authorizationcode)) {

            $authprovider = required_param('authprovider', PARAM_ALPHANUMEXT);

            //set the params specific to the authentication provider
            $params = array();

            switch ($authprovider) {
                case 'google':
                    $params['client_id'] = get_config('auth/googleoauth2', 'googleclientid');
                    $params['client_secret'] = get_config('auth/googleoauth2', 'googleclientsecret');
                    $requestaccesstokenurl = 'https://accounts.google.com/o/oauth2/token';
                    $params['grant_type'] = 'authorization_code';
                    $params['redirect_uri'] = $CFG->wwwroot . '/auth/googleoauth2/google_redirect.php';
                    $params['code'] = $authorizationcode;
                    break;
                case 'facebook':
                    $params['client_id'] = get_config('auth/googleoauth2', 'facebookclientid');
                    $params['client_secret'] = get_config('auth/googleoauth2', 'facebookclientsecret');
                    $requestaccesstokenurl = 'https://graph.facebook.com/oauth/access_token';
                    $params['redirect_uri'] = $CFG->wwwroot . '/auth/googleoauth2/facebook_redirect.php';
                    $params['code'] = $authorizationcode;
                    break;
                case 'messenger':
                    $params['client_id'] = get_config('auth/googleoauth2', 'messengerclientid');
                    $params['client_secret'] = get_config('auth/googleoauth2', 'messengerclientsecret');
                    $requestaccesstokenurl = 'https://oauth.live.com/token';
                    $params['redirect_uri'] = $CFG->wwwroot . '/auth/googleoauth2/messenger_redirect.php';
                    $params['code'] = $authorizationcode;
                    $params['grant_type'] = 'authorization_code';
                    break;
                case 'github':
                    $params['client_id'] = get_config('auth/googleoauth2', 'githubclientid');
                    $params['client_secret'] = get_config('auth/googleoauth2', 'githubclientsecret');
                    $requestaccesstokenurl = 'https://github.com/login/oauth/access_token';
                    $params['redirect_uri'] = $CFG->wwwroot . '/auth/googleoauth2/github_redirect.php';
                    $params['code'] = $authorizationcode;
                    break;
                case 'linkedin':
                    $params['grant_type'] = 'authorization_code';
                    $params['code'] = $authorizationcode;
                    $params['redirect_uri'] = $CFG->wwwroot . '/auth/googleoauth2/linkedin_redirect.php';
                    $params['client_id'] = get_config('auth/googleoauth2', 'linkedinclientid');
                    $params['client_secret'] = get_config('auth/googleoauth2', 'linkedinclientsecret');
                    $requestaccesstokenurl = 'https://www.linkedin.com/uas/oauth2/accessToken';
                    break;
                default:
                    throw new moodle_exception('unknown_oauth2_provider');
                    break;
            }

            //request by curl an access token and refresh token
            require_once($CFG->libdir . '/filelib.php');
            if ($authprovider == 'messenger') { //Windows Live returns an "Object moved" error with curl->post() encoding
                $curl = new curl();
                $postreturnvalues = $curl->get('https://oauth.live.com/token?client_id=' . urlencode($params['client_id']) . '&redirect_uri=' . urlencode($params['redirect_uri'] ). '&client_secret=' . urlencode($params['client_secret']) . '&code=' .urlencode( $params['code']) . '&grant_type=authorization_code');

           } else if ($authprovider == 'linkedin') {
                $curl = new curl();
                $postreturnvalues = $curl->get($requestaccesstokenurl . '?client_id=' . urlencode($params['client_id']) . '&redirect_uri=' . urlencode($params['redirect_uri'] ). '&client_secret=' . urlencode($params['client_secret']) . '&code=' .urlencode( $params['code']) . '&grant_type=authorization_code');

           } else {
                $curl = new curl();
                $postreturnvalues = $curl->post($requestaccesstokenurl, $params);
            }

            switch ($authprovider) {
                case 'google':
                case 'linkedin':
                    $postreturnvalues = json_decode($postreturnvalues);
                    $accesstoken = $postreturnvalues->access_token;
                    //$refreshtoken = $postreturnvalues->refresh_token;
                    //$expiresin = $postreturnvalues->expires_in;
                    //$tokentype = $postreturnvalues->token_type;
                    break;
                case 'facebook':
                case 'github':
                    parse_str($postreturnvalues, $returnvalues);
                    $accesstoken = $returnvalues['access_token'];
                    break;
                case 'messenger':
                    $accesstoken = json_decode($postreturnvalues)->access_token;
                    break;
                default:
                    break;
            }

            //with access token request by curl the email address
            if (!empty($accesstoken)) {

                //get the username matching the email
                switch ($authprovider) {
                    case 'google':
                        $params = array();
                        $params['access_token'] = $accesstoken;
                        $params['alt'] = 'json';
                        $postreturnvalues = $curl->get('https://www.googleapis.com/userinfo/email', $params);
                        $postreturnvalues = json_decode($postreturnvalues);
                        $useremail = $postreturnvalues->data->email;
                        $verified = $postreturnvalues->data->isVerified;
                        break;

                    case 'facebook':
                        $params = array();
                        $params['access_token'] = $accesstoken;
                        $postreturnvalues = $curl->get('https://graph.facebook.com/me', $params);
                        $facebookuser = json_decode($postreturnvalues);
                        $useremail = $facebookuser->email;
                        $verified = $facebookuser->verified;
                        break;

                    case 'messenger':
                        $params = array();
                        $params['access_token'] = $accesstoken;
                        $postreturnvalues = $curl->get('https://apis.live.net/v5.0/me', $params);
                        $messengeruser = json_decode($postreturnvalues);
                        $useremail = $messengeruser->emails->preferred;
                        $verified = 1; //not super good but there are no way to check it yet:
                                       //http://social.msdn.microsoft.com/Forums/en-US/messengerconnect/thread/515d546d-1155-4775-95d8-89dadc5ee929
                        break;

                    case 'github':
                        $params = array();
                        $params['access_token'] = $accesstoken;
                        $postreturnvalues = $curl->get('https://api.github.com/user', $params);
                        $githubuser = json_decode($postreturnvalues);
                        $useremails = json_decode($curl->get('https://api.github.com/user/emails', $params));
                        $useremail = $useremails[0];
                        $verified = 1; // The field will be available in the final version of the API v3.
                        break;

                    case 'linkedin':
                        $params = array();
                        $params['format'] = 'json';
                        $params['oauth2_access_token'] = $accesstoken;
                        $postreturnvalues = $curl->get('https://api.linkedin.com/v1/people/~:(first-name,last-name,email-address,location:(name,country:(code)))', $params);
                        $linkedinuser = json_decode($postreturnvalues);
                        $useremail = $linkedinuser->emailAddress;
                        $verified = 1;
                        break;

                    default:
                        break;
                }

                //throw an error if the email address is not verified
                if (!$verified) {
                    throw new moodle_exception('emailaddressmustbeverified', 'auth_googleoauth2');
                }

                // Prohibit login if email belongs to the prohibited domain
                if ($err = email_is_not_allowed($useremail)) {
                   throw new moodle_exception($err, 'auth_googleoauth2');
                }

                //if email not existing in user database then create a new username (userX).
                if (empty($useremail) or $useremail != clean_param($useremail, PARAM_EMAIL)) {
                    throw new moodle_exception('couldnotgetuseremail');
                    //TODO: display a link for people to retry
                }
                //get the user - don't bother with auth = googleoauth2 because
                //authenticate_user_login() will fail it if it's not 'googleoauth2'
                $user = $DB->get_record('user', array('email' => $useremail, 'deleted' => 0, 'mnethostid' => $CFG->mnet_localhost_id));

                //create the user if it doesn't exist
                if (empty($user)) {

                    // deny login if setting "Prevent account creation when authenticating" is on
                    if($CFG->authpreventaccountcreation) throw new moodle_exception("noaccountyet", "auth_googleoauth2");


                    //get following incremented username
                    $lastusernumber = get_config('auth/googleoauth2', 'lastusernumber');
                    $lastusernumber = empty($lastusernumber)?1:$lastusernumber++;
                    //check the user doesn't exist
                    $nextuser = $DB->get_record('user',
                            array('username' => get_config('auth/googleoauth2', 'googleuserprefix').$lastusernumber));
                    while (!empty($nextuser)) {
                        $lastusernumber = $lastusernumber +1;
                        $nextuser = $DB->get_record('user',
                            array('username' => get_config('auth/googleoauth2', 'googleuserprefix').$lastusernumber));
                    }
                    set_config('lastusernumber', $lastusernumber, 'auth/googleoauth2');
                    $username = get_config('auth/googleoauth2', 'googleuserprefix') . $lastusernumber;

                    //retrieve more information from the provider
                    $newuser = new stdClass();
                    $newuser->email = $useremail;
                    switch ($authprovider) {
                        case 'google':
                            $params = array();
                            $params['access_token'] = $accesstoken;
                            $params['alt'] = 'json';
                            $userinfo = $curl->get('https://www.googleapis.com/oauth2/v1/userinfo', $params);
                            $userinfo = json_decode($userinfo); //email, id, name, verified_email, given_name, family_name, link, gender, locale

                            $newuser->auth = 'googleoauth2';
                            if (!empty($userinfo->given_name)) {
                                $newuser->firstname = $userinfo->given_name;
                            }
                            if (!empty($userinfo->family_name)) {
                                $newuser->lastname = $userinfo->family_name;
                            }
                            if (!empty($userinfo->locale)) {
                                //$newuser->lang = $userinfo->locale;
                                //TODO: convert the locale into correct Moodle language code
                            }
                            break;

                        case 'facebook':
                            $newuser->firstname =  $facebookuser->first_name;
                            $newuser->lastname =  $facebookuser->last_name;
                            break;

                        case 'messenger':
                            $newuser->firstname =  $messengeruser->first_name;
                            $newuser->lastname =  $messengeruser->last_name;
                            break;

                        case 'github':
                            //As Github doesn't provide firstname/lastname, we'll split the name at the first whitespace.
                            $githubusername = explode(' ', $githubuser->name, 2);
                            $newuser->firstname =  $githubusername[0];
                            $newuser->lastname =  $githubusername[1];
                            break;

                        case 'linkedin':
                            $newuser->firstname =  $linkedinuser->firstName;
                            $newuser->lastname =  $linkedinuser->lastName;
                            $newuser->country = $linkedinuser->country->code;
                            $newuser->city = $linkedinuser->name;
                            break;

                        default:
                            break;
                    }

                    //retrieve country and city if the provider failed to give it
                    if (!isset($newuser->country) or !isset($newuser->city)) {
                        $googleipinfodbkey = get_config('auth/googleoauth2', 'googleipinfodbkey');
                        if (!empty($googleipinfodbkey)) {
                            $locationdata = $curl->get('http://api.ipinfodb.com/v3/ip-city/?key=' .
                                $googleipinfodbkey . '&ip='. getremoteaddr() . '&format=json' );
                            $locationdata = json_decode($locationdata);
                        }
                        if (!empty($locationdata)) {
                            //TODO: check that countryCode does match the Moodle country code
                            $newuser->country = isset($newuser->country)?isset($newuser->country):$locationdata->countryCode;
                            $newuser->city = isset($newuser->city)?isset($newuser->city):$locationdata->cityName;
                        }
                    }

                    create_user_record($username, '', 'googleoauth2');

                } else {
                    $username = $user->username;
                }

                //authenticate the user
                //TODO: delete this log later
                $userid = empty($user)?'new user':$user->id;
                add_to_log(SITEID, 'auth_googleoauth2', '', '', $username . '/' . $useremail . '/' . $userid);
                $user = authenticate_user_login($username, null);
                if ($user) {

                    //set a cookie to remember what auth provider was selected
                    setcookie('MOODLEGOOGLEOAUTH2_'.$CFG->sessioncookie, $authprovider,
                            time()+(DAYSECS*60), $CFG->sessioncookiepath,
                            $CFG->sessioncookiedomain, $CFG->cookiesecure,
                            $CFG->cookiehttponly);

                    //prefill more user information if new user
                    if (!empty($newuser)) {
                        $newuser->id = $user->id;
                        $DB->update_record('user', $newuser);
                        $user = (object) array_merge((array) $user, (array) $newuser);
                    }

                    complete_user_login($user);

                    // Redirection
                    if (user_not_fully_set_up($USER)) {
                        $urltogo = $CFG->wwwroot.'/user/edit.php';
                        // We don't delete $SESSION->wantsurl yet, so we get there later
                    } else if (isset($SESSION->wantsurl) and (strpos($SESSION->wantsurl, $CFG->wwwroot) === 0)) {
                        $urltogo = $SESSION->wantsurl;    // Because it's an address in this site
                        unset($SESSION->wantsurl);
                    } else {
                        // No wantsurl stored or external - go to homepage
                        $urltogo = $CFG->wwwroot.'/';
                        unset($SESSION->wantsurl);
                    }
                    redirect($urltogo);
                }
            } else {
                throw new moodle_exception('couldnotgetgoogleaccesstoken', 'auth_googleoauth2');
            }
        }
    }


    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * TODO: as print_auth_lock_options() core function displays an old-fashion HTML table, I didn't bother writing
     * some proper Moodle code. This code is similar to other auth plugins (04/09/11)
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        global $OUTPUT, $CFG;

        include($CFG->dirroot.'/auth/googleoauth2/config.html');
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {
        // set to defaults if undefined
        if (!isset ($config->googleclientid)) {
            $config->googleclientid = '';
        }
        if (!isset ($config->googleclientsecret)) {
            $config->googleclientsecret = '';
        }
        if (!isset ($config->facebookclientid)) {
            $config->facebookclientid = '';
        }
        if (!isset ($config->facebookclientsecret)) {
            $config->facebookclientsecret = '';
        }
        if (!isset ($config->messengerclientid)) {
            $config->messengerclientid = '';
        }
        if (!isset ($config->messengerclientsecret)) {
            $config->messengerclientsecret = '';
        }
        if (!isset ($config->githubclientid)) {
            $config->githubclientid = '';
        }
        if (!isset ($config->githubclientsecret)) {
            $config->githubclientsecret = '';
        }
        if (!isset ($config->linkedinclientid)) {
            $config->linkedinclientid = '';
        }
        if (!isset ($config->linkedinclientsecret)) {
            $config->linkedinclientsecret = '';
        }
        if (!isset ($config->googleipinfodbkey)) {
            $config->googleipinfodbkey = '';
        }
        if (!isset ($config->googleuserprefix)) {
            $config->googleuserprefix = 'social_user_';
        }

        // save settings
        set_config('googleclientid', $config->googleclientid, 'auth/googleoauth2');
        set_config('googleclientsecret', $config->googleclientsecret, 'auth/googleoauth2');
        set_config('facebookclientid', $config->facebookclientid, 'auth/googleoauth2');
        set_config('facebookclientsecret', $config->facebookclientsecret, 'auth/googleoauth2');
        set_config('messengerclientid', $config->messengerclientid, 'auth/googleoauth2');
        set_config('messengerclientsecret', $config->messengerclientsecret, 'auth/googleoauth2');
        set_config('githubclientid', $config->githubclientid, 'auth/googleoauth2');
        set_config('githubclientsecret', $config->githubclientsecret, 'auth/googleoauth2');
        set_config('linkedinclientid', $config->linkedinclientid, 'auth/googleoauth2');
        set_config('linkedinclientsecret', $config->linkedinclientsecret, 'auth/googleoauth2');
        set_config('googleipinfodbkey', $config->googleipinfodbkey, 'auth/googleoauth2');
        set_config('googleuserprefix', $config->googleuserprefix, 'auth/googleoauth2');

        return true;
    }

    /**
     * Called when the user record is updated.
     *
     * We check there is no hack-attempt by a user to change his/her email address
     *
     * @param mixed $olduser     Userobject before modifications    (without system magic quotes)
     * @param mixed $newuser     Userobject new modified userobject (without system magic quotes)
     * @return boolean result
     *
     */
    function user_update($olduser, $newuser) {
        if ($olduser->email != $newuser->email) {
            return false;
        } else {
            return true;
        }
    }

}
