<?php
/**
 * Plugin Name: IWB HIVE WP SSO
 * Plugin URI: http://www.innerwebblueprint.com/projects/wpplugins/iwb-hive-wp-sso
 * Description: Sign in to Wordpress with your Hive account.
 * Version: 1.1.0
 * Author: @innwerwebbp www.InnerWebBlueprint.com
 * License: MIT
 * License URI: https://www.innerwebblueprint.com/license/mit
 */

/**
 * ** Please note ** - this is a work in progress, see : https://www.innerwebblueprint.com/blog/innerweb-monolog/a-work-in-progress-learning-to-iterate/
 * Contributions, critcisim, suggestion on how to improve or do things better are MORE than welcomed, they are encourage. I'm still learning and working to improve! 
 * On with the show!
 */

/**
 * This is a composer thing...
 * It includes all the dependencies defined by composer.
 * Currently that's only Tuupola\Base58
 */
require 'vendor/autoload.php';

 /**
 * Wordpress has lots of 'hooks' you can 'hook' into to run specific code
 * at specific times in the Wordpress 'processes'.
 * https://developer.wordpress.org/plugins/hooks/
 * 
 * Below I am including different php files for the hooks specific to
 * plugin activation and deactivation. 
 */
require 'includes/iwb-sso-activate.php';
require 'includes/iwb-sso-deactivate.php';

/**
 * 
 */
require 'includes/iwb-sso-verify_signature.php';

/**
 * Define some shorter plugin path constants
 * Not sure if this should go here of I should put it in another file and include it.
 * We will see
 */
define( 'IWBSSO_DIR', plugin_dir_path( __FILE__ ) );
define( 'IWBSSO_URL', plugin_dir_url( __FILE__ ) );

/**
 * as of 1.1.0 I am verifying the signature natively in php
 * will remove this later.
 */
// Should this be a constant?
// Python script for signature validation
// $iwb_sso_PyScript = plugin_dir_path( __FILE__ ) .'/includes/py/iwbpy.py';

// These will eventually be configurable as configurable settings
$iwb_sso_Message = 'Signing this message confirms you are who you say you are. Please confirm this dialog to sign this message and authorize your login. Message number: ';
$iwb_sso_ButtonText = 'Login With Your Hive Account';

/**
 * Enqueue iwbsso-login.js to handle the login with hive button press 
 * and to interact with the Hive Keychain extension
 */
add_action( 'wp_enqueue_scripts', 'iwb_sso_enqueue_scripts' );
function iwb_sso_enqueue_scripts () {
    global $iwb_sso_Message;
    global $iwb_sso_wpnonce;
    wp_enqueue_script( 
        'iwb_sso_login', 
        IWBSSO_URL . '/includes/js/iwb_sso-login.js', 
        array( 'jquery' ),
        $ver = "1.0.0",
        $in_footer = false 
    );
    /**
     * Add some data to our enqueued script. This is 'the wordpress way' as I 
     * understand it.
     * 
     * I am adding three things here:
     * 1. the Ajax URL for a front end request (that means 'wordpress front end' or non admin pages). 
     *      It's apparently only defined by default on the 'admin pages'.
     * 2. a unique number only used once wp_nonce
     * 3. The message that a user will sign to authenticate their login.
     * 
     * Too see these in the Browser using Javascript:
     * console.log( iwb_sso_data.ajaxUrl );
     * console.log( iwb_sso_data.signMessage );
     * console.log( iwb_sso_data.wp_nonce )
     */

    $iwb_sso_wpnonce = wp_create_nonce( 'iwb_sso_wp_login_nonce');
    $iwb_sso_data= array(
        'ajaxUrl' => admin_url( 'admin-ajax.php' ),
        'wp_nonce'    => $iwb_sso_wpnonce,
        'signMessage' => $iwb_sso_Message
    );
    $iwb_sso_data = json_encode($iwb_sso_data);
    // wp_localize_script( 'iwb_sso_login', 'iwb_sso_data', $iwb_sso_data );
    wp_add_inline_script( 'iwb_sso_login', 'const iwb_sso_data = ' . $iwb_sso_data, 'before' );

}

/**
 * iwb_sso_add_login_button()
 * This function adds a 'Login with your Hive Account' button to the default login form
 * 
 */
function iwb_sso_add_login_button(){
    global $iwb_sso_ButtonText;
    iwb_sso_enqueue_scripts();
     ?>
     <div>
         <center><button class="button button-primary button-large" style="float: none; background-color: green; font-weight: bold;" onclick="iwb_sso_login_button_click()" type="button" id="buttonText" ><?php echo $iwb_sso_ButtonText; ?></button></center>
         <br/>
     </div>        
    <?php
}
add_action( 'login_form', 'iwb_sso_add_login_button');

/**
 * Here I am telling wordpress what to do with the ajax call with
 * the signed login message... call iwb_sso_handle_login_request() for both
 * privedleged requests and non priveleged requests.
 */
add_action('wp_ajax_nopriv_iwb_sso_handle_login_request','iwb_sso_handle_login_request');
add_action('wp_ajax_iwb_sso_handle_login_request', 'iwb_sso_handle_login_request');

/**
 * iwb_sso_get_publickey ();
 * Get the usernames public key from the hive blockchain
 * We have this from their assertion, but we need to make sure
 * it's valid by checking it against the source...
 * The Hive blockchain is the definitive source.
*/
function iwb_sso_get_publickey ($iwb_sso_HiveUsername) {
  /**
   * For now I am just going to use an API call to get the info I need
   * I'm using a hard coded api for now
   * For API calls I will need to ensure I have a working API
   * see: https://hive.blog/full-nodes/@fullnodeupdate/full-api-node-update---2762022-20220627t203029z
   */
  $iwb_sso_HiveNode = 'https://api.hive.blog';
    
  // Use Curl to make an API call.    
  // Build out the json data for the call
  $iwb_sso_CallData = json_encode(array(
    "jsonrpc" => "2.0",
    "method" => "condenser_api.lookup_account_names",
    "params" => array(
      ["$iwb_sso_HiveUsername"]
      ),
    "id" => 1
    ));

  // Let's do the curl call
  $ch = curl_init( $iwb_sso_HiveNode );    
  curl_setopt( $ch, CURLOPT_POSTFIELDS, $iwb_sso_CallData );
  curl_setopt( $ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
  # Return response
  curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
  # Send request.
  $result = curl_exec($ch);
  curl_close($ch);
  # Print response.
  //echo $result;
  //var_dump(json_decode($result));
  
  $data = json_decode($result, true);

  // $x="\n";
  // echo  $data["result"][0]["name"];
  // echo $x;
  // echo  $data["result"][0]["active"]["account_auths"];
  // echo $x;
  // echo  $data["result"][0]["active"]["key_auths"];
  // echo $x;
  // echo  $data["result"][0]["active"]["key_auths"][0][0];
  // echo $x;

  return $data["result"][0]["active"]["key_auths"][0][0];  
}

/**
 * as of 1.1.0 I am verifying the signature natively in php
 * will remove this later.
 * 
 * iwb_sso_validate_signature()
 * So I am cheating here and doing this in python instead of php.
 * That requires the beempy python library by (name?)
 * Which most people running wordpress will not have installed
 * I'm considnering making a fallback call to an auth server of some kind
 * but it really should be done locally in php.
 * I have the required python libraries built in to the 
 * IWB docker wordpress image, so as long as your using that, this will work.
 */
// function iwb_sso_validate_signature($message,$publicKey,$signature) {
//     global $iwb_sso_PyScript;
    
//     $shellCommandArgs = '"'. $message. '" "'. $publicKey. '" "'. $signature. '"';
//     $shellCommand = $iwb_sso_PyScript;

//     $output = shell_exec($shellCommand. ' '. $shellCommandArgs);
//     //echo "$testOutput";
//     return $output;
// }
  
/**
 * iwb_sso_handle_login_request()
 * This is the handler for the ajax call sent after a message is signed 
 */
function iwb_sso_handle_login_request() {
  global $iwb_sso_Message;

    // _ajax_nonce: iwb_sso_data.wp_nonce,
    // action: "iwb_sso_handle_login_request", // action
    // iwb_sso_HiveUsername: callbackResponse.data.username,
    // iwb_sso_Message: callbackResponse.data.message,
    // iwb_sso_MessageSignature: callbackResponse.result,
    // iwb_sso_HivePublicKey: callbackResponse.publicKey

  // Verify our wp nonce
  check_ajax_referer( 'iwb_sso_wp_login_nonce' );

  // Assign variables from the post data
  $iwb_sso_wpnonce = isset($_REQUEST['_ajax_nonce'])?sanitize_text_field( wp_unslash( $_REQUEST['_ajax_nonce'] ) ):'';

  $iwb_sso_HiveUsername = isset($_REQUEST['iwb_sso_HiveUsername'])?sanitize_text_field( wp_unslash( $_REQUEST['iwb_sso_HiveUsername'] ) ):'';
    
  $iwb_sso_MessageSignature = isset($_REQUEST['iwb_sso_MessageSignature'])?sanitize_text_field( wp_unslash( $_REQUEST['iwb_sso_MessageSignature'] ) ):'';

  $iwb_sso_ReportedMessage = isset($_REQUEST['iwb_sso_Message'])?sanitize_text_field( wp_unslash( $_REQUEST['iwb_sso_Message'] ) ):'';

  //Construct our original message sent for signing.
  $iwb_sso_OriginalMessage = $iwb_sso_Message . $iwb_sso_wpnonce;

  // $response = array(
  //   'nonce' => $iwb_sso_wpnonce,
  //   'username' => $iwb_sso_HiveUsername,
  //   'OriginalMessage' => $iwb_sso_OriginalMessage,
  //   'ReportedMessage' => $iwb_sso_ReportedMessage
  // );

  // wp_send_json($response);
  // wp_die();



  //This should be the same as our original message. We check against the original message
  //not the reported one for security reasons.
  if ($iwb_sso_ReportedMessage != $iwb_sso_OriginalMessage) {
    // maybe bail on the login with a message?
    // These messages should be the same, but arn't... something is not right.
    $response = array(
      'nonce' => $iwb_sso_wpnonce,
      'username' => $iwb_sso_HiveUsername,
      'test'  => $iwb_sso_OriginalMessage,
      'test2' => $iwb_sso_ReportedMessage
    );

    wp_send_json($response);
    wp_die();

  }

  // Get the Users 'admin' public key from the chain by name
  $iwb_sso_ValidPublicKey = iwb_sso_get_publickey($iwb_sso_HiveUsername);


  // Pass the valid public key, the signature, and the original message sent for signing...
  // to a function that verifies the signature is valid    
  $valid = iwb_sso_verify_message_signature($iwb_sso_OriginalMessage,$iwb_sso_MessageSignature,$iwb_sso_ValidPublicKey);

    /**
     * If the signature is valid, proceed, otherwise return an error message 
     */
     if ($valid = 'true')  {
      // Log the user in to wordpress
      $user_name=$iwb_sso_HiveUsername;
      $user_email="";
      // @todo
      // I do not capture an email when logging in...
      // I'd like to, so I can send new users an email
      // with information about their new account.
      // We don't do 'password resets' we use Hive authentication so
      // it's not technically required.
      // So I'll incorporate that in somehow at some point as a voluntary thing.
      
      // Check if the user already exists. Hive usernames are unique.
      $user_id = username_exists( $user_name );
    
      // if the username already has an account, log the user in and
      // pass a redirect url for javascript to act on.

      // if no account by that name already exists, we will create a 
      // WordPress account for the user and log them in.
      // @todo - I need to build this out with some options and checks for username conflicts
      //    in case someone wants to use this on an existing site.
      //    I might build in some functionality to allow linkage of multiple have accounts
      //    to a single wordpress account... I'll have to think on that and if it's worth the effort.
      if ( !$user_id) {
          $random_password = wp_generate_password( $length = 12, $include_standard_special_chars = false );
          $user_id = wp_create_user($user_name,$random_password,$user_email);
      } else {
          $random_password = __( 'User already exists.  Password inherited.', 'textdomain' );
      }

      $user=get_user_by("login",$user_name);        
      clean_user_cache( $user->ID );
      wp_clear_auth_cookie();
      wp_set_current_user( $user->ID );
      wp_set_auth_cookie( $user->ID, true );
      update_user_caches( $user );
      do_action( 'wp_login', $user->data->user_login, $user );

      $response = array(
        'isSignatureVerified'  => $valid,
          'nonce'       => null,
          'redirect' => site_url('/members-start-here/my-account/')
        );

      wp_send_json($response);
      wp_die(); // All ajax handlers die when finished, though I think that's incorporated into the wp_send_json() function.

     } else {
      // Not valid return an error.
      // What do I want to do here?
      // Ideally after they click the button a javascript model should
      // take over the page and indicate what's happening.
      // 1. Waiting for Keychain Signature
      // 2. Processing Signature
      // 3. Error message if it fails
      // need to also refresh the page somehow as multiple attempts
      // withot a refresh seem to not work for some reason.
      $response = array(
        'isSignatureVerified'  => $valid,
          'nonce'       => null,
          //'redirect' => site_url('/members-start-here/my-account/')
        );
     }
  }

//this is the end here
?>
