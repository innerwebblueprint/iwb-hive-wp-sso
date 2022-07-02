/**  
 * iwb_sso-login.js v1.0
 * ** please note ** - this is a work in progress, see : https://www.innerwebblueprint.com/blog/innerweb-monolog/a-work-in-progress-learning-to-iterate/
 * 
 * This script is a part of the WordPress plugin:
 * iwb-hive-wp-sso
 * See: https://www.innerwebblueprint.com/category/roadmap/iwb-wordpress-plugins/
 * 
 * Functions in this script are activated (called) by a button press defined in the wordpress plugin. See iwb-hive-wp-sso.php
 * In it's current form it supports the Hive Keychain browser extentsion.
 * I plan to integrate HAS ~ Hive Authentication Services in future versions.
 * see: https://peakd.com/hive-139531/@arcange/hive-authentication-services-official-documentation-available
 * and maybe even a built in HAS server too! Not sure about that, but I love the idea.
 * 
 * Script General Overview:
 * The main function of this script sends a 'sign message' request to Hive Keychain.
 * A succesful Hive Keychain response will be sent to 'the backend' of this wordpress plugin using ajax for verification and processing the user login.
 * If verification is succesfful we redirect, the now logged in user, to a given page passed to us from the backend.
 * If the process fails at any point, we notify the user what to do next with an error message.
 * 
 * Again, ** please note ** - this is a work in progress, see : https://www.innerwebblueprint.com/blog/innerweb-monolog/a-work-in-progress-learning-to-iterate/
 * Contributions, critcisim, suggestion on how to improve or do things better are MORE than welcomed, they are encourage. I'm still learning and want to imporve! 
 * On with the show!
 */

/**
 * Let's set some data
 * For future versions->
 * @todo add some configured variables to this script from inside the wp plugin. For example: Error Message on Signature Fail, Error Message 'Keychain not installed', Debug mode?, Custom Redirect URL on succes or failure, what else could be added here? 
 */

/** 
 * function iwb_sso_login_button_click()
 * On login with Hive button click event:
 * ask user to sign a message through Hive Keychain Extension
 * Direct the user to install Hive Keychain if not installed
 * The keychain.requestSignBuffer 'method' calls back to the 4th parameter
 * in this case 'iwb_sso_backend_post', which is a function below: iwb_sso_backend_post()
 * For future versions->
 * @todo integrate the hive onboard process - I have to make it first.
 * @todo Integrate HAF so users can sign in with their mobile device
 * or without having to install a browser extension.
*/
function iwb_sso_login_button_click() {
    // if Hive Keychain is installed, request signature
    if(window.hive_keychain) {
        let keychain = window.hive_keychain;
        console.log('Hive Keychain is available... proceed to signature request');
        messageToSign = iwb_sso_data.signMessage += iwb_sso_data.wp_nonce;
        keychain.requestSignBuffer(null,messageToSign,'active',iwb_sso_backend_post,null);
    //If Keychain is not installed...
    } else {
    // Do something here that directs the user to install keychain to continue.
    // More specifically this should redirect the user to the Hive onboarding
    // process that I'm building... but I haven't gotten that far yet.
    // It's possible someone has a hive account but does not yet have Keychain
    // installed... it's far more likley that they do not have
    // a hive account at all, and will need to create one to continue.
    // For now...
    console.log ('Keychain not installed... cannot proceed.')
    alert('Oh Dear... the Hive Keychain extension is required to continue. I\'ll have something nicer for you here in the future... but for now you can get it here: https://chrome.google.com/webstore/detail/hive-keychain/jcacnejopjdphbnjgfaaobbfafkihpep?hl=en Click OK to be redirected their automatically.' )
    window.location = 'https://chrome.google.com/webstore/detail/hive-keychain/jcacnejopjdphbnjgfaaobbfafkihpep?hl=en';
    }
}

/** 
 * function iwb_sso_backend_post(callbackResponse)
 * Post the response to the 'backend' for verification
 * So this function is called after keychain.requestSignBuffer() completes
 * and returns a bunch of stuff.
*/

// Does this need to be an 'async function?
// async function iwb_sso_backend_post()???

function iwb_sso_backend_post(callbackResponse) {
    // I'm just printing to conosle an iteration of the keys and values for debugging. 
    // for(var key in callbackResponse) {
    //     if(callbackResponse.hasOwnProperty(key)) {
    //         console.log(key, ":", callbackResponse[key]);
    //     }    
    // }

    /**
     * I should first check if I have a sucessfull response.
     * @todo - Finish this.
     */

    /**
     * Set data from the signature to send to the backend
     */
     //console.log( iwb_sso_data.wp_nonce )
     iwb_sso_PostData = {
        _ajax_nonce: iwb_sso_data.wp_nonce,
        action: "iwb_sso_handle_login_request", // action
        iwb_sso_HiveUsername: callbackResponse.data.username,
        iwb_sso_Message: callbackResponse.data.message,
        iwb_sso_MessageSignature: callbackResponse.result,
        iwb_sso_HivePublicKey: callbackResponse.publicKey
    }

    // pop a dialog for testing
    // iwb_sso_HoldingSpace = ''
    // for(var key in iwb_sso_PostData) {
    //         iwb_sso_HoldingSpace += key + ": " + iwb_sso_PostData[key] + "\n";
    // }
    // console.log(iwb_sso_HoldingSpace);


    /**
     * This is the actual part where I do the post to the backend
     */

    // Whats my ajaxurl variable again?
    //iwbsso_data.ajaxUrl

    jQuery.post(iwb_sso_data.ajaxUrl, iwb_sso_PostData, function(response) {
        //testing
        // console.log("server response: "+response);
        // iwb_sso_HoldingSpace = ''
        // for(var key in response) {
        //         iwb_sso_HoldingSpace += key + ": " + response[key] + "\n";
        // }
        // console.log(iwb_sso_HoldingSpace);

        // I need to either check what the response is... or return
        // a different URL for failure?
        // If I send a status code, I can check that and give the user
        // an error if something went wrong...
        // Otherwise I redirect the user to some page
        // Eventually I will confiugre that as 'configurable'
        // For now it's hard coded on the php side to the my acount page.

        //window.location.href( response.redirect );
        window.location = response.redirect;
        
        });

}

