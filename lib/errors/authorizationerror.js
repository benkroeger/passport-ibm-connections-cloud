var util = require('util');
/**
 * `AuthorizationError` error.
 *
 * AuthorizationError represents an error in response to an authorization
 * request.  For details, refer to RFC 6749, section 4.1.2.1.
 *
 * References:
 *   - [The OAuth 2.0 Authorization Framework](http://tools.ietf.org/html/rfc6749)
 *
 * @constructor
 * @param {String} [message]
 * @param {String} [code]
 * @param {String} [uri]
 * @param {Number} [status]
 * @api public
 */
function AuthorizationError(message, code, uri, status) {
  if (!status) {
    switch (code) {
      case 'oauth_denied':
        status = 403;
        break;
      case 'server_error':
        status = 502;
        break;
      case 'temporarily_unavailable':
        status = 503;
        break;
    }
  }

  Error.call(this);
  Error.captureStackTrace(this, AuthorizationError);
  this.name = 'AuthorizationError';
  this.message = message;
  this.code = code || 'server_error';
  this.uri = uri;
  this.status = status || 500;
}

/**
 * Inherit from `Error`.
 */
util.inherits(AuthorizationError, Error);


/**
 * Expose `AuthorizationError`.
 */
module.exports = AuthorizationError;



/**
 * Connections Cloud OAuth Endpoint Errors when obtaining the authorize code
 * https://www-10.lotus.com/ldd/appdevwiki.nsf/xpAPIViewer.xsp?lookupName=API+Reference#action=openDocument&res_title=Step_2_Obtain_authorization_code_sbt&content=apicontent
 *
 * BAD REQUEST (400): oauth_absent_parameters: <parameter_list>
 * The <parameter_list> parameters must be included in the request.
 * BAD REQUEST (400): oauth_duplicated_parameters: <parameter_list>
 * Duplicate parameters were passed with the request.
 * BAD REQUEST (400): oauth_unsupported_parameters: <parameter_list>
 * Unsupported parameters were passed with the request.
 * BAD REQUEST (400): oauth_invalid_parameters:response_type=invalidValue
 * The value of the response_type parameter contains invalid characters. Invalid characters include commas (,) and spaces.
 * UNAUTHORIZED (401): oauth_invalid_responsetype
 * The value of the response_type parameter in the request is not set to code.
 * UNAUTHORIZED (401): oauth_invalid_clientid
 * The client_id parameter is not valid.
 * UNAUTHORIZED (401): Callback URI sent with the request is not the same as the one registered for this Company App
 * The callback_uri parameter that was sent with the request is not the same as the value that is registered for this application.
 * UNAUTHORIZED (401): oauth_consumer_missing_subscription
 * The user is not subscribed to this application.
 * INTERNAL SERVER ERROR (500): oauth_request_failed
 * The OAuth flow failed. Try again or contact the administrator.
 */

/**
 * Connections Cloud OAuth Endpoint Errors when obtaining the access token
 * https://www-10.lotus.com/ldd/appdevwiki.nsf/xpAPIViewer.xsp?lookupName=API+Reference#action=openDocument&res_title=Step_3_Exchange_authorization_code_for_access_and_refresh_tokens_sbt&content=apicontent
 *
 * BAD REQUEST (400): oauth_absent_parameters: <parameter_list>
 * The <parameter_list> parameters must be included in the request.
 * BAD REQUEST (400): oauth_duplicated_parameters: <parameter_list>
 * Duplicate parameters were passed with the request.
 * BAD REQUEST (400): oauth_unsupported_parameters: <parameter_list>
 * Unsupported parameters were passed with the request.
 * BAD REQUEST (400): oauth_invalid_parameters: <parameter_list>
 * Invalid parameters were passed with the request.
 * BAD REQUEST (400): oauth_unsupported_grant_type
 * The grant_type parameter that was passed with the request is not supported by Connections Cloud.
 * UNAUTHORIZED (401): oauth_missing_clientsecret
 * The client_secret parameter is either missing or has a null or empty value in the request.
 * UNAUTHORIZED (401): oauth_missing_callbackurl
 * The callback_uri parameter is either missing or has a null or empty value in the request.
 * UNAUTHORIZED (401): oauth_invalid_clientid
 * The OAuth 2.0 credential is not present or was deleted in Connections Cloud.
 * UNAUTHORIZED (401): Callback URI sent with the request is not the same as the one registered for this Company App
 * The callback_uri parameter that was sent with the request is not the same as the value that is registered for the application.
 * UNAUTHORIZED (401): fail decrypt client secret
 * The client secret cannot be decrypted.
 * UNAUTHORIZED (401): Service Component not found
 * The application associated with the credentials that were passed with the request cannot be found in Connections Cloud.
 * UNAUTHORIZED (401): oauth_missing_authorizationcode
 * The authorization_code parameter is missing from the request.
 * UNAUTHORIZED (401): oauth_invalid_authorizationcode
 * The authorization_code parameter is not valid.
 * UNAUTHORIZED (401): oauth_authorization_code_expired
 * The authorization code has expired.
 * UNAUTHORIZED (401): oauth_access_token_expired
 * The access token has expired.
 * UNAUTHORIZED (401): refresh token encrypt failure
 * The refresh token cannot be encrypted.
 * UNAUTHORIZED (401): fail decrypt refresh token
 * The refresh token cannot be decrypted.
 * INTERNAL SERVER ERROR (500): oauth_request_failed
 * The OAuth flow failed. Try again or contact the administrator.
 */
