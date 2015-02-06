'use strict';

/**
 * Module dependencies.
 */
var util = require('util'),
  OAuth2Strategy = require('passport-oauth2').Strategy,
  Profile = require('./profile'),
  InternalOAuthError = require('passport-oauth2').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The IBM Connections authentication strategy authenticates requests by delegating to
 * IBM Connections using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` [optional `params`] and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 * If the `verify` callback takes the `params` parameter, it will receive all parameters
 * that the oAuth provider sent along with `accessToken` and `refreshToken`
 *
 * Options:
 *   - `clientID`      your IBM Connections application's App ID
 *   - `clientSecret`  your IBM Connections application's App Secret
 *   - `callbackURL`   URL to which IBM Connections will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new IBMConnectionsStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/ibm-connections/callback'
 *       },
 *       function(accessToken, refreshToken, params, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  if (!options.hostname) {
    throw new TypeError('IBMConnectionsCloud oAuth requires a hostname');
  }
  options.authorizationURL = 'https://' + options.hostname + '/manage/oauth2/authorize';
  options.tokenURL = 'https://' + options.hostname + '/manage/oauth2/token';
  options.redirectUriParam = 'callback_uri';
  OAuth2Strategy.call(this, options, verify);
  this._oauth2.useAuthorizationHeaderforGET(true);
  this.name = 'ibm-connections-cloud';
  this._clientSecret = options.clientSecret;
  this._profileURL = 'https://' + options.hostname + '/connections/opensocial/oauth/rest/people/@me/@self';

  // IBM Connections Cloud doesn't support "scope"
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Authenticate request by delegating to IBM Connections using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  OAuth2Strategy.prototype.authenticate.call(this, req, options);
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  var params = {};
  return params;
};

/**
 * Retrieve user's OpenSocial profile from IBM Connections Cloud.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `ibm-connections-cloud`
 *   - `id`               the user's OpenSocial ID (urn:lsid:lconn.ibm.com:profiles.person:xxxx-xxx-x-x-x-x-x)
 *   - `userid`           the users id (id split after 'urn:lsid:lconn.ibm.com:profiles.person:')
 *   - `displayName`      the user's full name
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */


Strategy.prototype.userProfile = function(accessToken, done) {
  var self = this;

  this._oauth2.get(this._profileURL, accessToken, function(err, body) {
    var json;

    if (err) {
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }

    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }

    var profile = Profile.parse(json);
    profile.provider = self.name;
    profile._raw = body;
    profile._json = json;

    done(null, profile);
  });
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  return {};
};

/**
 * Return extra parameters to be included in the token request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting an access token.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @return {Object}
 * @api protected
 */
Strategy.prototype.tokenParams = function(options) {
  return {};
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;