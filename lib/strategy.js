'use strict';

/**
 * Module dependencies.
 */
var util = require('util'),
  url = require('url'),
  OAuth2Strategy = require('passport-oauth2').Strategy,
  uid = require('uid2'),
  Profile = require('./profile'),
  utils = require('./utils'),
  InternalOAuthError = require('passport-oauth2').InternalOAuthError,
  AuthorizationError = require('./errors/authorizationerror');


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
// Strategy.prototype.authenticate = function(req, options) {
//   OAuth2Strategy.prototype.authenticate.call(this, req, options);
// };

Strategy.prototype.authenticate = function (req, options) {
  options = options || {};
  var self = this;
  var params, state, key;

  if (req.query && req.query.oauth_error) {
    if (req.query.oauth_error === 'oauth_denied') {
      return this.fail({
        message: req.query.oauth_error_description
      });
    } else {
      return this.error(new AuthorizationError(req.query.oauth_error_description, req.query.oauth_error, req.query.oauth_error_uri));
    }
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, {
        proxy: this._trustProxy
      }), callbackURL);
    }
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    if (this._state) {
      if (!req.session) {
        return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
      }

      key = this._key;
      if (!req.session[key]) {
        return this.fail({
          message: 'Unable to verify authorization request state.'
        }, 403);
      }
      state = req.session[key].state;
      if (!state) {
        return this.fail({
          message: 'Unable to verify authorization request state.'
        }, 403);
      }

      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }

      if (state !== req.query.state) {
        return this.fail({
          message: 'Invalid authorization request state.'
        }, 403);
      }
    }

    params = this.tokenParams(options);
    params.grant_type = 'authorization_code';
    params.callback_uri = callbackURL;

    this._oauth2.getOAuthAccessToken(code, params,
      function (err, accessToken, refreshToken, params) {
        if (err) {
          return self.error(self._createOAuthError('Failed to obtain access token', err));
        }

        self._loadUserProfile(accessToken, function (err, profile) {
          var arity;
          if (err) {
            return self.error(err);
          }

          function verified(err, user, info) {
            if (err) {
              return self.error(err);
            }
            if (!user) {
              return self.fail(info);
            }
            self.success(user, info);
          }

          try {
            if (self._passReqToCallback) {
              arity = self._verify.length;
              if (arity === 6) {
                self._verify(req, accessToken, refreshToken, params, profile, verified);
              } else { // arity == 5
                self._verify(req, accessToken, refreshToken, profile, verified);
              }
            } else {
              arity = self._verify.length;
              if (arity === 5) {
                self._verify(accessToken, refreshToken, params, profile, verified);
              } else { // arity == 4
                self._verify(accessToken, refreshToken, profile, verified);
              }
            }
          } catch (ex) {
            return self.error(ex);
          }
        });
      }
    );
  } else {
    params = this.authorizationParams(options);
    params.response_type = 'code';
    params.callback_uri = callbackURL;
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) {
        scope = scope.join(this._scopeSeparator);
      }
      params.scope = scope;
    }
    state = options.state;
    if (state) {
      params.state = state;
    } else if (this._state) {
      if (!req.session) {
        return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
      }

      key = this._key;
      state = uid(24);
      if (!req.session[key]) {
        req.session[key] = {};
      }
      req.session[key].state = state;
      params.state = state;
    }

    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
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
Strategy.prototype.authorizationParams = function (options) {
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


Strategy.prototype.userProfile = function (accessToken, done) {
  var self = this;

  this._oauth2.get(this._profileURL, accessToken, function (err, body) {
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
Strategy.prototype.authorizationParams = function (options) {
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
Strategy.prototype.tokenParams = function (options) {
  return {};
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;

