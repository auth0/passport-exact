/**
 * Module dependencies.
 */
var util = require('util') 
  ,xml2json = require('xml2json')
  ,OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  ,InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Exact authentication strategy authenticates requests by delegating to
 * Exact using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`    your exact application's client id
 *   - `clientSecret` your exact application's client secret
 *   - `baseUrl`  the base Url for the Exact servers. If not specified: https://start.exactonline.nl
 *   - `callbackURL`    URL to which uber will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new uberStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
           baseUrl: 'https://start.exactonline.nl'
 *         callbackURL: 'https://www.example.net/auth/exact/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
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
  options.baseUrl = options.baseUrl || 'https://start.exactonline.nl';
  options.authorizationURL = options.baseUrl + '/api/oauth2/auth';
  options.tokenURL = options.baseUrl + '/api/oauth2/token';
  
  OAuth2Strategy.call(this, options, verify);
  this.name = 'exact';
  this.baseUrl = options.baseUrl;
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Exact.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `exact`
 *   - `id`
 *   - `displayName`      FirstName + " " + LastName
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {

  this._oauth2._request('GET', this.baseUrl + '/api/v1/current/Me', 
                        {Authorization: "Bearer " + accessToken },
                        null, 
                        accessToken, 
                        function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
    
    try {

      var json = xml2json.toJson(body, {object:true});
      
      var profile = { provider: 'exact' };

      var properties = json.feed.entry.content["m:properties"];

      profile.id = properties['d:UserID']['$t'];
      profile.displayName = properties['d:FirstName'] + " " + 
                            properties['d:LastName'];
      
      profile._json = json;
      profile._xml = body;
      
      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
