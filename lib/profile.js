/**
 * Parse profile.
 *
 * @param {Object|String} json
 * @return {Object}
 * @api private
 */
exports.parse = function(json) {
  if ('string' === typeof json) {
    json = JSON.parse(json);
  }

  var profile = {};
  profile.id = json.entry.id;
  profile.displayName = json.entry.displayName;
  profile.userid = profile.id.split('urn:lsid:lconn.ibm.com:profiles.person:')[1];

  if (json.entry.emails) {
    profile.emails = json.entry.emails;
  }

  return profile;
};