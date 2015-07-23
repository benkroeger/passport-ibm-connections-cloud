[![NPM info](https://nodei.co/npm/passport-ibm-connections-cloud.png?downloads=true)](https://nodei.co/npm/passport-ibm-connections-cloud.png?downloads=true)

[![dependencies](https://david-dm.org/benkroeger/passport-ibm-connections-cloud.png)](https://david-dm.org/benkroeger/passport-ibm-connections-cloud.png)

> Passport oAuth 2.0 Strategy for IBM Connections Cloud


## Install

```sh
$ npm install --save passport-ibm-connections-cloud
```


## Usage

```javascript
var express = require('express'),
  passport = require('passport'),
  IBMConnectionsCloudStrategy = require('passport-ibm-connections-cloud').Strategy;
var app = express();

// setup passport to use this strategy
passport.use(new IBMConnectionsCloudStrategy({
  hostname: 'apps.na.collabserv.com',
  clientID: 'your client id',
  clientSecret: 'your client secret',
  callbackURL: 'https://your-host.com/auth/ibm-connections-cloud/callback' //https is important here. Connections Cloud doesn't accept http callback urls
  },
  function(accessToken, refreshToken, params, profile, done) {
    // do your magic to load or create a local user here
    done();
  }
));

var router = express.Router();
router
  .get('/', passport.authenticate('ibm-connections-cloud', {
    session: false
  }))
  .get('/callback', passport.authenticate('ibm-connections-cloud', {
    failureRedirect: '/account/login',
    session: false
  }), function(req, res, next){
    // e.g. create a jwt for your application and return to client
  });
  
app.use('/auth/ibm-connections-cloud', router);

```

## License

MIT © [Benjamin Kroeger]()


[npm-url]: https://npmjs.org/package/passport-ibm-connections-cloud
[npm-image]: https://badge.fury.io/js/passport-ibm-connections-cloud.svg
[daviddm-url]: https://david-dm.org/benkroeger/passport-ibm-connections-cloud.svg?theme=shields.io
[daviddm-image]: https://david-dm.org/benkroeger/passport-ibm-connections-cloud
