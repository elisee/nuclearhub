path = require 'path'
config = require './config'
signedRequest = require 'signed-request'

# Application
express = require 'express'
expose = require 'express-expose'
app = express()

app.set 'port', config.internalPort
app.set 'views', path.join __dirname, 'views'
app.set 'view engine', 'jade'

env = app.get 'env'
baseURL = "http://#{config.domain}"
baseURL += ":#{config.publicPort}" if config.publicPort != 80

RedisStore = require('connect-redis')(express)
sessionStore = new RedisStore { db: config.redisDbIndex, ttl: 3600 * 24 * 14, prefix: "#{config.appId}sess:" }

# Apps
registeredAppsById =
  Home:
    public:
      id: 'Home'
      name: "Home"
      URL: 'http://home.sparklinlabs.com'
    secret: ''
  NuclearNode:
    public:
      id: 'NuclearNode'
      name: "NuclearNode"
      URL: 'http://nuclearnode.dev:3000'
    secret: '|gt82k5n573i7xs~YP9L}+wpPA-OmH'
  MasterOfTheGrid:
    public:
      id: 'MasterOfTheGrid'
      name: "Master of the Grid"
      URL: 'http://masterofthegrid.net'
    secret: ''
  BombParty:
    public:
      id: 'BombParty'
      name: "BombParty"
      URL: 'http://bombparty.sparklinlabs.com'
    secret: ''
  DailyFrenzy:
    public:
      id: 'DailyFrenzy'
      name: "The Daily Frenzy Challenge"
      URL: 'http://frenzy.sparklinlabs.com'
    secret: ''

defaultAppPublics = [ registeredAppsById.Home.public, registeredAppsById.NuclearNode.public, registeredAppsById.MasterOfTheGrid.public, registeredAppsById.BombParty.public, registeredAppsById.DailyFrenzy.public ]

# Authentication
passport = require 'passport'
passport.serializeUser (user, done) -> done null, user
passport.deserializeUser (obj, done) -> done null, obj

TwitterStrategy = require('passport-twitter').Strategy
passport.use new TwitterStrategy
    consumerKey: config.twitter.consumerKey,
    consumerSecret: config.twitter.consumerSecret
    callbackURL: baseURL + "/auth/twitter/callback"
  , (token, tokenSecret, profile, done) ->
    done null, 
      authId: "twitter#{profile._json.id_str}"
      twitterId: profile._json.id_str
      twitterHandle: profile.username
      displayName: profile.displayName
      pictureURL: profile.photos[0].value
      twitterToken: token
      twitterTokenSecret: tokenSecret

TwitchtvStrategy = require('passport-twitchtv').Strategy
passport.use new TwitchtvStrategy
    clientID: config.twitchtv.clientID,
    clientSecret: config.twitchtv.clientSecret
    callbackURL: baseURL + "/auth/twitchtv/callback"
  , (accessToken, refreshToken, profile, done) ->
    done null, 
      authId: "twitchtv#{profile._json._id.toString()}",
      twitchtvId: profile._json._id.toString()
      twitchtvHandle: profile.username.toLowerCase()
      displayName: profile._json.display_name
      pictureURL: profile._json.logo
      twitchtvToken: accessToken
      twitchtvRefreshToken: refreshToken

# Middlewares
app.use express.logger('dev') if 'development' == env

app.use require('static-asset') __dirname + '/public/'
app.use express.static __dirname + '/public/'

app.use express.json()
app.use express.urlencoded()
app.use express.cookieParser config.sessionSecret
app.use express.session { key: "#{config.appId}.sid", cookie: { domain: '.' + config.domain, maxAge: 3600 * 24 * 14 * 1000 }, store: sessionStore }
app.use passport.initialize()
app.use passport.session()
require('nuclear-i18n')(app)
app.use app.router

app.use express.errorHandler() if 'development' == env

# Routes
app.get '/', (req, res) -> res.render 'index', appTitle: config.title

nextGuestId = 0

app.get '/apps/:appId/:channelName', (req, res) ->
  app = registeredAppsById[req.params.appId]
  return res.send 400, error: "Unknown app" if ! app?

  data =
    apps: defaultAppPublics

  if req.user?
    data.authId = req.user.authId # FIXME: This may or may not make sense. Have a NuclearHub ID instead?
    data.displayName = req.user.displayName
    data.pictureURL = req.user.pictureURL
  else
    data.authId = "guest#{nextGuestId}"
    data.displayName = "Guest #{nextGuestId++}"
    data.isGuest = true

  res.render 'app',
    signedData: signedRequest.stringify data, app.secret
    path: "#{app.public.URL}/play/#{req.params.channelName}"

app.get '/auth/twitter', (req, res, next) ->
  req.session.returnTo = req.query.redirect if req.query.redirect?
  passport.authenticate('twitter')(req, res, next)
app.get '/auth/twitter/callback', passport.authenticate 'twitter', { successReturnToOrRedirect: '/', failureRedirect: '/' }

app.get '/auth/twitchtv', (req, res, next) ->
  req.session.returnTo = req.query.redirect if req.query.redirect?
  passport.authenticate('twitchtv', scope: [ 'user_read' ])(req, res, next)
app.get '/auth/twitchtv/callback', passport.authenticate 'twitchtv', { successReturnToOrRedirect: '/', failureRedirect: '/' }

app.get '/logout', (req, res) -> req.logout(); res.redirect req.query.redirect or '/'

http = require 'http'
server = http.createServer app

# Listen
server.listen app.get('port'), ->
  console.log "#{config.appId} server listening on port " + app.get('port')
