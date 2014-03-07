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
defaultAppPublics = ( registeredApp.public for registeredAppId, registeredApp of config.registeredAppsById )

# Authentication
passport = require 'passport'
passport.serializeUser (user, done) -> done null, user
passport.deserializeUser (obj, done) -> done null, obj

SteamStrategy = require('passport-steam').Strategy
passport.use new SteamStrategy
    returnURL: baseURL + '/auth/steam/callback',
    realm: baseURL
    apiKey: config.steam.apiKey
  , (identifier, profile, done) ->
    done null, 
      authId: "steam:#{profile.id}",
      steamId: profile.id
      serviceHandles: { steam: null }
      displayName: profile.displayName
      pictureURL: profile.photos[0].value

TwitchStrategy = require('passport-twitchtv').Strategy
passport.use new TwitchStrategy
    clientID: config.twitch.clientID,
    clientSecret: config.twitch.clientSecret
    callbackURL: baseURL + '/auth/twitch/callback'
  , (accessToken, refreshToken, profile, done) ->
    done null, 
      authId: "twitch:#{profile._json._id.toString()}",
      twitchId: profile._json._id.toString()
      serviceHandles: { twitch: profile.username.toLowerCase() }
      displayName: profile._json.display_name
      pictureURL: profile._json.logo
      twitchToken: accessToken
      twitchRefreshToken: refreshToken

TwitterStrategy = require('passport-twitter').Strategy
passport.use new TwitterStrategy
    consumerKey: config.twitter.consumerKey,
    consumerSecret: config.twitter.consumerSecret
    callbackURL: baseURL + '/auth/twitter/callback'
  , (token, tokenSecret, profile, done) ->
    done null, 
      authId: "twitter:#{profile._json.id_str}"
      twitterId: profile._json.id_str
      serviceHandles: { twitter: profile.username }
      displayName: profile.displayName
      pictureURL: profile.photos[0].value
      twitterToken: token
      twitterTokenSecret: tokenSecret

FacebookStrategy = require('passport-facebook').Strategy
passport.use new FacebookStrategy
    clientID: config.facebook.clientID
    clientSecret: config.facebook.clientSecret
    callbackURL: baseURL + '/auth/facebook/callback'
    profileFields: ['id', 'displayName', 'photos']
  , (accessToken, refreshToken, profile, done) ->
    done null,
      authId: "facebook:#{profile.id}"
      facebookId: profile.id
      serviceHandles: { facebook: profile.username }
      displayName: profile.displayName
      pictureURL: profile.photos[0].value

GoogleStrategy = require('passport-google-oauth').OAuth2Strategy
passport.use new GoogleStrategy
    clientID: config.google.clientID
    clientSecret: config.google.clientSecret
    callbackURL: baseURL + '/auth/google/callback'
  , (accessToken, refreshToken, profile, done) ->
    done null, 
      authId: "google:#{profile.id}",
      googleId: profile.id
      serviceHandles: { google: null }
      displayName: profile.displayName
      pictureURL: profile._json.picture

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

app.get '/apps/:appId/*', (req, res) ->
  app = config.registeredAppsById[req.params.appId]
  return res.send 400, error: "Unknown app" if ! app?

  data =
    apps: defaultAppPublics

  if req.user?
    data.authId = req.user.authId # FIXME: This may or may not make sense. Have a NuclearHub ID instead?
    data.displayName = req.user.displayName
    data.pictureURL = req.user.pictureURL
    data.serviceHandles = req.user.serviceHandles
  else
    data.authId = "guest:#{nextGuestId}"
    data.serviceHandles = { guest: null }
    data.displayName = "Guest #{nextGuestId++}"
    data.isGuest = true

  res.render 'app',
    signedData: signedRequest.stringify data, app.secret
    path: "#{app.public.URL}/#{req.params[0]}"

app.get '/auth/steam', (req, res, next) ->
  req.session.returnTo = req.query.redirect if req.query.redirect?
  passport.authenticate('steam')(req, res, next)
app.get '/auth/steam/callback', passport.authenticate 'steam', { successReturnToOrRedirect: '/', failureRedirect: '/' }

app.get '/auth/twitch', (req, res, next) ->
  req.session.returnTo = req.query.redirect if req.query.redirect?
  passport.authenticate('twitchtv', scope: [ 'user_read' ])(req, res, next)
app.get '/auth/twitch/callback', passport.authenticate 'twitchtv', { successReturnToOrRedirect: '/', failureRedirect: '/' }

app.get '/auth/twitter', (req, res, next) ->
  req.session.returnTo = req.query.redirect if req.query.redirect?
  passport.authenticate('twitter')(req, res, next)
app.get '/auth/twitter/callback', passport.authenticate 'twitter', { successReturnToOrRedirect: '/', failureRedirect: '/' }

app.get '/auth/facebook', (req, res, next) ->
  req.session.returnTo = req.query.redirect if req.query.redirect?
  passport.authenticate('facebook')(req, res, next)
app.get '/auth/facebook/callback', passport.authenticate 'facebook', { successReturnToOrRedirect: '/', failureRedirect: '/' }

app.get '/auth/google', (req, res, next) ->
  req.session.returnTo = req.query.redirect if req.query.redirect?
  passport.authenticate('google', scope: [ 'https://www.googleapis.com/auth/userinfo.profile' ] )(req, res, next)
app.get '/auth/google/callback', passport.authenticate 'google', { successReturnToOrRedirect: '/', failureRedirect: '/' }


app.get '/logout', (req, res) -> req.logout(); res.redirect req.query.redirect or '/'

http = require 'http'
server = http.createServer app

# Online users tracking
socketio = require 'socket.io'
io = socketio.listen(server)
io.set 'log level', 1
io.set 'transports', [ 'websocket' ]

usersByAppId = {}
dirtyUsersByAppId = {}
appUsersDirty = false

io.sockets.on 'connection', (socket) ->

  socket.on 'app', (appId) ->
    return socket.disconnect() if socket.appId? or ! config.registeredAppsById[appId]?

    socket.appId = appId
    appUsersDirty = true

    usersByAppId[appId] = 0 if ! usersByAppId[appId]?
    usersByAppId[appId]++
    dirtyUsersByAppId[appId] = usersByAppId[appId]

    socket.emit 'appUsers', usersByAppId
    return

  socket.on 'disconnect', ->
    return if ! socket.appId?

    appUsersDirty = true
    usersByAppId[socket.appId]--
    dirtyUsersByAppId[socket.appId] = usersByAppId[socket.appId]
    return

broadcastAppUsers = ->
  return if ! appUsersDirty

  io.sockets.emit 'appUsers', dirtyUsersByAppId
  dirtyUsersByAppId = {}
  appUsersDirty = false
  return

setInterval broadcastAppUsers, config.appUsersBroadcastInterval

# Listen
server.listen app.get('port'), ->
  console.log "#{config.appId} server listening on port " + app.get('port')
