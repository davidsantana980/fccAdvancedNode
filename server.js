'use strict';
const routes = require("./routes.js");
const auth = require("./auth.js")
require('dotenv').config();
const express = require('express');
const myDB = require('./connection');
const fccTesting = require('./freeCodeCamp/fcctesting.js');
const session = require("express-session");
const passport = require("passport");
const URI = process.env.MONGO_URI;

const app = express();

const http = require('http').createServer(app);

const passportSocketIo = require("passport.socketio");
const MongoStore = require("connect-mongo")(session);
const cookieParser = require("cookie-parser");

const io = require('socket.io')(http);
const store = new MongoStore({ url: URI });

fccTesting(app); //For FCC testing purposes
app.use('/public', express.static(process.cwd() + '/public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret:process.env.SESSION_SECRET,
  resave: true,
  key: 'express.sid',
  saveUninitialized: true,
  cookie: {secure:false}
}));
const cors = require('cors')
app.use(cors())

app.use(passport.initialize(), passport.session());

app.set("view engine", "pug");
app.set("views", "./views/pug");

io.use(
  passportSocketIo.authorize({
    cookieParser: cookieParser,
    key: 'express.sid',
    secret: process.env.SESSION_SECRET,
    store: store,
    success: onAuthorizeSuccess,
    fail: onAuthorizeFail
  })
);

myDB(async client => {
  const myDataBase = await client.db('database').collection('users');

  routes(app, myDataBase);
  auth(app, myDataBase); 

  let currentUsers = 0;
  io.on('connection', socket => {
    currentUsers++;
    // io.emit('user count', currentUsers);
    io.emit('user', {
      username: socket.request.username,
      currentUsers,
      connected:true
    });

    socket.on("chat message", (message) => {
      io.emit("chat message", {username: socket.request.user.username, message})
    })

    console.log('user ' + socket.request.user.username + ' connected');

    socket.on('disconnect', () => {
      console.log('A user has disconnected');
      currentUsers--;
      io.emit('user count', currentUsers);
    })
  });
}).catch(e => {
  app.route('/').get((req, res) => {
    res.render('index', { title: e, message: 'Unable to connect to database' });
  });
});

function onAuthorizeSuccess(data, accept) {
  console.log('successful connection to socket.io');

  accept(null, true);
}

function onAuthorizeFail(data, message, error, accept) {
  if (error) throw new Error(message);
  console.log('failed connection to socket.io:', message);
  accept(null, false);
}

const PORT = process.env.PORT || 3000;
http.listen(PORT, () => {
  console.log('Listening on port ' + PORT);
});

