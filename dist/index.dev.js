"use strict";

require("./utils");

require("dotenv").config();

var express = require("express");

var session = require("express-session");

var MongoStore = require("connect-mongo");

var bcrypt = require("bcrypt");

var Joi = require("joi");

var _require = require("./databaseConnection"),
    connectToDatabase = _require.connectToDatabase;

var saltRounds = 12;
var port = process.env.PORT || 3000;
var app = express();
var expireTime = 1 * 60 * 60 * 1000;
var mongodb_host = process.env.MONGODB_HOST;
var mongodb_user = process.env.MONGODB_USER;
var mongodb_password = process.env.MONGODB_PASSWORD;
var mongodb_database = process.env.MONGODB_DATABASE;
var mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
var node_session_secret = process.env.NODE_SESSION_SECRET;

function startServer() {
  var db, userCollection, mongoStore;
  return regeneratorRuntime.async(function startServer$(_context3) {
    while (1) {
      switch (_context3.prev = _context3.next) {
        case 0:
          _context3.next = 2;
          return regeneratorRuntime.awrap(connectToDatabase());

        case 2:
          db = _context3.sent;
          userCollection = db.collection("user");
          app.locals.userCollection = userCollection;
          app.use(express.urlencoded({
            extended: false
          })); //add ejs

          app.set('view engine', 'ejs');
          mongoStore = MongoStore.create({
            mongoUrl: "mongodb+srv://".concat(mongodb_user, ":").concat(mongodb_password, "@").concat(mongodb_host, "/sessions"),
            crypto: {
              secret: mongodb_session_secret
            }
          });
          app.use(session({
            secret: node_session_secret,
            store: mongoStore,
            saveUninitialized: false,
            resave: true
          }));
          app.get("/", function (req, res) {
            res.render('index', {
              user: req.session.user
            });
          });
          app.get("/signup", function (req, res) {
            res.render('signup');
          });
          app.post("/submitUser", function _callee(req, res) {
            var _req$body, name, email, password, userCollection, errorMsg, schema, validationResult, hashedPassword;

            return regeneratorRuntime.async(function _callee$(_context) {
              while (1) {
                switch (_context.prev = _context.next) {
                  case 0:
                    _req$body = req.body, name = _req$body.name, email = _req$body.email, password = _req$body.password;
                    userCollection = req.app.locals.userCollection;

                    if (!(!name || !email || !password)) {
                      _context.next = 5;
                      break;
                    }

                    errorMsg = !name ? "Name is required" : !email ? "Email is required" : "Password is required";
                    return _context.abrupt("return", res.status(400).render("signup", {
                      error: errorMsg
                    }));

                  case 5:
                    schema = Joi.object({
                      name: Joi.string().alphanum().max(20).required(),
                      email: Joi.string().email().max(50).required(),
                      password: Joi.string().max(20).required()
                    });
                    validationResult = schema.validate({
                      name: name,
                      email: email,
                      password: password
                    });

                    if (!validationResult.error) {
                      _context.next = 9;
                      break;
                    }

                    return _context.abrupt("return", res.status(400).render("signup", {
                      error: "Invalid input format"
                    }));

                  case 9:
                    _context.next = 11;
                    return regeneratorRuntime.awrap(bcrypt.hash(password, saltRounds));

                  case 11:
                    hashedPassword = _context.sent;
                    _context.next = 14;
                    return regeneratorRuntime.awrap(userCollection.insertOne({
                      name: name,
                      email: email,
                      password: hashedPassword
                    }));

                  case 14:
                    console.log("Inserted user");
                    req.session.authenticated = true;
                    req.session.user = {
                      name: name,
                      email: email,
                      user_type: "user"
                    };
                    req.session.cookie.maxAge = expireTime;
                    res.redirect("/");

                  case 19:
                  case "end":
                    return _context.stop();
                }
              }
            });
          });
          app.post("/login", function _callee2(req, res) {
            var _req$body2, email, password, userCollection, schema, validationResult, user;

            return regeneratorRuntime.async(function _callee2$(_context2) {
              while (1) {
                switch (_context2.prev = _context2.next) {
                  case 0:
                    _req$body2 = req.body, email = _req$body2.email, password = _req$body2.password;
                    userCollection = req.app.locals.userCollection;
                    schema = Joi.object({
                      email: Joi.string().email().max(50).required(),
                      password: Joi.string().max(20).required()
                    });
                    validationResult = schema.validate({
                      email: email,
                      password: password
                    });

                    if (!validationResult.error) {
                      _context2.next = 6;
                      break;
                    }

                    return _context2.abrupt("return", res.status(400).render("login", {
                      error: "Invalid email or password format"
                    }));

                  case 6:
                    _context2.next = 8;
                    return regeneratorRuntime.awrap(userCollection.findOne({
                      email: email
                    }));

                  case 8:
                    user = _context2.sent;
                    _context2.t0 = !user;

                    if (_context2.t0) {
                      _context2.next = 14;
                      break;
                    }

                    _context2.next = 13;
                    return regeneratorRuntime.awrap(bcrypt.compare(password, user.password));

                  case 13:
                    _context2.t0 = !_context2.sent;

                  case 14:
                    if (!_context2.t0) {
                      _context2.next = 16;
                      break;
                    }

                    return _context2.abrupt("return", res.status(401).render("login", {
                      error: "Invalid email or password"
                    }));

                  case 16:
                    req.session.authenticated = true;
                    req.session.user = {
                      name: user.name,
                      email: user.email,
                      user_type: user.user_type || "user"
                    };
                    req.session.cookie.maxAge = expireTime;
                    res.redirect("/");

                  case 20:
                  case "end":
                    return _context2.stop();
                }
              }
            });
          });
          app.get("/cats", function (req, res) {
            if (!req.session.authenticated) {}
          });
          app.get("/logout", function (req, res) {
            req.session.destroy(function (err) {
              if (err) {
                console.log("Logout error:", err);
                res.send("Error logging out");
              } else {
                res.redirect('/');
              }
            });
          });
          app.use(express["static"](__dirname + "/public"));
          app.get("*", function (req, res) {
            res.render("404");
          });
          app.listen(port, function () {
            console.log("Node application listening on port " + port);
          });

        case 18:
        case "end":
          return _context3.stop();
      }
    }
  });
}

startServer();