require("./utils");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { connectToDatabase } = require("./databaseConnection");

const saltRounds = 12;
const port = process.env.PORT || 3000;
const app = express();
const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

async function startServer() {
  const db = await connectToDatabase();
  const userCollection = db.collection("user");
  app.locals.userCollection = userCollection;

  app.use(express.urlencoded({ extended: false }));

  const mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
      secret: mongodb_session_secret,
    },
  });

  app.use(
    session({
      secret: node_session_secret,
      store: mongoStore,
      saveUninitialized: false,
      resave: true,
    })
  );

  app.get("/", (req, res) => {
    if (req.session.authenticated) {
      res.redirect("/loggedin");
    } else {
      res.send(`
        <form action="/signup" method="get">
          <button type="submit">Sign up</button>
        </form>
        <form action="/login" method="get">
          <button type="submit">Log in</button>
        </form>
      `);
    }
  });

  app.get("/signup", (req, res) => {
    res.send(`
      <h3>create user</h3>
      <form action='/submitUser' method='post'>
        <input name='name' type='text' placeholder='name'>
        <input name='email' type='email' placeholder='email'>
        <input name='password' type='password' placeholder='password'>
        <button>Submit</button>
      </form>
    `);
  });

  app.post("/submitUser", async (req, res) => {
    const { name, email, password } = req.body;
    const userCollection = req.app.locals.userCollection;

          if(!name)
          {
                    var html=`
                     <h3>Name is required</h3>
                     <a href="/signup">Try again</a>
                    `;
                    res.send(html);
                    return;
          }
          else if(!email)
          {
                    var html=`
                     <h3>Email is required</h3>
                     <a href="/signup">Try again</a>
                    `;
                    res.send(html);
                    return;
          }
          else if(!password)
          {
                    var html=`
                     <h3>Password is required</h3>
                     <a href="/signup">Try again</a>
                    `;
                    res.send(html);
                    return;
          }

    const schema = Joi.object({
      name: Joi.string().alphanum().max(20).required(),
      email: Joi.string().email().max(50).required(),
      password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error) {
      res.redirect("/signup");
      return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, password: hashedPassword });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedin");
  });

  app.get("/login", (req, res) => {
    res.send(`
      <h3>log in</h3>
      <form action='/loggingin' method='post'>
        <input name='email' type='email' placeholder='email'>
        <input name='password' type='password' placeholder='password'>
        <button>Submit</button>
      </form>
    `);
  });

  app.post("/loggingin", async (req, res) => {
    const { email, password } = req.body;
    const userCollection = req.app.locals.userCollection;

    const schema = Joi.object({
      email: Joi.string().email().max(50).required(),
      password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error) {
      res.redirect("/login");
      return;
    }

    const result = await userCollection
      .find({ email })
      .project({ email: 1, password: 1, name: 1 })
      .toArray();

    if (result.length !== 1 || !(await bcrypt.compare(password, result[0].password))) {
      res.send("<h3>Invalid email/password combination.<a href='/login'>Try again</a></h3>");
    } else {
      req.session.authenticated = true;
      req.session.email = email;
      req.session.name = result[0].name;
      req.session.cookie.maxAge = expireTime;
      res.redirect("/loggedin");
    }
  });

  app.get("/loggedin", (req, res) => {
    if (!req.session.authenticated) {
      res.redirect("/login");
      return;
    }

    const name = req.session.name;
    res.send(`
      <h3>Welcome, ${name}!</h3>
      <form action='/members' method='get'>
        <button>Go to Members Area</button>
      </form>
      <form action='/logout' method='get'>
        <button>Logout</button>
      </form>
    `);
  });

  app.get("/members", (req, res) => {
    if (!req.session.authenticated) {
          res.redirect("/login");
          return;
          
     }  
    const name = req.session.name;
    const randomIndex = Math.floor(Math.random()*4)+1;
    const imageName = `cat${randomIndex}.jpg`;
    res.send(`
      <h3>Welcome, ${name}!</h3>
      <img src="/${imageName}" alt="cat" width="300" style="border-radius: 12px;">
      <form action='/logout' method='get'>
        <button>Logout</button>
      </form>
    `);
  });

  app.get("/logout", (req, res) => {
    req.session.destroy(err => {
          if(err){
                    console.log("Logout error:", err);
                    res.send("Error logging out");
          }
          else{
                    res.redirect('/');
          }
    });
  });

  app.use(express.static(__dirname + "/public"));

  app.get("*", (req, res) => {
    res.status(404).send("Page not found - 404");
  });

  app.listen(port, () => {
	console.log("Node application listening on port "+port);
          }); 
}

startServer();