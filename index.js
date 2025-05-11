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
  //add ejs
  app.set('view engine', 'ejs');

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

  const navLinks = [
          { name: "Home", path: "/" },
          { name: "Cats", path: "/members" },
          { name: "Login", path: "/login" },
          { name: "Admin", path: "/admin" },
          { name: "404", path: "/doesnotexist" }
  ];

  app.get("/", (req, res) => {
    res.render('index', {user:req.session.user, currentPath:"/", navLinks});
  });

  app.get("/signup", (req, res) => {
    res.render('signup',{error:null, currentPath: "/login", navLinks});
  });

  app.post("/submitUser", async (req, res) => {
    const { name, email, password } = req.body;
    const userCollection = req.app.locals.userCollection;

    if(!name || !email || !password)
    {
      let errorMsg = !name ? "Name is required"
                    :!email ? "Email is required"
                    :"Password is required"
      return res.status(400).render("signup", {error:errorMsg, currentPath:"/login", navLinks});
    }


    const schema = Joi.object({
      name: Joi.string().alphanum().max(20).required(),
      email: Joi.string().email().max(50).required(),
      password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error) {
      return res.status(400).render("signup", {
      error: validationResult.error.details[0].message,
      currentPath:"/login",
      navLinks});
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, password: hashedPassword , user_type : "user"});
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.user={name, email, user_type:"user"};
    req.session.cookie.maxAge = expireTime;

    res.redirect("/");
  });

  app.get("/login", (req,res)=>
  {
    res.render('login', {error:null, currentPath:"/login", navLinks});
  })

  app.post("/loggingin", async (req, res) => {
    const { email, password } = req.body;
    const userCollection = req.app.locals.userCollection;

    const schema = Joi.object({
      email: Joi.string().email().max(50).required(),
      password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error) {
      return res.status(400).render("login", {error:"Invalid email or password format",currentPath:"/login", navLinks});
    }

    const user = await userCollection.findOne({email});
    if(!user || !(await bcrypt.compare(password, user.password)))
    {
      return res.status(401).render("login", {error:"Invalid email or password", currentPath:"/login", navLinks});
    }

    req.session.authenticated = true;
    req.session.user={
      name: user.name,
      email: user.email,
      user_type: user.user_type || "user"
    };

    req.session.cookie.maxAge = expireTime;

    res.redirect("/");

  });


function isAuthenticated(req,res,next){
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }
  next();
}

function isAdmin(req,res,next){
  if (!req.session.user || req.session.user.user_type !== "admin") {
    return res.status(403).render("admin", 
      {
        error:"You are not athorized", 
        currentPath:"/admin",
        navLinks
      });
   } 
   next();
}

app.get("/members", isAuthenticated, (req, res) => {
  res.render("cats",{currentPath:"/members", navLinks});
});


app.get("/admin", isAuthenticated, isAdmin, async(req, res)=>{
  const users = await userCollection.find({}).toArray();
  res.render("admin", {users, error:null, currentPath:"/admin", navLinks});
});

app.get("/admin/demote/:email", isAuthenticated, isAdmin, async(req,res)=>{
    const email = req.params.email;
    await userCollection.updateOne(
      {email},
      {$set : {user_type:"user"}}
    );

    res.redirect("/admin");
});


app.get("/admin/promote/:email", isAuthenticated, isAdmin, async(req,res)=>{
    const email = req.params.email;
    await userCollection.updateOne(
      {email},
      {$set : {user_type:"admin"}}
    );

    res.redirect("/admin");
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
    res.render("404",{currentPath:"/doesnotexist", navLinks});
  });

  app.listen(port, () => {
	console.log("Node application listening on port "+port);
          }); 
}

startServer();