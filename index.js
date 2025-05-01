require("./utils");

//set up the .env file and catch the information inside.
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

//expires after 1 day  (hours * minutes * seconds * millis)
const expireTime = 24 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/*END secret setion */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('user');

app.use(express.urlencoded({extended:false}));

var mongoStore = MongoStore.create({
          mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({
          secret: node_session_secret,
          saveUninitialized: false,
          resave:true
}
));

app.get('/', (req, res)=>{
  var html = `
  <form action="/signup" method="get">
          <button type="submit">Sign up</button>
  </form>
  <form action="/login" method="get">
          <button type="submit">Log in</button>
  <form>
  `;
  res.send(html);
});

//Sign up pages
app.get('/signup', (req, res)=>{
          var html =`
          <h3>create user</h3>
          <form action='/submitUser' method ='post'>
          <input name='name' type='text' placeholder = 'name'>
          <input name='email' type='email' placeholder = 'email'>
          <input name='password' type='password' placeholder = 'password'>
          <button>Submit</button>
          </form>
          `;
          res.send(html);
});

//Sign up -> validation -> submitUser -------create session
app.post('/submitUser', async(req,res)=>{
          var name = req.body.name;
          var email = req.body.email;

          var password = req.body.password;

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


          

          //set up the constrictions to inputs
          const schema = Joi.object(
                    {
                              name: Joi.string().alphanum().max(20).required(),
                              email:Joi.string().email().max(50).required(),
                              password: Joi.string().max(20).required()
                    }
          );
          
          //validate the inputs
          const validationResult = schema.validate({name,email,password});
          if(validationResult.error != null){
                    console.log(validationResult.error);
                    res.redirect("/signup");
                    return;
          }

          //if the name is used???

          var hashedPassword = await bcrypt.hash(password, saltRounds);
          
          await userCollection.insertOne({name: name, email: email, password:hashedPassword});
          console.log("Inserted user");

          //how to create a session?---------------
          res.redirect("/members");
});


//Log in
app.get('/login', (req,res)=>{
          var html = `
          <h3>log in</h3>
          <form action='/loggingin' method='post'>
          <input name = 'email' type = 'email' placeholder = 'email'>
          <input name = 'password' type = 'password' placeholder = 'password'>
          <button>Submit</button>
          </form>
          `;
          res.send(html);
});

//Login -> validation -> logedin -> members
app.post('/loggingin', async(req, res)=>{
          var email = req.body.email;
          var password = req.body.password;
          
          const schema = Joi.object(
                    {
                              email:Joi.string().email().max(50).required(),
                              password: Joi.string().max(20).required()
                    }
          );

          const validationResult = schema.validate({email, password});
          if(validationResult.error != null)
          {
                    console.log(validationResult.error);
                    res.redirect("/login");
                    return;
          }

          const result = await userCollection.find({email: email}).project({email:1, password:1, name:1, _id:1}).toArray();
          console.log(result);
          if(result.length != 1 || !await bcrypt.compare(password, result[0].password))
          {
                   var html = `
                    <h3>Invalid email/password combination.
                    <a href="/login">Try again</a>
                   `
                   res.send(html);
          }
          else
          {
                    req.session.authenticated = true;
                    req.session.email = email;
                    req.session.name = result[0].name;
                    req.session.cookie.maxAge = expireTime;
                    res.redirect('/loggedin');
                    return;
          }

});

//logedin page
app.get('/loggedin', (req,res) => {
          if (!req.session.authenticated) {
              res.redirect('/login');
              return;
          }

          const name = req.session.name;

          var html=`
            <h3>Welcome, ${name}!</h3>
            <form action='/members' method = 'get'> 
            <button>Go to Members Area</button>
            </form>
            <form action='/logout' method = 'get'>
            <button>Logout</button>
            </form>
          `
          res.send(html)
});

//members
app.get('/members', (req,res)=>
{
    const name = req.session.name;

    const randomIndex = Math.floor(Math.random()*4);

    var html=`
        <h3>Welcome, ${name}!<h3>
        <img src="/cat.jpg" alt="cat" width="300" style="border-radius: 12px;"> 
        <form action='logout' method = 'get'>
        <button>Logout</button>
        </form>
    `
    res.send(html)
});


//log out
app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/')
});




//at the end 
app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 