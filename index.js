require("./utils.js");

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("database.js");

const userCollection = database.db(mongodb_database).collection("users");

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(session({
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false,
  resave: true
}
));

function isValidSession(req) {  
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  }
  else {
    res.redirect('/login');
  }
}


function isAdmin(req) {
  if (req.session.user_type == 'admin') {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("error", { errorMessage: "Error 403: Not Authorized" });
    return;
  }
  else {
    next();
  }
}

app.get('/', (req, res) => {
  if (!req.session.authenticated) {
    res.render("index");
  }
  const name = req.session.name;
  res.render("homeloggedin", { name: name });
});

app.get('/nosql-injection', async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  //If we didn't use Joi to validate and check for a valid URL parameter below
  // we could run our userCollection.find and it would be possible to attack.
  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
    return;
  }

  const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req, res) => {
  var color = req.query.color;

  res.render("about", { color: color });
});

app.get('/contact', (req, res) => {
  var missingEmail = req.query.missing;

  res.render("contact", { missing: missingEmail });
});

app.get('/signup', (req,res) => {
  res.render("signup")
});

app.get('/login', (req, res) => {
  res.render("login");
});

app.post('/submitEmail', (req, res) => {
  var email = req.body.email;
  if (!email) {
    res.redirect('/contact?missing=1');
  }
  else {
    res.render("submitEmail", { email: email });
  }
});

app.post("/submitUser", async (req, res) => {
  var email = req.body.email;
  var name = req.body.name;
  var password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    name: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, name, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    var errorMessage = validationResult.error.details[0].message;
    res.render("error", { errorMessage: errorMessage });
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    password: hashedPassword,
    email: email,
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.name = name;

  res.redirect("/");
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
    .toArray();

    console.log(result);

  console.log(result);
  if (result.length != 1) {
    console.log("User not found");
    res.render("loggingin", { errorMessage:`Invalid email/password combination`});
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("Correct Password");
    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = result[0].name;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedin");
    return;
  }
  else {
    console.log("Incorrect Password");
    res.render("loggingin", { errorMessage:`Invalid email/password combination`});
    return;
  }
});

app.get('/loggedin', (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
  }
  res.render("loggedin");
});

app.get('/loggedin/info', (req, res) => {
  res.render("loggedin-info");
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.render("loggedout");
});

app.get("/members", (req, res) => {
  if (!req.session.name) {
    res.redirect("/");
    return;
  }

  const name = req.session.name;
  const image = imageURL[Math.floor(Math.random() * imageURL.length)];

  res.render("members", { name: name, image: image });
});

const imageURL = [
  "cat.gif",
  "cat2.jpg",
  "catgifone.gif"
];


app.get('/cat/:id', (req, res) => {
  var cat = req.params.id;

  res.render("cat", { cat: cat });
});


app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
  const result = await userCollection.find().project({ name: 1, user_type: 1 }).toArray();
  console.log(result)

  res.render("admin", { users: result });
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
})



app.listen(port, () => {
  console.log("Node application listening on port " + port);
}); 