import express from "express";
import bodyParser from "body-parser";
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from "passport";
import { Strategy } from "passport-local";
import env from 'dotenv';
import GoogleStrategy from 'passport-google-oauth2';

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(session({
  secret: process.env.SESSION_SECRETS,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 *60 * 24
  }
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  port: process.env.PG_PORT
})
db.connect((err) => {
  if(err){
    console.log('Failed to connect to Database', err)
  }else{
    console.log('Connection Successfully')
  }
})

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get('/logout', (req, res) => {
  req.logout(function (err){
    if(err){
      return next(err);
    }
    res.redirect("/")
  })
})

app.get('/secrets', async (req, res) => {
  try {
    const result = req.user;
    if(req.isAuthenticated()){
      const userSecret = (await db.query(
        'SELECT secret FROM users WHERE email = $1', [result.email])).rows[0]
        console.log(userSecret)
      res.render("secrets.ejs", {secret: userSecret.secret})

    }else{
      throw new Error("User is not authenticated!");
    }
  } catch (error) {
    res.redirect('/')
  }
  
})
app.get('/submit', (req, res) => {
  if(req.isAuthenticated()){
    res.render("submit.ejs")
  }else{
    res.redirect('/')
  }
})

app.get('/auth/google', passport.authenticate("google", {
  scope: ["profile", "email"]
}))

app.get('/auth/google/secrets', passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

app.post('/submit', async (req, res) => {
  const input = req.body.secret;
  try {
    if(input){
      const result = await db.query(
        "UPDATE users SET secret = ($1) WHERE email = ($2) RETURNING *", 
        [input, req.user.email]);

      res.redirect('/secrets');
    }else{
     throw new Error("Preencha o campo de segredo!");
    }
  } catch (error) {
    console.log(error)
    res.redirect('/secrets')
  }
})

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username
  const password = req.body.password
  try {
    if(!email || !password){
      throw new Error('Campos nao preenchidos corretamente');
    }
    const checkResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    console.log(checkResult)
    if(checkResult.rows.lenght > 0){
      throw new Error('Email ja cadastrado')
    }
    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if(err){
        console.log("Error hashing password", err);
      }

      const result = await db.query('INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *',[email, hash])
      console.log('Data insered into Database', [email, hash]);
      const user = result.rows[0];
      req.login(user, (err) => {
        console.log(err)
        res.redirect('/secrets')
      })

    })
  } catch (error) {
    console.log('Error:', error);
    res.redirect('/')
  }
});

passport.use("local",
  new Strategy(async function verify(username, password, cb) {
  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', 
      [username]);
    
    if(result.rows.length > 0){
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if(err){
          return cb(err)
        }else{
          if(result){
            return cb(null, user)
          }else{
            return cb(null, false)
          }
        }
      })
    }else {
      return cb('User Not found')
    }
  } catch (error) {
    return cb(error)
  }
}));

passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  }, async (accessToken, refreshToken, profile, cb) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
      if(result.rows.length === 0){
        const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [profile.email, "GOOGLE"])
        cb(null, newUser.rows[0]);
      }else{
        cb(null, result.rows[0]);
      }
    } catch (error) {
      cb(error)
    }
  }
))

passport.serializeUser((user, cb) => {
  cb(null, user);

});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
