import express from "express";
import bodyParser from "body-parser";
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from "passport";
import { Strategy } from "passport-local";
import env from 'dotenv';

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
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: 'postgres',
  password: '1234',
  host: 'localhost',
  database: 'Secrets',
  port: 5432
})
db.connect((err) => {
  if(err){
    console.log('Failed to connect to Database', err)
  }else{
    console.log('Connection Successfully')
  }
})

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get('/secrets', (req, res) => {
  if(req.isAuthenticated()){
    res.render("secrets.ejs")
  }else{
    res.redirect('/')
  }
})

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

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
  })
);

passport.use(
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

passport.serializeUser((user, cb) => {
  cb(null, user);

});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
