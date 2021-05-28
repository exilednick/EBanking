const express = require('express');
const cookieSession = require('cookie-session')
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20');
const LocalStrategy = require('passport-local').Strategy
const config = require('./config');
const flash = require('express-flash');
const bcrypt = require('bcrypt');
const MongoClient = require('mongodb').MongoClient;

const app = express();

app.set('view engine', 'ejs');
app.use(flash());
app.use(cookieSession({
    maxAge: 24*60*60*1000,
    keys:['djachdjcddcd'],
    resave: false,
    saveUninitialized: false
}))
app.use(express.urlencoded({extended:false}));

app.use(passport.initialize());
app.use(passport.session())

async function loadUsers() {
    const client = await MongoClient.connect(config.db.uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    return client.db('EBanking').collection('users');
}

passport.serializeUser((user, done) => {
    done(null, user)
});

passport.deserializeUser(async(user, done) => {
    done(null, user);
});

passport.use(
    new LocalStrategy(async(username, password, done) => {
        const users = await loadUsers();
        const user = await users.findOne({
            username: username,
        });
        if(!user || !(await bcrypt.compare(password, user.password))) {
            return done(null, false, {message: "Incorrect username or password"});
        } else if(user)
            done(null, user);
    })
)

passport.use(
    new GoogleStrategy({
        clientID: config.auth.google_client_id,
        clientSecret: config.auth.google_client_secret,
        callbackURL: config.auth.redirect_uri
    }, async(accessToken, refreshToken, profile, done) => {
        const users = await loadUsers();

        const user = await users.findOne({
            googleId: profile.id
        })

        if(user) {
            done(null, user)
        }
        else {
            try {
                users.insertOne({
                    username: profile.displayName,
                    googleId: profile.id,
                    email: profile.emails[0].value,
                    balance: 0
                }, (err, resp) => {
                    done(null, resp.ops[0])
                })

            } catch(err) {
                console.log(err);
            }
        }
    }
))

app.get('/auth/login', async(req, res) => {
    if(req.user)
        res.redirect('/');
    else 
        res.render('login', {user: null});
})

app.get('/auth/logout', (req, res) => {
    req.logout();
    res.redirect('/')
})

app.get('/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

app.get('/auth/google/callback',passport.authenticate('google', {session: true}), (req, res) => {
    res.redirect('/profile');
})

app.post('/auth/local', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/auth/login',
    failureFlash: true
}))

app.get('/', async(req, res) => {
    res.render('home', {user:req.user});
})

app.post('/register', async(req, res) => {

    if(req.body.password.length < 8) {
        req.flash('info', 'Password should have atleast 8 characters');
        res.redirect('/register');
    } else {
        const users = await loadUsers();
        const user = await users.findOne({
            username: req.body.username
        });
        if(user) {
            req.flash('info', 'This username already exists');
            return res.redirect('/register');
        }
        const password = await bcrypt.hash(req.body.password, 10);
        await users.insertOne({
            username: req.body.username,
            password: password,
            balance: 0
        });
        res.redirect('/auth/login')
    }
})

app.get('/register', (req, res) => {
    res.render('register', {user:req.user});
})

app.get('/profile', async(req, res) => {
    const users = await loadUsers();
    const user = await users.findOne({  
        username: req.user.username
    });
    res.render('profile', {user:req.user, balance: user.balance})
})

app.post('/transfer', async(req, res) => {

    if(isNaN(req.body.amount)) {
        req.flash("error","Please enter correct value");
        res.redirect('/profile')
    } else {
        const users = await loadUsers();
        if(req.body.type === 'deposit') {
            await users.updateOne({
                username: req.user.username
            }, {
                $inc: { balance: parseInt(req.body.amount) }
            })
        } else {
            await users.updateOne({
                username: req.user.username
            }, {
                $inc: { balance: parseInt(-req.body.amount) }
            })
        }

        res.redirect('/profile');
    }
})

app.listen(5000, () => console.log('server started'));