const express = require('express');
const cookieSession = require('cookie-session')
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20');
const LocalStrategy = require('passport-local').Strategy
const config = require('./config');
const flash = require('express-flash');
const bcrypt = require('bcrypt');
const MongoClient = require('mongodb').MongoClient;
const ObjectID = require('mongodb').ObjectID;

const app = express();

app.set('view engine', 'ejs');
app.use(flash());
app.use(cookieSession({
    maxAge: 24*60*60*1000,
    keys:['djachdjcddcd']
}))
app.use(express.urlencoded({extended:false}));

app.use(passport.initialize());
app.use(passport.session())

const loadUsers = async() => {
    const client = await MongoClient.connect(config.db.uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    return client.db('EBanking').collection('users');
}

const loadAccounts = async() => {
    const client = await MongoClient.connect(config.db.uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true
      });
      return client.db('EBanking').collection('account');
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
            email: username,
        });
        if(!user || !(await bcrypt.compare(password, user.password))) {
            return done(null, false, {message: "Incorrect email or password"});
        } else if(user)
            done(null, user);
    })
)

passport.use(
    new GoogleStrategy({
        clientID: config.auth.google_client_id,
        clientSecret: config.auth.google_client_secret,
        callbackURL: "/auth/google/callback"
    }, async(accessToken, refreshToken, profile, done) => {
        const users = await loadUsers();
        const accounts = await loadAccounts();
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
                    email: profile.emails[0].value
                }, async(err, resp) => {
                    await accounts.insertOne({
                        userId: resp.ops[0]._id,
                        balance: 0,
                        transactions: []
                    })
                    done(null, resp.ops[0])
                })

            } catch(err) {
                console.log(err);
            }
        }
    }
))

//Login routes

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

app.post('/auth/login', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/auth/login',
    failureFlash: true
}))

//Register routes

app.get('/register', (req, res) => {
    res.render('register', {user:req.user});
})

app.post('/register', async(req, res) => {
    const users = await loadUsers();
    const accounts = await loadAccounts();
    const user = await users.findOne({
        $or: [
            { username: req.body.username },
            { email: req.body.email }
        ]
    });
    if(user && user.username === req.body.username) {
        req.flash('info', 'This username already exists');
        return res.redirect('/register');
    } else if(user && user.email === req.body.email) {
        req.flash('info', 'This email already exists');
        return res.redirect('/register');
    } else {
        const password = await bcrypt.hash(req.body.password, 10);
        await users.insertOne({
            username: req.body.username,
            password: password,
            email: req.body.email,
        }, async(err, resp) => {
            await accounts.insertOne({
                userId: resp.ops[0]._id,
                balance: 0,
                transactions: []
            })
        });
        res.redirect('/auth/login')
    }
})

//profile and homepage routes

app.get('/', async(req, res) => {
    res.render('home', {user:req.user});
})

app.get('/profile', async(req, res) => {
    const accounts = await loadAccounts();
    const account = await accounts.findOne({
        userId: new ObjectID(req.user._id.toString())
    })
    res.render('profile', {user:req.user, account: account})
})

//POST Requests

app.post('/transfer', async(req, res) => {
    const users = await loadUsers();
    const newId = ObjectID(req.body.account);
    const accounts = await loadAccounts();
    const user = await users.findOne({
        _id: newId
    });
    if(!user) {
        req.flash('error', 'Incorrect account id');
    } else {
        await accounts.updateOne({
            userId: newId
        }, {
            $inc: { balance: parseInt(req.body.amount) },
            $push: { transactions : {
                    type: 'credit',
                    amount: parseInt(req.body.amount),
                    time: (new Date(Date.now())).toLocaleString()
                }
            }
        })
        await accounts.updateOne({
            userId: new ObjectID(req.user._id.toString())
        }, {
            $inc: { balance: parseInt(-req.body.amount) },
            $push: { transactions : {
                    type: 'debit',
                    amount: parseInt(req.body.amount),
                    time: (new Date(Date.now())).toLocaleString()
                }
            }
        })

    }
    res.redirect('/profile')
})

app.post('/deposit', async(req, res) => {
    const accounts = await loadAccounts();
    await accounts.updateOne({
        userId: new ObjectID(req.user._id.toString())
    }, {
        $inc: { balance: parseInt(req.body.amount) },
        $push: { transactions : {
                type: 'credit',
                amount: parseInt(req.body.amount),
                time: (new Date(Date.now())).toLocaleString()
            }
        }
    })
    res.redirect('/profile')
})

app.post('/withdraw', async(req, res) => {
    const accounts = await loadAccounts();
    await accounts.updateOne({
        userId: new ObjectID(req.user._id.toString())
    }, {
        $inc: { balance: parseInt(-req.body.amount) },
        $push: { transactions : {
                type: 'debit',
                amount: parseInt(req.body.amount),
                time: (new Date(Date.now())).toLocaleString()
            }
        }
    })
    res.redirect('/profile')
})


app.listen(5000, () => console.log('server started'));