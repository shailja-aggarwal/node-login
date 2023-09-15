require("dotenv").config()
const express = require("express");
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cors = require("cors")

const app = express();


app.use(express.json());

app.use(cors({
    "access-control-allow-origin": ['*'],
    methods: ["GET", "POST"]
}))

var users = [];
const posts = [{post:'post1', name: 'tim'}, {post: 'post2', name: 'tom'}]
var refreshTokens = [];

app.get('/posts', authenticateToken, (req, res) => {
   const post = posts.filter((e) => e.name == req.user.name)
    res.json(post)
})

app.post('/signup', signUpUSer, async (req, res) => {
    let user = {"name": req.body.username, "password": req.body.pass}
    users.push(user)
    res.json("password created")
})

app.post('/login', authenticateUser, async(req, res) => {
     if(req.isValid){
        const username = req.body.username;
        const user = {name: username}
        const userAccessToken = generateToken(user)
        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
        refreshTokens.push(refreshToken)
        const obj = {userAccessToken: userAccessToken, refreshToken: refreshToken}
        res.json(obj)

     }
})

app.post('/token', getRefreshToken, (req, res) => {
     if(req.user){
        let token = generateToken({name: req.user})
        res.json({authenticateToken: token})
     }
})

async function signUpUSer (req, res, next){
    const isUser = users.filter((e) => e.name == req.body.username)
    console.log("isUser", isUser)
    if(isUser.length>0){
       res.sendStatus(401)
    } else {
        try {
            const salt = await bcrypt.genSalt(10);
            const pass = await bcrypt.hash(req.body.password, salt);
            console.log(pass)
            req.body.pass =pass;
            next()
        } catch (error) {
            res.sendStatus(500)
        }
    }
}

async function authenticateUser(req, res, next){

    const isUser = users.find((e) => e.name == req.body.username);
    console.log(isUser)
    if(!isUser){
        res.sendStatus(500)
    } else {
        try {
            const isValid = await bcrypt.compare(req.body.password, isUser.password)
            req.isValid = isValid;
            console.log("isValid", isValid)
            if(isValid){
                next()
            } else {
                res.sendStatus(401)
            }
        } catch (error) {
            res.status(403).send("Invalid Password")
        }
    }

}

function generateToken(user){
    return jwt.sign(user, process.env.ACESS_TOKEN_SECRET, {expiresIn: '30s'})
}

function authenticateToken(req, res, next){
    const authHeader = req.headers['authorization'];
    const token = authHeader.split(' ')[1]
    if(token == null){
        res.sendStatus(401)
    } else {
        jwt.verify(token, process.env.ACESS_TOKEN_SECRET, (err, user) => {
            if(err){
                res.sendStatus(403)
            } else {
                req.user = user;
                next();
            }
        })
    }
}

function getRefreshToken(req, res, next){
    const token = req.body.token;
    console.log(token)
    if(token == null){
        res.sendStatus(401);
    } else if(!refreshTokens.includes(token)){
        res.sendStatus(403);
    } else {
        jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if(err){
                res.sendStatus(403)
            } else {
                req.user = user;
                next();
            }
        })
    }
}


app.listen(3000, ()=>{
    console.log("App is running");
})