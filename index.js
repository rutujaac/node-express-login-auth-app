require('dotenv').config()

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')


app.use(express.json())

const users = []

app.get('/users',authenticateUser,(req,res)=> {
    res.json(users.filter(u => u.name=== req.user.name))
})

app.post('/users',async(req,res) => {
    try {
        const salt = await bcrypt.genSalt();
        const hashedPassw = await bcrypt.hash(req.body.password,salt)
        const user1 = { name: req.body.name , password: hashedPassw , post: req.body.post}
        users.push(user1)
        res.status(200).send()
    }
    catch {
        res.status(400).send()
    }
})

app.post('/users/login',async(req,res) => {
    try {
        const user = users.find(user => user.name === req.body.name)
        console.log(user)
        if(user == undefined) {
            res.send('User not found')
        }
        else {
            if(await bcrypt.compare(req.body.password,user.password)) {
                const user = { name : req.body.name}
                const accessToken = jwt.sign(user,process.env.ACCESS_TOKEN_SECRET)
                res.send({accessToken:accessToken})
            }
            else {
                res.send('Incorrect password')
            }
        }
    }
    catch {
        res.status(400).send()
    }
})

function authenticateUser(req,res,next) {
    const header = req.headers['authorization']
    const token = header && header.split(' ')[1]
    if(token == null) return res.sendStatus(401)

    jwt.verify(token,process.env.ACCESS_TOKEN_SECRET,(err,a)=> {
        if(err) return res.sendStatus(403);
        req.user = a;
        next()
    })
}

app.listen(3000)