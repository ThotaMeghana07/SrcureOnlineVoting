const express = require('express')
require('dotenv').config({ path: './envFolder/.env' })
const { sendVerMail } = require('./mailer')

const app = express()
const port = 9090

// middleware
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.post('/', sendVerMail)

app.listen(port, console.log(`http://localhost:${port}`))