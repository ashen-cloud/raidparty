import express from 'express'
import csurf from 'csurf'
import jwt from 'jsonwebtoken'

import bcrypt from 'bcrypt'

import { User, IUser } from './db'

const app = express()
const PORT = process.env.PORT || 6111

app.use(express.json())
// app.use(csurf()) TODO

const authenticatjToken = (req: any, res: any, next: any) => {
  const token = req.headers['authorization'] 
  if (!token) return res.sendStatus(401)

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, (err: any, user: any) => {

    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

const generateAccessToken = (user: { email: string }) => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET!, { expiresIn: '60m' })
}

app.get('/ping', (req: any, res: any) => {
  res.json({ pong: true })
})

app.post('/token', (req, res) => {
  const refreshToken = req.body.token

  if (!refreshToken) return res.sendStatus(401)

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!, (err: any, user: any) => {

    if (err) return res.sendStatus(403)

    const accessToken = generateAccessToken({ email: user.email })

    res.json({ accessToken })
  })
})

app.post('/register', async (req: any, res: any) => {
  const email = req.body.email
  const password  = req.body.password

  const salt = await bcrypt.genSalt(10)

  const passwordSalted = await bcrypt.hash(password, salt)

  const user = new User({ email, password: passwordSalted })

  await user.save()

  const accessToken = generateAccessToken({ email: user.email })
  const refreshToken = jwt.sign({ email: user.email }, process.env.REFRESH_TOKEN_SECRET!)

  return res.json({ accessToken, refreshToken })  
})

app.post('/login', async (req: any, res: any) => {
  const email = req.body.email
  const password  = req.body.password

  const user = await User.findOne({ email })
  if (!user) {
    return res.status(401).send({ err: "incorrect email or password" })
  }

  const validPassword = await bcrypt.compare(password, user.password)
  if (!validPassword) {
    return res.status(401).send({ err: "incorrect email or password" })
  }

  const accessToken = generateAccessToken({ email: user.email })
  const refreshToken = jwt.sign({ email: user.email }, process.env.REFRESH_TOKEN_SECRET!)

  return res.json({ accessToken, refreshToken })
})

app.delete('/logout', (req: any, res: any) => {
  // todo: invalidate tokens
  res.sendStatus(204)
})

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})
