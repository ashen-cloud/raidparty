import express from 'express'
import csurf from 'csurf'
import jwt from 'jsonwebtoken'

import bcrypt from 'bcrypt'

import { User, IUser, Token, IToken } from './db'

const app = express()
const PORT = process.env.PORT || 6111

app.use(express.json())
// app.use(csurf()) TODO

const authenticateToken = (req: any, res: any, next: any) => {
  let token = req.headers['authorization'] 
  if (!token) return res.sendStatus(401)
  token = token.split(' ')[1]

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, async (err: any, _user: any) => {
    if (err) return res.sendStatus(403)
    const user = (await User.findOne({ email: _user.email }))!.toObject()

    const existingTokens = await Token.find({ user: user._id })
    if (!existingTokens.length) return res.sendStatus(403)

    const currentToken = await Token.findOne({ user: user._id, token: token })
    if (!currentToken) return res.sendStatus(403)

    delete user.password
    delete user.__v
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

app.get('/user/:id', authenticateToken, async (req: any, res: any) => {
  const id = req.params.id

  if (!id) {
    return res.sendStatus(400)   
  }

  const user = (await User.findById(id))!.toObject()

  if (!user) {
    return res.status(400).json({ err: 'user not found' })
  }

  delete user.password
  delete user.__v

  return res.json(user)
})

app.post('/refresh-token', authenticateToken, (req: any, res: any) => {
  const refreshToken = req.body.refreshToken

  if (!refreshToken) return res.sendStatus(401)

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!, async (err: any, user: any) => {
    if (err) return res.sendStatus(403)

    const existingTokens = await Token.find({ user: req.user._id })
    if (!existingTokens.length) return res.sendStatus(403)

    const currentToken = await Token.findOne({ user: req.user._id, token: refreshToken })
    if (!currentToken) return res.sendStatus(403)

    const accessToken = generateAccessToken({ email: req.user.email })

    await (new Token({ user: req.user._id, token: accessToken })).save()

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

  await (new Token({ user: user._id, token: accessToken })).save()
  await (new Token({ user: user._id, token: refreshToken })).save()

  return res.json({ accessToken, refreshToken })  
})

app.post('/login', async (req: any, res: any) => {
  const email = req.body.email
  const password  = req.body.password

  const user = await User.findOne({ email })
  if (!user) {
    return res.status(401).send({ err: "incorrect email or password" })
  }

  const validPassword = await bcrypt.compare(password, user.password!)
  if (!validPassword) {
    return res.status(401).send({ err: "incorrect email or password" })
  }

  const accessToken = generateAccessToken({ email: user.email })
  const refreshToken = jwt.sign({ email: user.email }, process.env.REFRESH_TOKEN_SECRET!)

  await (new Token({ user: user._id, token: accessToken })).save()
  await (new Token({ user: user._id, token: refreshToken })).save()

  return res.json({ accessToken, refreshToken })
})

app.post('/logout', authenticateToken, async (req: any, res: any) => {
  const user = req.user._id
  if (!user) res.sendStatus(401)
  await Token.deleteMany({ user })
  res.sendStatus(204)
})

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})
