import express from 'express'
import { User } from './db'

const app = express()
const PORT = 3000

app.use(express.json())

app.get('/ping', (req: any, res: any) => {
  res.json({ pong: true })
})

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})
