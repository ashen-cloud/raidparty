import { connect, Schema, model, Document } from 'mongoose'
import bcrypt from 'bcrypt'

export interface IUser extends Document {
  name: string
  email: string
  password: string
}

const UserSchema = new Schema<IUser>({
  name: { type: String, require: true },
  email: { type: String, require: true },
  password: { type: String, require: true },
})

export const User = model<IUser>('User', UserSchema) 

const MONGO_URI = 'mongodb://127.0.0.1:27017/raidparty'

connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
} as any)
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err))
