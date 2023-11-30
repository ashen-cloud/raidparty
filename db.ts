import { connect, Schema, model, Document } from 'mongoose'

interface IUser extends Document {
  name: string
  email: string
}

const userSchema = new Schema<IUser>({
  name: String,
  email: String
})

export const User = model<IUser>('User', userSchema) 

const MONGO_URI = 'mongodb://127.0.0.1:27017/raidparty'

connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
} as any)
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err))
