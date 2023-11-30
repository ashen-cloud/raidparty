import mongoose, { connect, Schema, model, Document } from 'mongoose'

export interface IUser extends Document {
  name: string
  email: string
  password?: string
}

const UserSchema = new Schema<IUser>({
  name: { type: String, require: true },
  email: { type: String, require: true },
  password: { type: String, require: true },
})

export const User = model<IUser>('User', UserSchema) 

export interface IToken extends Document {
  user: mongoose.Schema.Types.ObjectId,
  token: string,
}

const TokenSchema: Schema = new Schema<IToken>({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token: { type: String, required: true }, // access token or refresh token
})

export const Token = model<IToken>('Token', TokenSchema)

const MONGO_URI = 'mongodb://127.0.0.1:27017/raidparty'

connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
} as any)
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err))
