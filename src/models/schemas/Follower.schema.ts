import { ObjectId } from 'mongodb'

interface FollowerType {
  _id?: ObjectId
  user_id: ObjectId
  created_at?: Date
  followed_user_id: ObjectId
}

export default class Follower {
  _id?: ObjectId
  followed_user_id: ObjectId
  user_id: ObjectId
  createdAt: Date

  constructor({ _id, followed_user_id, created_at, user_id }: FollowerType) {
    this._id = _id
    this.followed_user_id = followed_user_id
    this.user_id = user_id
    this.createdAt = created_at || new Date()
  }
}
