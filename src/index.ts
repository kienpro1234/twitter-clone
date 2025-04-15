import { config } from 'dotenv'
import express from 'express'
import { UPLOAD_IMAGE_DIR, UPLOAD_VIDEO_DIR } from '~/constants/dir'
import { defaultErrorHandler } from '~/middlewares/error.middlewares'
import mediasRouter from '~/routes/medias.routes'
import staticRouter from '~/routes/static.routes'
import usersRouter from '~/routes/users.routes'
import databaseService from '~/services/database.services'
import { initFolder } from '~/utils/file'
import cors from 'cors'

config()

databaseService.connect().catch(console.dir)
const app = express()

app.use(cors())

const port = process.env.PORT || 4000

initFolder()

app.get('/', (req, res) => {
  res.send('hello world')
})

app.use(express.json())
app.use('/medias', mediasRouter)
app.use('/users', usersRouter)
// app.use('/static', express.static(UPLOAD_IMAGE_DIR))
app.use('/static', staticRouter)
// app.use('/static/video', express.static(UPLOAD_VIDEO_DIR))

app.use(defaultErrorHandler)

app.listen(port, () => {
  console.log(`Running on port ${port}`)
})
