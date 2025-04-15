import path from 'path'
import fs from 'fs'
import { Request, Response } from 'express'
import formidable, { File } from 'formidable'
import { UPLOAD_IMAGE_TEMP_DIR, UPLOAD_VIDEO_DIR, UPLOAD_VIDEO_TEMP_DIR } from '~/constants/dir'
import { nanoid } from 'nanoid'
export const initFolder = () => {
  ;[UPLOAD_IMAGE_TEMP_DIR, UPLOAD_VIDEO_TEMP_DIR].forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }
  })
}

export const handleUploadImage = async (req: Request, res: Response) => {
  const form = formidable({
    uploadDir: UPLOAD_IMAGE_TEMP_DIR,
    maxFiles: 4,
    keepExtensions: true,
    maxFileSize: 1 * 1024 * 1024, // 1MB,
    maxTotalFileSize: 4 * 1024 * 1024, // 4MB
    filter: function ({ name, originalFilename, mimetype }) {
      const valid = name === 'image' && Boolean(mimetype?.includes('image/'))
      if (!valid) {
        form.emit('error' as any, new Error('Invalid file type') as any)
        return false
      }

      return valid
    }
  })

  return new Promise<File[]>((resolve, reject) => {
    form.parse(req, (err, fields, files) => {
      if (err) {
        reject(err)
      }

      if (!files.image) {
        reject(new Error('No file uploaded'))
      }

      resolve(files.image as File[])
    })
  })
}

export const handleUploadVideo = async (req: Request, res: Response) => {
  const idName = nanoid()
  const folderPath = path.resolve(UPLOAD_VIDEO_DIR, idName)
  fs.mkdirSync(folderPath)
  const form = formidable({
    uploadDir: path.resolve(UPLOAD_VIDEO_DIR, idName),
    maxFiles: 1,
    keepExtensions: true,
    maxFileSize: 100 * 1024 * 1024, // 1MB,

    filter: function ({ name, originalFilename, mimetype }) {
      const valid = name === 'video' && Boolean(mimetype?.includes('mp4') || mimetype?.includes('quicktime/'))
      if (!valid) {
        form.emit('error' as any, new Error('Invalid file type') as any)
        return false
      }

      return valid
    },
    filename: function (name, ext, part) {
      console.log(name, ext, part)
      return idName + ext
    }
  })

  return new Promise<File[]>((resolve, reject) => {
    form.parse(req, (err, fields, files) => {
      if (err) {
        reject(err)
      }

      if (!files.video) {
        reject(new Error('No file uploaded'))
      }

      // const videos = files.video as File[]
      // videos.forEach((video) => {
      //   const ext = getExtension(video.originalFilename as string)
      //   fs.renameSync(video.filepath, video.filepath + '.' + ext)
      // })

      resolve(files.video as File[])
    })
  })
}

export const getnameFromFullName = (fullName: string) => {
  const nameArr = fullName.split('.')
  nameArr.pop()
  return nameArr.join('')
}

export const getExtension = (fullName: string) => {
  const nameArr = fullName.split('.')
  return nameArr[nameArr.length - 1]
}
