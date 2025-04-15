import { checkSchema, ParamSchema } from 'express-validator'
import { JsonWebTokenError } from 'jsonwebtoken'
import HTTP_STATUS from '~/constants/httpStatus'
import { USER_MESSAGES } from '~/constants/messages'
import { ErrorWithStatus } from '~/models/errors'
import { TokenPayload } from '~/models/requests/User.requests'
import databaseService from '~/services/database.services'

import usersService from '~/services/users.services'
import { hashPassword } from '~/utils/crypto'
import { verifyToken } from '~/utils/jwt'
import validate from '~/utils/validation'
import { NextFunction, Request, Response } from 'express'
import { ObjectId } from 'mongodb'
import { UserVerifyStatus } from '~/constants/enum'
import { REGEX_USERNAME } from '~/constants/regex'

const passwordSchema: ParamSchema = {
  isString: {
    errorMessage: USER_MESSAGES.PASSWORD_REQUIRED
  },
  notEmpty: {
    errorMessage: USER_MESSAGES.PASSWORD_REQUIRED
  },
  isLength: {
    errorMessage: USER_MESSAGES.PASSWORD_LENGTH,
    options: {
      min: 6,
      max: 50
    }
  },
  isStrongPassword: {
    errorMessage: USER_MESSAGES.PASSWORD_STRONG,
    options: {
      minLength: 6,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1
    }
  }
}

const confirmPasswordSchema: ParamSchema = {
  isString: {
    errorMessage: USER_MESSAGES.CONFIRM_PASSWORD_MUST_BE_STRING
  },
  notEmpty: {
    errorMessage: USER_MESSAGES.CONFIRM_PASSWORD_REQUIRED
  },
  isLength: {
    errorMessage: USER_MESSAGES.CONFIRM_PASSWORD_LENGTH,
    options: {
      min: 6,
      max: 50
    }
  },
  isStrongPassword: {
    errorMessage: USER_MESSAGES.CONFIRM_PASSWORD_STRONG,
    options: {
      minLength: 6,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1
    }
  },
  custom: {
    options: (value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password and confirm password do not match')
      }
      return true
    }
  }
}

const forgotPasswordSchema: ParamSchema = {
  trim: true,
  custom: {
    options: async (value: string, { req }) => {
      if (!value) {
        throw new ErrorWithStatus({
          message: USER_MESSAGES.FORGOT_PASSWORD_TOKEN_REQUIRED,
          status: HTTP_STATUS.UNAUTHORIZED
        })
      }
      try {
        const decoded_forgot_pasword_token = await verifyToken({
          token: value,
          secretOrPublicKey: process.env.JWT_SECRET_FORGOT_PASSWORD_TOKEN as string
        })

        const { user_id } = decoded_forgot_pasword_token
        const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })

        if (!user) {
          throw new ErrorWithStatus({
            message: USER_MESSAGES.USER_NOT_FOUND,
            status: HTTP_STATUS.UNAUTHORIZED
          })
        }

        if (user.forgot_password_token !== value) {
          throw new ErrorWithStatus({
            message: USER_MESSAGES.INVALID_FORGOT_PASSWORD_TOKEN,
            status: HTTP_STATUS.UNAUTHORIZED
          })
        }

        ;(req as TokenPayload).decoded_forgot_pasword_token = decoded_forgot_pasword_token
      } catch (error) {
        if (error instanceof JsonWebTokenError) {
          throw new ErrorWithStatus({
            message: error.message,
            status: HTTP_STATUS.UNAUTHORIZED
          })
        }
        throw error
      }

      return true
    }
  }
}

const nameSchema: ParamSchema = {
  notEmpty: {
    errorMessage: USER_MESSAGES.NAME_REQUIRED
  },
  isString: {
    errorMessage: USER_MESSAGES.NAME_MUST_BE_STRING
  },
  isLength: {
    errorMessage: USER_MESSAGES.NAME_LENGTH,
    options: {
      min: 1,
      max: 100
    }
  },
  trim: true
}

const dateOfBirthSchema: ParamSchema = {
  isISO8601: {
    options: {
      strict: true,
      strictSeparator: true
    },
    errorMessage: USER_MESSAGES.DATE_OF_BIRTH_MUST_BE_ISO8601
  }
}

const imgSchema: ParamSchema = {
  optional: true,
  isString: {
    errorMessage: USER_MESSAGES.IMG_MUST_BE_STRING
  },
  trim: true,
  isLength: {
    options: {
      min: 1,
      max: 400
    },
    errorMessage: USER_MESSAGES.IMG_LENGTH
  }
}

const userIdSchema: ParamSchema = {
  custom: {
    options: async (value: string, { req }) => {
      if (!ObjectId.isValid(value)) {
        throw new ErrorWithStatus({
          message: USER_MESSAGES.INVALID_USER_ID,
          status: HTTP_STATUS.NOT_FOUND
        })
      }
      const followed_user = await databaseService.users.findOne({
        _id: new ObjectId(value)
      })

      if (!followed_user) {
        throw new ErrorWithStatus({
          message: USER_MESSAGES.USER_NOT_FOUND,
          status: HTTP_STATUS.NOT_FOUND
        })
      }
    }
  }
}

export const loginValidator = validate(
  checkSchema(
    {
      email: {
        isEmail: {
          errorMessage: USER_MESSAGES.EMAIL_INVALID
        },

        trim: true,
        custom: {
          options: async (value, { req }) => {
            const user = await databaseService.users.findOne({
              email: value,
              password: hashPassword(req.body.password)
            })

            if (!user) {
              throw new Error(USER_MESSAGES.EMAIL_OR_PASSWORD_INCORRECT)
            }
            req.user = user
            return true
          }
        }
      },
      password: {
        isString: {
          errorMessage: USER_MESSAGES.PASSWORD_REQUIRED
        },
        notEmpty: {
          errorMessage: USER_MESSAGES.PASSWORD_REQUIRED
        },
        isLength: {
          errorMessage: USER_MESSAGES.PASSWORD_LENGTH,
          options: {
            min: 6,
            max: 50
          }
        },
        isStrongPassword: {
          errorMessage: USER_MESSAGES.PASSWORD_STRONG,
          options: {
            minLength: 6,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
          }
        }
      }
    },
    ['body']
  )
)

export const registerValidator = validate(
  checkSchema(
    {
      name: nameSchema,
      email: {
        isEmail: {
          errorMessage: USER_MESSAGES.EMAIL_INVALID
        },

        trim: true,
        custom: {
          options: async (value) => {
            const isExistEmail = await usersService.checkEmailExists(value)
            if (isExistEmail) {
              throw new Error(USER_MESSAGES.EMAIL_ALREADY_EXISTS)
            }
            return true
          }
        }
      },
      password: passwordSchema,
      confirm_password: confirmPasswordSchema,
      date_of_birth: dateOfBirthSchema
    },
    ['body']
  )
)

// export const logoutValidator = validate(
//   checkSchema(
//     {
//       Authorization: {
//         in: ['headers'],
//         trim: true,
//         custom: {
//           options: async (value: string, { req }) => {
//             const access_token = value?.split(' ')[1] || ''
//             if (!access_token) {
//               throw new ErrorWithStatus({ message: USER_MESSAGES.ACCESS_TOKEN_REQUIRED, status: 401 })
//             }
//             try {
//               const decoded_authorization = await verifyToken({
//                 token: access_token,
//                 secretOrPublicKey: process.env.JWT_SECRET_ACCESS_TOKEN as string
//               })
//               ;(req as Request).decoded_authorization = decoded_authorization
//             } catch (error) {
//               throw new ErrorWithStatus({
//                 message: (error as JsonWebTokenError).message,
//                 status: HTTP_STATUS.UNAUTHORIZED
//               })
//             }

//             return true
//           }
//         }
//       },
//       refresh_token: {
//         in: ['body'],
//         trim: true,
//         custom: {
//           options: async (value: string, { req }) => {
//             if (!value) {
//               throw new ErrorWithStatus({
//                 message: USER_MESSAGES.REFRESH_TOKEN_REQUIRED,
//                 status: HTTP_STATUS.UNAUTHORIZED
//               })
//             }
//             try {
//               const [decoded_refresh_token, refresh_token] = await Promise.all([
//                 verifyToken({ token: value, secretOrPublicKey: process.env.JWT_SECRET_REFRESH_TOKEN as string }),
//                 databaseService.refreshTokens.findOne({ token: value })
//               ])
//               if (!refresh_token) {
//                 throw new ErrorWithStatus({
//                   message: USER_MESSAGES.REFRESH_TOKEN_NOT_EXISTS,
//                   status: HTTP_STATUS.UNAUTHORIZED
//                 })
//               }

//               ;(req as TokenPayload).decoded_refresh_token = decoded_refresh_token
//             } catch (error) {
//               if (error instanceof JsonWebTokenError) {
//                 throw new ErrorWithStatus({
//                   message: error.message,
//                   status: HTTP_STATUS.UNAUTHORIZED
//                 })
//               }
//               throw error
//             }

//             return true
//           }
//         }
//       }
//     },
//     ['headers', 'body']
//   )
// )

export const accessTokenValidator = validate(
  checkSchema({
    Authorization: {
      trim: true,
      custom: {
        options: async (value: string, { req }) => {
          const access_token = value?.split(' ')[1] || ''
          if (!access_token) {
            throw new ErrorWithStatus({ message: USER_MESSAGES.ACCESS_TOKEN_REQUIRED, status: 401 })
          }
          try {
            const decoded_authorization = await verifyToken({
              token: access_token,
              secretOrPublicKey: process.env.JWT_SECRET_ACCESS_TOKEN as string
            })
            ;(req as Request).decoded_authorization = decoded_authorization
          } catch (error) {
            throw new ErrorWithStatus({
              message: (error as JsonWebTokenError).message,
              status: HTTP_STATUS.UNAUTHORIZED
            })
          }

          return true
        }
      }
    }
  })
)

export const refreshTokenValidator = validate(
  checkSchema({
    refresh_token: {
      trim: true,
      custom: {
        options: async (value: string, { req }) => {
          if (!value) {
            throw new ErrorWithStatus({
              message: USER_MESSAGES.REFRESH_TOKEN_REQUIRED,
              status: HTTP_STATUS.UNAUTHORIZED
            })
          }
          try {
            const [decoded_refresh_token, refresh_token] = await Promise.all([
              verifyToken({ token: value, secretOrPublicKey: process.env.JWT_SECRET_REFRESH_TOKEN as string }),
              databaseService.refreshTokens.findOne({ token: value })
            ])
            if (!refresh_token) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.REFRESH_TOKEN_NOT_EXISTS,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }

            ;(req as TokenPayload).decoded_refresh_token = decoded_refresh_token
          } catch (error) {
            if (error instanceof JsonWebTokenError) {
              throw new ErrorWithStatus({
                message: error.message,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }
            throw error
          }

          return true
        }
      }
    }
  })
)

export const emailVeriyfyTokenValidator = validate(
  checkSchema(
    {
      email_verify_token: {
        trim: true,

        custom: {
          options: async (value: string, { req }) => {
            if (!value) {
              throw new ErrorWithStatus({
                message: USER_MESSAGES.EMAIL_VERIFY_TOKEN_IS_REQUIRED,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }

            try {
              const decoded_email_verify_token = await verifyToken({
                token: value,
                secretOrPublicKey: process.env.JWT_SECRET_EMAIL_VERIFY_TOKEN as string
              })

              ;(req as Request).decoded_email_verify_token = decoded_email_verify_token
            } catch (error) {
              throw new ErrorWithStatus({
                message: (error as JsonWebTokenError).message,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }

            return true
          }
        }
      }
    },
    ['body']
  )
)

export const forgotPasswordValidator = validate(
  checkSchema(
    {
      email: {
        isEmail: {
          errorMessage: USER_MESSAGES.EMAIL_INVALID
        },

        trim: true,
        custom: {
          options: async (value, { req }) => {
            const user = await databaseService.users.findOne({
              email: value
            })

            if (!user) {
              throw new Error(USER_MESSAGES.USER_NOT_FOUND)
            }
            req.user = user
            return true
          }
        }
      }
    },
    ['body']
  )
)

export const verifyForgotPasswordTokenValidator = validate(
  checkSchema({
    forgot_password_token: forgotPasswordSchema
  })
)

export const resetPasswordValidator = validate(
  checkSchema(
    {
      password: passwordSchema,
      confirm_password: confirmPasswordSchema,
      forgot_password_token: forgotPasswordSchema
    },
    ['body']
  )
)

export const verifiedUserValidator = async (req: Request, res: Response, next: NextFunction) => {
  const { verify } = req.decoded_authorization as TokenPayload
  console.log('verify', verify)
  if (verify !== UserVerifyStatus.Verified) {
    return next(
      new ErrorWithStatus({
        message: USER_MESSAGES.USER_NOT_VERIFIED,
        status: HTTP_STATUS.FORBIDDEN
      })
    )
  }
  next()
}

export const updateMeValidator = validate(
  checkSchema({
    name: {
      ...nameSchema,
      optional: true,
      notEmpty: undefined
    },
    date_of_birth: {
      ...dateOfBirthSchema,
      optional: true,
      notEmpty: undefined
    },
    bio: {
      optional: true,
      isString: {
        errorMessage: USER_MESSAGES.BIO_MUST_BE_STRING
      },
      trim: true,
      isLength: {
        options: {
          min: 1,
          max: 200
        },
        errorMessage: USER_MESSAGES.BIO_LENGTH
      }
    },
    location: {
      optional: true,
      isString: {
        errorMessage: USER_MESSAGES.LOCATION_MUST_BE_STRING
      },
      trim: true,
      isLength: {
        options: {
          min: 1,
          max: 200
        },
        errorMessage: USER_MESSAGES.LOCATION_LENGTH
      }
    },
    website: {
      optional: true,
      isString: {
        errorMessage: USER_MESSAGES.WEBSITE_MUST_BE_STRING
      },

      trim: true,
      isLength: {
        options: {
          min: 1,
          max: 200
        },
        errorMessage: USER_MESSAGES.WEBSITE_LENGTH
      }
    },
    username: {
      optional: true,
      isString: {
        errorMessage: USER_MESSAGES.USERNAME_MUST_BE_STRING
      },
      trim: true,
      custom: {
        options: async (value, { req }) => {
          if (!REGEX_USERNAME.test(value)) {
            throw new Error(USER_MESSAGES.USERNAME_INVALID)
          }
          const user = await databaseService.users.findOne({ username: value })
          if (user) {
            throw new Error(USER_MESSAGES.USERNAME_EXISTS)
          }
        }
      }
    },
    avatar: imgSchema,
    cover_photo: imgSchema
  })
)

export const followValidator = validate(
  checkSchema(
    {
      followed_user_id: userIdSchema
    },
    ['body']
  )
)

export const unFollowValidator = validate(
  checkSchema(
    {
      user_id: userIdSchema
    },
    ['params']
  )
)

export const changePasswordValidator = validate(
  checkSchema({
    old_password: {
      ...passwordSchema,
      custom: {
        options: async (value, { req }) => {
          const { user_id } = req.decoded_authorization as TokenPayload
          const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })

          if (!user) {
            throw new ErrorWithStatus({
              message: USER_MESSAGES.USER_NOT_FOUND,
              status: HTTP_STATUS.NOT_FOUND
            })
          }

          const { password } = user
          const isMatch = hashPassword(value) === password
          if (!isMatch) {
            throw new ErrorWithStatus({
              message: USER_MESSAGES.OLD_PASSWORD_NOT_MATCH,
              status: HTTP_STATUS.UNAUTHORIZED
            })
          }
          return true
        }
      }
    },
    password: passwordSchema,
    confirm_password: confirmPasswordSchema
  })
)
