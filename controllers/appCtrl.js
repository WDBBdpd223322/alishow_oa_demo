// app.js 文件的 controllers
const { getUserInfoByEmail } = require('../models/api/usersModel')
const md5 = require('../utils/md5')

// 统一错误处理
exports.errorHandler = (err, req, res, next) => {
  res.status(500).send({
    data: {},
    meta: {
      code: 500,
      message: 'Internal Server Error',
      error: err.message
    }
  })
}

// 页面的登陆验证
exports.loginHandler = async (req, res, next, app) => {
  // 登陆直接通过
  if (req.originalUrl === '/admin/login') return next()

  // 其余验证 session
  const sessionUser = req.session.user
  if (sessionUser) {
    app.locals.sessionUser = sessionUser
    return next()
  }

  // 没有 session 验证 cookie
  let userInfo = req.cookies.rememberme
  if (!userInfo) return res.redirect('/admin/login')
  userInfo = JSON.parse(userInfo)
  const result = await getUserInfoByEmail(userInfo.admin_email, next)
  if (!result || result[0].admin_pwd !== userInfo.admin_pwd) return res.redirect('/admin/login')
  app.locals.sessionUser = result[0]
  req.session.user = result[0]
  res.cookie('rememberme', JSON.stringify(userInfo), {
    maxAge: 1000 * 60 * 60
  })
  next()
}

// api 接口的登陆验证
exports.apiHandler = (req, res, next) => {
  if (!req.session.user) return res.status(403).send({
    data: {},
    meta: {
      status: 403,
      message: '登陆过期，请重新登陆！'
    }
  })

  next()
}

// 用户模块的权限验证
exports.usersRight = (req, res, next) => {
  const {admin_id} = req.session.user
  if (admin_id !== 17) return res.status(401).send({
    data: {},
    meta: {
      status: 401,
      message: '您没有权限进行该操作！'
    }
  })

  next()
}
