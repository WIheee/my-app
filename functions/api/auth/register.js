import { nanoid } from 'nanoid'
import bcrypt from 'bcryptjs'

export async function onRequest(context) {
  const { request, env } = context

  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json' }
    })
  }

  try {
    const { email, username, password } = await request.json()

    // 校验字段
    if (!email || !username || !password) {
      return new Response(JSON.stringify({ error: '请完整填写所有字段' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }
    if (!email.includes('@')) {
      return new Response(JSON.stringify({ error: '请输入有效的邮箱地址' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }
    if (username.length < 2) {
      return new Response(JSON.stringify({ error: '用户名至少2个字符' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }
    if (password.length < 6) {
      return new Response(JSON.stringify({ error: '密码至少6位' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // 检查用户是否已存在
    const existing = await env.DB.prepare(
      'SELECT id FROM users WHERE username = ? OR email = ?'
    ).bind(username, email).first()

    if (existing) {
      return new Response(JSON.stringify({ error: '用户名或邮箱已被注册' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // 哈希密码
    const salt = await bcrypt.genSalt(10)
    const passwordHash = await bcrypt.hash(password, salt)
    const userId = nanoid()
    const now = Date.now()

    // 插入用户
    await env.DB.prepare(
      `INSERT INTO users (id, username, email, password_hash, created_at)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(userId, username, email, passwordHash, now).run()

    return new Response(JSON.stringify({
      success: true,
      message: '注册成功'
    }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    })

  } catch (error) {
    console.error(error)
    return new Response(JSON.stringify({ error: '服务器错误' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}
