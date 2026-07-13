// src/index.js
import { nanoid } from 'nanoid'
import bcrypt from 'bcryptjs'

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    const path = url.pathname

    if (path === '/api/auth/register' && request.method === 'POST') {
      return handleRegister(request, env)
    }

    if (path === '/api/auth/login' && request.method === 'POST') {
      return handleLogin(request, env)
    }

    return new Response(JSON.stringify({ error: 'Not Found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}

async function handleRegister(request, env) {
  try {
    const { email, username, password } = await request.json()

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

    const existing = await env.DB.prepare(
      'SELECT id FROM users WHERE username = ? OR email = ?'
    ).bind(username, email).first()

    if (existing) {
      return new Response(JSON.stringify({ error: '用户名或邮箱已被注册' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    const salt = await bcrypt.genSalt(10)
    const passwordHash = await bcrypt.hash(password, salt)
    const userId = nanoid()
    const now = Date.now()

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

async function handleLogin(request, env) {
  try {
    const { loginId, password } = await request.json()

    if (!loginId || !password) {
      return new Response(JSON.stringify({ error: '请输入账号和密码' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    const user = await env.DB.prepare(
      'SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ?'
    ).bind(loginId, loginId).first()

    if (!user) {
      return new Response(JSON.stringify({ error: '用户不存在' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    const isValid = await bcrypt.compare(password, user.password_hash)
    if (!isValid) {
      return new Response(JSON.stringify({ error: '密码错误' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    return new Response(JSON.stringify({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    }), {
      status: 200,
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