import { Hono } from 'hono';
import { getUserByEmail, createSession } from '../db.js';
import { verify } from '@node-rs/argon2';
import type { SessionWithToken } from '../types.js';

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const auth = new Hono();
const SESSION_COOKIE_NAME = 'session_token';

// TODO: RATE LIMITING
auth.post('/login', async (c) => {
    const { email, password } = await c.req.json();

    // Ensure email and password aren't given.
    if (!email || !password) {
        return c.json({ error: 'Email and password required' }, 400);
    }

    // Ensure email and password aren't empty strings.
    if (email.trim() === '' || password.trim() === '') {
        return c.json( { error: 'Email and password can\'t be empty' }, 400);
    }

    // Ensure email is valid
    if (!emailRegex.test(email)) {
        return c.json( { error: 'Invalid email format' }, 400);
    }

    const user = await getUserByEmail(email);

    // Credentials don't exist!
    if (!user) {
        return c.json({ error: 'Invalid credentials' }, 401);
    }

    const isValid = await verify(user.password_hash, password);

    // Password is incorrect!
    if (!isValid) {
        return c.json({ error: 'Invalid credentials' }, 401);
    }

    const userId = user.user_id;
    const id = generateSecureRandomString();
    const secret = generateSecureRandomString();
    const secretHash = await hashSecret(secret);
    const token = id + "." + secret;

    // Validation complete -> Create a session.
    const session: SessionWithToken = {
        id,
        userId,
        secretHash,
        token
    }
    
    await createSession(session);

    // After creating the session, I must send it as a httpOnly cookie. This is de way.
    const cookieString = process.env.NODE_ENV === 'production'
        ? `${SESSION_COOKIE_NAME}=${session.token}; HttpOnly; Secure; SameSite=Lax; Path=/`
        : `${SESSION_COOKIE_NAME}=${session.token}; HttpOnly; SameSite=Lax; Path=/`;
    
    c.header('Set-Cookie', cookieString)
    
    // Booyah! Return the user item.
    return c.json({
        user: { id: user.user_id, email: user.email }
    }); 

});

// Validate user's cookies.
auth.get('/validate', async (c) => {
    const cookieHeader = c.req.header('Cookie');

    if (!cookieHeader) {
        return c.json( { error: 'No session cookie' }, 401);
    }

    // Check the session_token for cookie
    const match = cookieHeader.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`));
    const sessionToken = match?.[1];

    if (!sessionToken) {
        return c.json({ error: 'No session token' }, 401);
    }

});

function generateSecureRandomString(): string {
    const alphabet = "abcdefghijkmnpqrstuvwxyz23456789";
    
	const bytes: Uint8Array = new Uint8Array(24);
	crypto.getRandomValues(bytes);

	let id = "";
	for (let i = 0; i < bytes.length; i++) {
		id += alphabet[bytes[i]! >> 3];
	}
	return id;
}

// Since 120 bits is unguessable as it is, sha256 is fine here as it is faster.
async function hashSecret(secret: string): Promise<Uint8Array> {
	const secretBytes = new TextEncoder().encode(secret);
	const secretHashBuffer = await crypto.subtle.digest("SHA-256", secretBytes);
	return new Uint8Array(secretHashBuffer);
}


export default auth;