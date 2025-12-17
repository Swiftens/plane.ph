import { neon } from '@neondatabase/serverless';
import type { User, Session } from './types.js';

export const sql = neon(process.env.NEON_STORAGE_DATABASE_URL!);

const sessionExpires = 24 * 60 * 60 * 1000;
const sessionAbsoluteExpires = 12 * 24 * 60 * 60 * 1000;

// Never send password_hash or pin_hash front-end.
export async function getUserByEmail(email: string) {
    const result = await sql`
        SELECT * FROM USERS
        WHERE email = ${email}
    `;
    return result[0];
}

// Important reminder: I am not using timezones in here.
// Using UNIX times.
export async function createSession(
    session: Session
): Promise<void> {
    const now = Date.now();
    const expiresAt = now + sessionExpires;
    const absoluteExpiresAt = now + sessionAbsoluteExpires;
    await sql`
        INSERT INTO sessions(id, user_id, secret_hash, expires_at, absolute_expires_at)
        VALUES (${session.id}, ${session.userId}, ${session.secretHash}, ${expiresAt}, ${absoluteExpiresAt})
    `;
    return;
}