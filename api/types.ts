export interface User {
    userId: string,
    email: string
    passwordHash: string,
    pinHash: string,
    createdAt: string,
    updatedAt: string,
    lastLogin: string
}

export interface Session {
    id: string,
    userId: string,
    secretHash: Uint8Array
}

export interface SessionWithToken extends Session {
    token: string
}