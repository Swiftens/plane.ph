- Always use Secure protocols
- HTTPS everywhere
- Understand security headers
- Update your dependencies: npm audit
- Validate SSL
- Never hardcode keys. Use environment variables
- Find a way to prevent DoS attacks: Rate Limiting + WAF

**PostgreSQL**

- Connection Pooling
- SQL Injection: Never concatenate directly
- Create Roles: Principle of Least Privilege
- In the future, implement redis for faster processing

**Auth**

- We use session tokens to validate requests
- Session tokens must have a generous limit but still secure: 14 days rolling, hashed storage
- Admin should be able to lock a user if needed.
- Inactivity soft lock
- sudo/privilege access for critical actions. - 15 minutes of sudo
- Argon2 for password hashing
