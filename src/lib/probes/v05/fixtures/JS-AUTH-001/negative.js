// XL-013 / JS-AUTH-001 negative fixture.
// Signed algorithm + verify called with an explicit key.
import jwt from 'jsonwebtoken';

const signingKey = process.env.JWT_SECRET;

export function issue(payload) {
  return jwt.sign(payload, signingKey, { algorithm: 'HS256' });
}

export function check(token) {
  return jwt.verify(token, signingKey);
}
