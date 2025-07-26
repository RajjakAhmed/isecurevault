import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  id: any;
  iat?: number;
  exp?: number;
}
// Augment Express' Request type to include `user`
declare module 'express-serve-static-core' {
  interface Request {
    user?: JwtPayload;
  }
}

// ✅ Export a custom AuthRequest type (optional for cleaner controller code)
export interface AuthRequest extends Request {
  user?: JwtPayload;
}

export const authenticateToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Token missing' });

  jwt.verify(token, process.env.JWT_SECRET || '', (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });

    req.user = decoded as JwtPayload;
    next();
  });
};
