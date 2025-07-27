
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  userId: number;  // This matches what your login generates
  iat?: number;
  exp?: number;
}

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;  // Standardize on 'id' for consistency
        userId: number; // Keep userId for backward compatibility
        iat?: number;
        exp?: number;
      };
    }
  }
}

export interface AuthRequest extends Request {
  user: {
    id: number;
    userId: number;
    iat?: number;
    exp?: number;
  };
}

export const authenticateToken = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];

    if (!token) {
      console.log('Authentication failed: No token provided');
      return res.status(401).json({ error: 'Token missing' });
    }

    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) {
      console.error('JWT_SECRET not configured');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        console.log('Authentication failed: Invalid token', err.message);
        return res.status(403).json({ error: 'Invalid token' });
      }

      const payload = decoded as JwtPayload;
      
      // Set user object with both id and userId for compatibility
      req.user = {
        id: payload.userId,        // Map userId to id for consistency
        userId: payload.userId,    // Keep original userId
        iat: payload.iat,
        exp: payload.exp
      };

      console.log(`User authenticated: ${req.user.id}`);
      next();
    });
  } catch (error) {
    console.error('Authentication middleware error:', error);
    return res.status(500).json({ error: 'Authentication error' });
  }
};
