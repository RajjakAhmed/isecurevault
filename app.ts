import express, { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import fs from 'fs';
import { scanFile } from './utils/virusScan';



import uploadRoutes from './routes/uploadRoutes';
import { FileSecurity } from './utils/file';
import { authenticateToken } from './middleware/auth';
import { upload, processUpload } from './middleware/upload';


dotenv.config();

// Initialize Prisma and Express
const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_ENABLED = process.env.ENABLE_ENCRYPTION === 'true';


// Validate required environment variables
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('Invalid JWT_SECRET - must be at least 32 characters');
  process.exit(1);
}

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));
//const app = express();
app.use(express.json());

app.use('/files', uploadRoutes);

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

// Helper functions
const hashPassword = async (password: string): Promise<string> => {
  return bcrypt.hash(password, 12);
};

const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};

const generateToken = (userId: number): string => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' });
};

// Routes
app.get('/', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    version: '1.0.0',
    services: ['auth', 'files']
  });
});

app.post('/register', apiLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await prisma.user.findFirst({
      where: { OR: [{ username }, { email }] }
    });

    if (existingUser) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    const user = await prisma.user.create({
      data: {
        username,
        email,
        password: await hashPassword(password)
      },
      select: {
        id: true,
        username: true,
        email: true,
        createdAt: true
      }
    });

    res.status(201).json(user);
  } catch (error) {
    next(error);
  }
});

app.post('/login', apiLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { username, password } = req.body;

    const user = await prisma.user.findUnique({
      where: { username },
      select: {
        id: true,
        username: true,
        password: true
      }
    });

    if (!user || !(await comparePassword(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user.id);
    
    res.json({
      id: user.id,
      username: user.username,
      token
    });
  } catch (error) {
    next(error);
  }
});

// File routes


app.post('/files/upload', upload.single('file'), async (req, res) => {
  const file = req.file;

  if (!file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    const isClean = await scanFile(file.path);
    if (!isClean) {
      // Optionally delete the infected file here
      return res.status(400).json({ error: 'File contains malware' });
    }

    // 🔐 Proceed with encryption or saving logic here
    res.status(200).json({ message: 'File uploaded safely' });

  } catch (err) {
    console.error('Virus scan failed:', err);
    res.status(500).json({ error: 'Virus scan failed' });
  }
});

app.get('/files', 
  authenticateToken,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const files = await prisma.file.findMany({
        where: { ownerId: req.user!.id },
        select: {
          id: true,
          filename: true,
          size: true,
          isEncrypted: true,
          createdAt: true
        },
        orderBy: { createdAt: 'desc' }
      });
      res.json(files);
    } catch (error) {
      next(error);
    }
  }
);

app.get('/files/:id/download', 
  authenticateToken,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const fileId = parseInt(req.params.id);
      const file = await prisma.file.findUnique({
        where: { id: fileId },
        select: {
          id: true,
          filename: true,
          path: true,
          size: true,
          isEncrypted: true,
          ownerId: true
        }
      });

      if (!file || file.ownerId !== req.user!.id) {
        return res.status(404).json({ error: 'File not found' });
      }

      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);

      if (file.isEncrypted) {
        const decrypted = await FileSecurity.decryptFile(file.path);
        res.setHeader('Content-Length', decrypted.length);
        return res.end(decrypted);
      }

      const stream = fs.createReadStream(file.path);
      stream.pipe(res);
    } catch (error) {
      next(error);
    }
  }
);

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Server startup
async function startServer() {
  try {
    await prisma.$connect();
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
      console.log('Connected to database');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown() {
  await prisma.$disconnect();
  console.log('Database connection closed');
  process.exit(0);
}

startServer();
