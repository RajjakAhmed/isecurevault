import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { Request, Response, NextFunction } from 'express';
import { authenticateToken } from './auth';

// Configure multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Only create upload directory if user is authenticated
    if (req.user?.id) {
      const uploadDir = 'uploads/';
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    } else {
      cb(new Error('Unauthorized upload attempt'), '');
    }
  },
  filename: function (req, file, cb) {
    if (req.user?.id) {
      cb(null, `${Date.now()}-${req.user.id}-${file.originalname}`);
    } else {
      cb(new Error('Unauthorized upload attempt'), '');
    }
  }
});

const upload = multer({ 
  storage,
  limits: {
    fileSize: 32 * 1024 * 1024, // 32MB limit for VirusTotal
  },
  fileFilter: (req, file, cb) => {
    // Only allow upload if user is authenticated
    if (req.user?.id) {
      cb(null, true);
    } else {
      cb(new Error('Unauthorized upload attempt'));
    }
  }
});

// Combined middleware: authenticate first, then upload
export const secureUpload = [
  authenticateToken,  // First authenticate
  upload.single('file')  // Then upload if authenticated
];

