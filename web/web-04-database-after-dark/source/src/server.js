'use strict';

const path = require('node:path');
const express = require('express');
const { initDatabase } = require('./database');
const { getProducts, getCategories } = require('./products');
const { searchProducts } = require('./search');

const flag = process.env.GZCTF_FLAG;
if (!flag || typeof flag !== 'string' || flag.trim() === '') {
  console.error('[FATAL] GZCTF_FLAG is missing or empty; refusing to start.');
  process.exit(1);
}

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../data/inventory.db');

let db;
try {
  db = initDatabase(DB_PATH, flag);
} catch (err) {
  console.error('[FATAL] Failed to initialize database:', err.message);
  process.exit(1);
}

const app = express();
app.disable('x-powered-by');

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});

// Serve frontend static assets (only public directory)
app.use(express.static(path.join(__dirname, '../public'), {
  index: 'index.html',
  maxAge: 0
}));

// API Routes
app.get('/api/products', (req, res) => getProducts(db, req, res));
app.get('/api/products/search', (req, res) => searchProducts(db, req, res));
app.get('/api/categories', (req, res) => getCategories(db, req, res));

// Health endpoints
app.get(['/health', '/healthz'], (req, res) => {
  res.status(200).json({ status: 'ok', service: 'blackstone-inventory' });
});

// Fallback route
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

const server = app.listen(PORT, HOST, () => {
  console.log(`[INFO] Blackstone Commerce inventory portal listening on http://${HOST}:${PORT}`);
});

function gracefulShutdown(signal) {
  console.log(`[INFO] Received ${signal}. Shutting down gracefully...`);
  server.close(() => {
    try {
      if (db) {
        db.close();
      }
    } catch (_) {
      // ignore
    }
    process.exit(0);
  });

  setTimeout(() => {
    console.error('[WARN] Forced shutdown after timeout.');
    process.exit(1);
  }, 5000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
