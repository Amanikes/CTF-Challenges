'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');

const INITIAL_PRODUCTS = [
  {
    name: 'Precision Torque Wrench Set',
    category: 'Industrial Hardware',
    description: 'Calibrated digital torque wrench set with quick-release ratchets and certified tolerance.',
    price: 189.50,
    stock: 45
  },
  {
    name: 'Heavy-Duty Modular Workbench',
    category: 'Industrial Hardware',
    description: 'Reinforced steel frame workbench with electrostatic dissipative laminate surface.',
    price: 620.00,
    stock: 12
  },
  {
    name: 'Pneumatic Rivet Fastener Gun',
    category: 'Industrial Hardware',
    description: 'Industrial pneumatic riveter for structural sheet metal and assembly lines.',
    price: 145.00,
    stock: 28
  },
  {
    name: 'Barcode Inventory Scanner Terminal',
    category: 'Logistics & Storage',
    description: 'Ruggedized Android handheld terminal with 2D long-range imager and Wi-Fi 6.',
    price: 340.00,
    stock: 35
  },
  {
    name: 'Heavy Pallet Jack 5500lbs',
    category: 'Logistics & Storage',
    description: 'Ergonomic manual hydraulic pallet truck with polyurethane load wheels.',
    price: 480.00,
    stock: 18
  },
  {
    name: 'Stackable Industrial Tote Bins (Pack of 10)',
    category: 'Logistics & Storage',
    description: 'Impact-resistant polypropylene storage containers for high-density shelving.',
    price: 115.00,
    stock: 90
  },
  {
    name: 'Thermal Shipping Label Printer',
    category: 'Office Electronics',
    description: 'High-speed 300 DPI direct thermal printer supporting standard 4x6 labels.',
    price: 229.00,
    stock: 54
  },
  {
    name: 'Enterprise Dual-Band PoE Access Point',
    category: 'Office Electronics',
    description: 'Ceiling-mount Wi-Fi 6 wireless access point with multi-gigabit uplink.',
    price: 179.99,
    stock: 30
  },
  {
    name: 'Rackmount Power Distribution Unit (16-Outlet)',
    category: 'Office Electronics',
    description: 'Monitored 1U rackmount PDU with per-circuit metering and surge suppression.',
    price: 199.50,
    stock: 22
  },
  {
    name: 'Smart Emergency Eyewash Station',
    category: 'Facility Safety',
    description: 'Wall-mounted ANSI compliant emergency eyewash with digital pressure sensor.',
    price: 310.00,
    stock: 15
  },
  {
    name: 'Multi-Gas Detector & Ambient Monitor',
    category: 'Facility Safety',
    description: 'Portable four-gas monitor detecting CO, H2S, O2, and combustible gases.',
    price: 495.00,
    stock: 20
  },
  {
    name: 'High-Visibility Laser Safety Barrier',
    category: 'Facility Safety',
    description: 'Class 4 laser protection modular acoustic curtain barrier for shop floors.',
    price: 285.00,
    stock: 25
  }
];

function initDatabase(dbPath, flag) {
  if (!flag || typeof flag !== 'string' || flag.trim() === '') {
    throw new Error('GZCTF_FLAG is missing or empty; refusing to start.');
  }

  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Remove stale database if present to ensure clean per-instance state
  if (fs.existsSync(dbPath)) {
    try {
      fs.unlinkSync(dbPath);
    } catch (_) {
      // ignore
    }
  }

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');

  // Core schema required by challenge specifications
  db.exec(`
    CREATE TABLE products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      price REAL NOT NULL,
      stock INTEGER NOT NULL
    );

    CREATE TABLE internal_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      record_name TEXT NOT NULL,
      classification TEXT NOT NULL,
      flag TEXT NOT NULL
    );
  `);

  // Populate catalog products
  const insertProduct = db.prepare(`
    INSERT INTO products (name, category, description, price, stock)
    VALUES (?, ?, ?, ?, ?)
  `);

  const insertProductsTx = db.transaction((items) => {
    for (const item of items) {
      insertProduct.run(item.name, item.category, item.description, item.price, item.stock);
    }
  });
  insertProductsTx(INITIAL_PRODUCTS);

  // Populate internal restricted record with the runtime flag
  const insertInternal = db.prepare(`
    INSERT INTO internal_records (record_name, classification, flag)
    VALUES (?, ?, ?)
  `);
  insertInternal.run('Internal Deployment Record', 'Restricted', flag.trim());

  return db;
}

module.exports = {
  initDatabase,
  INITIAL_PRODUCTS
};
