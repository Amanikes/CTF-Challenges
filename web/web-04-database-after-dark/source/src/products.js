'use strict';

/**
 * Handles GET /api/products - returns public catalog items
 */
function getProducts(db, req, res) {
  try {
    const stmt = db.prepare('SELECT id, name, category, description, price, stock FROM products ORDER BY id ASC');
    const products = stmt.all();
    return res.json(products);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve products.' });
  }
}

/**
 * Handles GET /api/categories - returns unique catalog categories
 */
function getCategories(db, req, res) {
  try {
    const stmt = db.prepare('SELECT DISTINCT category FROM products ORDER BY category ASC');
    const rows = stmt.all();
    const categories = rows.map((r) => r.category);
    return res.json(categories);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve categories.' });
  }
}

module.exports = {
  getProducts,
  getCategories
};
