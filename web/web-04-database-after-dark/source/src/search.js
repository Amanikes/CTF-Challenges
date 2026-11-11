'use strict';

/**
 * Handles GET /api/products/search
 *
 * Vulnerability note (AxumSec College CTF - WEB-04):
 * The `category` query parameter is deliberately concatenated directly
 * into the SQL query without parameterization. This intentional flaw
 * enables UNION-based SQL injection against the 4-column SELECT query.
 */
function searchProducts(db, req, res) {
  const { category, q } = req.query;

  // Primary search/filter parameter: category
  if (category !== undefined) {
    if (typeof category !== 'string') {
      return res.status(400).json({ error: 'Invalid category parameter.' });
    }

    // =========================================================================
    // INTENTIONAL CTF VULNERABILITY (WEB-04):
    // The query below concatenates the untrusted user input directly into SQL.
    // The original query layout returns 4 columns: id, name, category, description.
    // =========================================================================
    const query = `SELECT id, name, category, description FROM products WHERE category = '${category}';`;

    try {
      const stmt = db.prepare(query);
      const rows = stmt.all();
      return res.json(rows);
    } catch (err) {
      // Do not leak raw SQL error details or filesystem paths to callers
      return res.status(400).json({ error: 'Invalid search query parameter.' });
    }
  }

  // Fallback: keyword search for the UI search bar
  if (q !== undefined) {
    if (typeof q !== 'string') {
      return res.status(400).json({ error: 'Invalid search query.' });
    }

    try {
      // Safe parameterized query for text keyword search
      const stmt = db.prepare(
        'SELECT id, name, category, description FROM products WHERE name LIKE ? OR description LIKE ? ORDER BY id ASC'
      );
      const pattern = `%${q}%`;
      const rows = stmt.all(pattern, pattern);
      return res.json(rows);
    } catch (err) {
      return res.status(400).json({ error: 'Invalid search query parameter.' });
    }
  }

  // Neither category nor q was provided
  return res.status(400).json({ error: "Missing required search parameter ('category' or 'q')." });
}

module.exports = {
  searchProducts
};
