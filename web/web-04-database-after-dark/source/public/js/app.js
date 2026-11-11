'use strict';

(function () {
  // DOM References
  const searchInput = document.getElementById('search-input');
  const searchBtn = document.getElementById('search-btn');
  const resetBtn = document.getElementById('reset-btn');
  const clearSearchBtn = document.getElementById('clear-search-btn');
  const categoryPillsContainer = document.getElementById('category-pills');
  const productGrid = document.getElementById('product-grid');
  const productTableWrapper = document.getElementById('product-table-wrapper');
  const productTableBody = document.getElementById('product-table-body');
  const resultsCount = document.getElementById('results-count');
  const metricTotal = document.getElementById('metric-total');
  const metricCategories = document.getElementById('metric-categories');
  const stateLoading = document.getElementById('state-loading');
  const stateError = document.getElementById('state-error');
  const stateEmpty = document.getElementById('state-empty');
  const errorMessage = document.getElementById('error-message');
  const errorRetryBtn = document.getElementById('error-retry-btn');
  const viewGridBtn = document.getElementById('view-grid-btn');
  const viewTableBtn = document.getElementById('view-table-btn');

  // Application State
  let currentProducts = [];
  let currentCategory = '';
  let currentView = 'grid'; // 'grid' | 'table'

  function showState(state) {
    stateLoading.hidden = state !== 'loading';
    stateError.hidden = state !== 'error';
    stateEmpty.hidden = state !== 'empty';

    if (state === 'content') {
      if (currentView === 'grid') {
        productGrid.hidden = false;
        productTableWrapper.hidden = true;
      } else {
        productGrid.hidden = true;
        productTableWrapper.hidden = false;
      }
    } else {
      productGrid.hidden = true;
      productTableWrapper.hidden = true;
    }
  }

  function formatCurrency(val) {
    if (val === undefined || val === null) return '—';
    const num = Number(val);
    if (isNaN(num)) return '—';
    return `$${num.toFixed(2)}`;
  }

  function formatStock(val) {
    if (val === undefined || val === null) {
      return '<span class="card-stock stock-na">Restricted</span>';
    }
    const num = Number(val);
    if (isNaN(num)) {
      return '<span class="card-stock stock-na">Restricted</span>';
    }
    return `<span class="card-stock stock-in">${num} in stock</span>`;
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function renderProducts(products) {
    currentProducts = products;
    metricTotal.textContent = products.length;

    if (!products || products.length === 0) {
      resultsCount.textContent = '0 items found';
      showState('empty');
      return;
    }

    resultsCount.textContent = `Showing ${products.length} product${products.length === 1 ? '' : 's'}`;

    // Render Grid
    productGrid.innerHTML = products.map((item) => `
      <article class="product-card">
        <div class="card-top">
          <span class="card-id">#${escapeHtml(item.id)}</span>
          <span class="card-category">${escapeHtml(item.category || 'General')}</span>
        </div>
        <h2 class="card-title">${escapeHtml(item.name || 'Unnamed Item')}</h2>
        <p class="card-desc">${escapeHtml(item.description || 'No description available.')}</p>
        <div class="card-bottom">
          <span class="card-price">${formatCurrency(item.price)}</span>
          ${formatStock(item.stock)}
        </div>
      </article>
    `).join('');

    // Render Table
    productTableBody.innerHTML = products.map((item) => `
      <tr>
        <td class="col-id">#${escapeHtml(item.id)}</td>
        <td class="col-name">${escapeHtml(item.name || 'Unnamed Item')}</td>
        <td class="col-category">
          <span class="card-category">${escapeHtml(item.category || 'General')}</span>
        </td>
        <td class="col-description">${escapeHtml(item.description || 'No description available.')}</td>
        <td class="col-price">${formatCurrency(item.price)}</td>
        <td class="col-stock">${formatStock(item.stock)}</td>
      </tr>
    `).join('');

    showState('content');
  }

  async function fetchCategories() {
    try {
      const res = await fetch('/api/categories');
      if (!res.ok) throw new Error('Failed to load categories');
      const categories = await res.json();
      metricCategories.textContent = categories.length;

      // Render category pills
      const pillHtml = ['<button type="button" class="category-pill active" data-category="">All Categories</button>'];
      categories.forEach((cat) => {
        pillHtml.push(`<button type="button" class="category-pill" data-category="${escapeHtml(cat)}">${escapeHtml(cat)}</button>`);
      });
      categoryPillsContainer.innerHTML = pillHtml.join('');

      // Add click handlers
      categoryPillsContainer.querySelectorAll('.category-pill').forEach((btn) => {
        btn.addEventListener('click', () => {
          const cat = btn.dataset.category || '';
          setActiveCategory(cat);
          if (cat === '') {
            loadAllProducts();
          } else {
            searchByCategory(cat);
          }
        });
      });
    } catch (err) {
      console.warn('Could not fetch categories:', err.message);
    }
  }

  function setActiveCategory(cat) {
    currentCategory = cat;
    categoryPillsContainer.querySelectorAll('.category-pill').forEach((btn) => {
      btn.classList.toggle('active', (btn.dataset.category || '') === cat);
    });
  }

  async function loadAllProducts() {
    showState('loading');
    resultsCount.textContent = 'Loading catalog items...';
    try {
      const res = await fetch('/api/products');
      if (!res.ok) {
        throw new Error(`Failed to load products: HTTP ${res.status}`);
      }
      const products = await res.json();
      renderProducts(products);
    } catch (err) {
      errorMessage.textContent = err.message || 'Unable to retrieve catalog data.';
      showState('error');
    }
  }

  async function searchByCategory(category) {
    showState('loading');
    resultsCount.textContent = `Filtering category: "${category}"...`;
    try {
      const res = await fetch(`/api/products/search?category=${encodeURIComponent(category)}`);
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `Search query failed with status ${res.status}`);
      }
      const products = await res.json();
      renderProducts(products);
    } catch (err) {
      errorMessage.textContent = err.message || 'Error occurred while querying database.';
      showState('error');
    }
  }

  async function executeSearch() {
    const q = searchInput.value.trim();
    if (!q && !currentCategory) {
      loadAllProducts();
      return;
    }

    showState('loading');
    try {
      let url;
      if (currentCategory) {
        url = `/api/products/search?category=${encodeURIComponent(currentCategory)}`;
      } else {
        url = `/api/products/search?q=${encodeURIComponent(q)}`;
      }

      resultsCount.textContent = 'Searching inventory records...';
      const res = await fetch(url);
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `Search query failed with status ${res.status}`);
      }
      const products = await res.json();
      renderProducts(products);
    } catch (err) {
      errorMessage.textContent = err.message || 'Error occurred while executing query.';
      showState('error');
    }
  }

  // Event Listeners
  searchBtn.addEventListener('click', executeSearch);

  searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      executeSearch();
    }
  });

  searchInput.addEventListener('input', () => {
    clearSearchBtn.hidden = searchInput.value.length === 0;
  });

  clearSearchBtn.addEventListener('click', () => {
    searchInput.value = '';
    clearSearchBtn.hidden = true;
    searchInput.focus();
    if (currentCategory) {
      searchByCategory(currentCategory);
    } else {
      loadAllProducts();
    }
  });

  resetBtn.addEventListener('click', () => {
    searchInput.value = '';
    clearSearchBtn.hidden = true;
    setActiveCategory('');
    loadAllProducts();
  });

  errorRetryBtn.addEventListener('click', () => {
    setActiveCategory('');
    searchInput.value = '';
    clearSearchBtn.hidden = true;
    loadAllProducts();
  });

  viewGridBtn.addEventListener('click', () => {
    currentView = 'grid';
    viewGridBtn.classList.add('active');
    viewTableBtn.classList.remove('active');
    showState(currentProducts.length > 0 ? 'content' : 'empty');
  });

  viewTableBtn.addEventListener('click', () => {
    currentView = 'table';
    viewTableBtn.classList.add('active');
    viewGridBtn.classList.remove('active');
    showState(currentProducts.length > 0 ? 'content' : 'empty');
  });

  // Initialization
  fetchCategories();
  loadAllProducts();
})();
