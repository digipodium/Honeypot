/* ============================================================
   DRAPE — Clothing Website Script
   Handles: SPA navigation, product rendering, cart, filters,
            product detail, contact form, navbar scroll effect.
   ============================================================ */

/* -----------------------------------------------
   1. PRODUCT DATA
   Each product: id, name, price, category, emoji
   (emoji acts as a placeholder "image")
----------------------------------------------- */
const products = [
  { id: 1,  name: "Classic White Tee",      price: 29,  category: "shirts",  emoji: "👕", color: "#f5f0e8",
    desc: "Our signature heavyweight cotton tee in crisp white. Relaxed fit, pre-washed for softness. A wardrobe essential that pairs with everything.",
    material: "100% Organic Cotton", fit: "Relaxed" },

  { id: 2,  name: "Slim Indigo Jeans",       price: 89,  category: "jeans",   emoji: "👖", color: "#dce8f5",
    desc: "Tailored slim-fit jeans in deep indigo selvedge denim. Slight stretch for all-day comfort without compromising on structure.",
    material: "98% Cotton, 2% Elastane", fit: "Slim" },

  { id: 3,  name: "Essential Hoodie",        price: 65,  category: "hoodies", emoji: "🧥", color: "#ede8f5",
    desc: "Heavyweight fleece hoodie with a kangaroo pocket and ribbed cuffs. Brushed interior for a cozy feel on colder days.",
    material: "80% Cotton, 20% Polyester", fit: "Oversized" },

  { id: 4,  name: "Linen Summer Shirt",      price: 55,  category: "shirts",  emoji: "👔", color: "#f5f0e0",
    desc: "Breathable washed linen shirt with a relaxed Cuban collar. Perfect for warm weather — effortlessly elegant.",
    material: "100% European Linen", fit: "Relaxed" },

  { id: 5,  name: "Moto Leather Jacket",     price: 189, category: "jackets", emoji: "🧣", color: "#e8e8e8",
    desc: "Genuine full-grain leather moto jacket with a YKK zipper and quilted shoulder panels. Gets better with every wear.",
    material: "Full-Grain Leather", fit: "Regular" },

  { id: 6,  name: "Cargo Wide Trousers",     price: 79,  category: "jeans",   emoji: "🩲", color: "#e8f5ee",
    desc: "Relaxed wide-leg trousers with cargo pockets in a durable ripstop fabric. Utilitarian style meets everyday comfort.",
    material: "100% Ripstop Cotton", fit: "Wide Leg" },

  { id: 7,  name: "Striped Breton Tee",      price: 39,  category: "shirts",  emoji: "👕", color: "#edf5f5",
    desc: "Classic Breton stripe tee in navy and white. Fine-knit jersey with a slightly cropped fit. A timeless French classic.",
    material: "100% Fine Jersey Cotton", fit: "Regular" },

  { id: 8,  name: "Zip-Up Fleece",           price: 72,  category: "hoodies", emoji: "🧤", color: "#f5ebe8",
    desc: "Sherpa-lined zip-up fleece with a stand collar. Ultra-warm without the bulk — your go-to layer for autumn and winter.",
    material: "Sherpa Fleece Blend", fit: "Regular" },

  { id: 9,  name: "Denim Trucker Jacket",    price: 129, category: "jackets", emoji: "🧢", color: "#dce8f5",
    desc: "Icon stonewash trucker jacket in raw blue denim. Four-pocket styling, button-front closure. Built to last decades.",
    material: "12oz Denim", fit: "Regular" },

  { id: 10, name: "Relaxed Chinos",          price: 69,  category: "jeans",   emoji: "👗", color: "#f5f0e0",
    desc: "Tailored relaxed-fit chinos in a soft garment-dyed cotton twill. Welt pockets, no break hem. Smart-casual perfection.",
    material: "100% Combed Cotton", fit: "Relaxed" },

  { id: 11, name: "Oversized Graphic Tee",   price: 45,  category: "shirts",  emoji: "🎽", color: "#f0ede8",
    desc: "Heavyweight 260gsm tee with an original hand-drawn graphic screen print. Drop shoulders, boxy cut. Limited run.",
    material: "100% Ring-Spun Cotton", fit: "Oversized" },

  { id: 12, name: "Bomber Jacket",           price: 155, category: "jackets", emoji: "🪬", color: "#e8f5ee",
    desc: "Satin bomber in forest green with contrast ribbed collar and cuffs. Lined interior with inside zip pocket.",
    material: "Satin Polyester + Nylon Lining", fit: "Regular" },
];

/* -----------------------------------------------
   2. CART STATE
   We store cart as an array of { product, qty }
----------------------------------------------- */
let cart = [];

/* Previous page tracker (for "Back" button on detail page) */
let previousPage = 'home';

/* -----------------------------------------------
   3. INITIALISE — run when page loads
----------------------------------------------- */
document.addEventListener('DOMContentLoaded', () => {
  renderFeatured();    // render 6 items on homepage
  renderShop('all');   // render all items on shop page
  initNavbarScroll();  // sticky navbar shadow on scroll
});

/* -----------------------------------------------
   4. SPA NAVIGATION — show/hide pages
----------------------------------------------- */
function showPage(pageName) {
  /* Record previous page for the back button */
  const current = document.querySelector('.page.active');
  if (current) previousPage = current.id.replace('page-', '');

  /* Hide all pages */
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));

  /* Show the target page */
  const target = document.getElementById('page-' + pageName);
  if (target) target.classList.add('active');

  /* Update active nav link */
  document.querySelectorAll('.nav-link').forEach(link => {
    link.classList.toggle('active', link.getAttribute('onclick').includes(`'${pageName}'`));
  });

  /* Close mobile menu if open */
  closeMenu();

  /* Scroll to top */
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* -----------------------------------------------
   5. MOBILE MENU
----------------------------------------------- */
function toggleMenu() {
  const nav  = document.getElementById('navLinks');
  const btn  = document.getElementById('hamburger');
  nav.classList.toggle('open');
  btn.classList.toggle('open');
}

function closeMenu() {
  document.getElementById('navLinks').classList.remove('open');
  document.getElementById('hamburger').classList.remove('open');
}

/* -----------------------------------------------
   6. NAVBAR SCROLL EFFECT
----------------------------------------------- */
function initNavbarScroll() {
  window.addEventListener('scroll', () => {
    document.getElementById('navbar').classList.toggle('scrolled', window.scrollY > 30);
  });
}

/* -----------------------------------------------
   7. RENDER FEATURED (homepage — first 6 items)
----------------------------------------------- */
function renderFeatured() {
  const grid = document.getElementById('featuredGrid');
  const featured = products.slice(0, 6);
  grid.innerHTML = featured.map(p => createProductCard(p)).join('');
}

/* -----------------------------------------------
   8. RENDER SHOP (all or filtered)
----------------------------------------------- */
function renderShop(category) {
  const grid = document.getElementById('shopGrid');
  const filtered = category === 'all' ? products : products.filter(p => p.category === category);
  grid.innerHTML = filtered.length
    ? filtered.map(p => createProductCard(p)).join('')
    : `<p style="color:var(--mid); grid-column:1/-1;">No products found in this category.</p>`;
}

/* -----------------------------------------------
   9. CREATE PRODUCT CARD HTML (reusable)
----------------------------------------------- */
function createProductCard(product) {
  return `
    <div class="product-card" onclick="openDetail(${product.id})">
      <!-- Product image (emoji placeholder on coloured bg) -->
      <div class="product-img" style="background:${product.color}">
        <span class="product-category-badge">${product.category}</span>
        ${product.emoji}
      </div>
      <!-- Product info -->
      <div class="product-info">
        <div class="product-name">${product.name}</div>
        <div class="product-price">$${product.price}</div>
        <!-- Stop click bubbling to card (don't open detail) -->
        <button class="add-cart-btn" id="btn-${product.id}"
          onclick="event.stopPropagation(); addToCart(${product.id})">
          Add to Cart
        </button>
      </div>
    </div>
  `;
}

/* -----------------------------------------------
   10. CATEGORY FILTER (shop page)
----------------------------------------------- */
function filterProducts(category, buttonEl) {
  /* Update active filter button */
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  buttonEl.classList.add('active');
  /* Re-render grid */
  renderShop(category);
}

/* -----------------------------------------------
   11. PRODUCT DETAIL PAGE
----------------------------------------------- */
function openDetail(productId) {
  const product = products.find(p => p.id === productId);
  if (!product) return;

  /* Store where we came from */
  const current = document.querySelector('.page.active');
  previousPage = current ? current.id.replace('page-', '') : 'home';

  /* Build detail HTML */
  const detail = document.getElementById('detailContent');
  detail.innerHTML = `
    <div class="detail-img" style="background:${product.color}">${product.emoji}</div>
    <div class="detail-info">
      <span class="section-tag">${product.category}</span>
      <div class="detail-title">${product.name}</div>
      <div class="detail-price">$${product.price}</div>
      <p class="detail-desc">${product.desc}</p>
      <div class="detail-meta">
        <div class="detail-meta-item">
          <strong>Material</strong>
          <span>${product.material}</span>
        </div>
        <div class="detail-meta-item">
          <strong>Fit</strong>
          <span>${product.fit}</span>
        </div>
        <div class="detail-meta-item">
          <strong>Category</strong>
          <span style="text-transform:capitalize">${product.category}</span>
        </div>
        <div class="detail-meta-item">
          <strong>Availability</strong>
          <span style="color:#2e7d32">In Stock</span>
        </div>
      </div>
      <button class="btn btn-primary" id="detail-cart-btn"
        onclick="addToCart(${product.id}); document.getElementById('detail-cart-btn').textContent='✓ Added!'">
        Add to Cart — $${product.price}
      </button>
    </div>
  `;

  showPage('detail');
}

/* Go back to previous page */
function goBack() {
  showPage(previousPage);
}

/* -----------------------------------------------
   12. CART — ADD TO CART
----------------------------------------------- */
function addToCart(productId) {
  const product = products.find(p => p.id === productId);
  if (!product) return;

  /* Check if item already in cart — if so, increase qty */
  const existing = cart.find(item => item.product.id === productId);
  if (existing) {
    existing.qty++;
  } else {
    cart.push({ product, qty: 1 });
  }

  updateCartUI();
  flashCartButton(productId);
}

/* -----------------------------------------------
   13. CART — CHANGE QUANTITY
----------------------------------------------- */
function changeQty(productId, delta) {
  const item = cart.find(i => i.product.id === productId);
  if (!item) return;

  item.qty += delta;
  if (item.qty <= 0) {
    /* Remove from cart */
    cart = cart.filter(i => i.product.id !== productId);
  }

  updateCartUI();
}

/* -----------------------------------------------
   14. CART — REMOVE ITEM
----------------------------------------------- */
function removeFromCart(productId) {
  cart = cart.filter(i => i.product.id !== productId);
  updateCartUI();
}

/* -----------------------------------------------
   15. CART — UPDATE ALL UI
----------------------------------------------- */
function updateCartUI() {
  /* Total count */
  const totalQty = cart.reduce((sum, i) => sum + i.qty, 0);
  const countEl = document.getElementById('cartCount');
  countEl.textContent = totalQty;

  /* Bump animation on count badge */
  countEl.classList.remove('bump');
  void countEl.offsetWidth; // reflow trick to restart animation
  countEl.classList.add('bump');
  setTimeout(() => countEl.classList.remove('bump'), 300);

  /* Cart items list */
  const itemsEl = document.getElementById('cartItems');
  if (cart.length === 0) {
    itemsEl.innerHTML = `<div class="cart-empty">Your cart is empty.<br/>Start adding some pieces!</div>`;
  } else {
    itemsEl.innerHTML = cart.map(({ product, qty }) => `
      <div class="cart-item">
        <div class="cart-item-img" style="background:${product.color}">${product.emoji}</div>
        <div style="flex:1">
          <div class="cart-item-name">${product.name}</div>
          <div class="cart-item-price">$${product.price}</div>
          <div class="cart-item-qty">
            <button class="qty-btn" onclick="changeQty(${product.id}, -1)">−</button>
            <span class="qty-val">${qty}</span>
            <button class="qty-btn" onclick="changeQty(${product.id}, 1)">+</button>
          </div>
        </div>
        <button class="remove-btn" onclick="removeFromCart(${product.id})">Remove</button>
      </div>
    `).join('');
  }

  /* Cart footer (total + checkout) */
  const footerEl = document.getElementById('cartFooter');
  const total = cart.reduce((sum, i) => sum + i.product.price * i.qty, 0);
  if (cart.length > 0) {
    footerEl.innerHTML = `
      <div class="cart-total">
        <span>Total</span>
        <span>$${total}</span>
      </div>
      <button class="checkout-btn" onclick="handleCheckout()">Proceed to Checkout</button>
    `;
    footerEl.style.display = 'block';
  } else {
    footerEl.innerHTML = '';
  }
}

/* -----------------------------------------------
   16. CART — TOGGLE OPEN/CLOSE SIDEBAR
----------------------------------------------- */
function toggleCart() {
  document.getElementById('cartSidebar').classList.toggle('open');
  document.getElementById('cartOverlay').classList.toggle('open');
}

/* -----------------------------------------------
   17. CART BUTTON FLASH (visual feedback)
----------------------------------------------- */
function flashCartButton(productId) {
  const btn = document.getElementById('btn-' + productId);
  if (!btn) return;
  const original = btn.textContent;
  btn.textContent = '✓ Added!';
  btn.classList.add('added');
  setTimeout(() => {
    btn.textContent = original;
    btn.classList.remove('added');
  }, 1500);
}

/* -----------------------------------------------
   18. CHECKOUT (mock)
----------------------------------------------- */
function handleCheckout() {
  const total = cart.reduce((sum, i) => sum + i.product.price * i.qty, 0);
  alert(`Thanks for your order! 🎉\nTotal: $${total}\n\nThis is a demo checkout — no payment processed.`);
  cart = [];
  updateCartUI();
  toggleCart();
}

/* -----------------------------------------------
   19. CONTACT FORM SUBMIT
----------------------------------------------- */
function handleFormSubmit(event) {
  event.preventDefault();                        // prevent page reload

  const name    = document.getElementById('name').value.trim();
  const email   = document.getElementById('email').value.trim();
  const message = document.getElementById('message').value.trim();

  /* Basic validation */
  if (!name || !email || !message) {
    alert('Please fill in all fields.');
    return;
  }

  /* In a real app you'd POST to a backend here */
  console.log('Form submitted:', { name, email, message });

  /* Show success message & reset form */
  document.getElementById('formSuccess').classList.add('show');
  event.target.reset();

  setTimeout(() => {
    document.getElementById('formSuccess').classList.remove('show');
  }, 4000);
}
