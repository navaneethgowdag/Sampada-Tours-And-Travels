/* ===========================
   REUSABLE AUTH SCRIPT
   Include in all pages: <script src="js/auth.js"></script>
=========================== */

const API_URL = 'https://sampada-tours-and-travels-ood6.onrender.com';

// Update auth UI on page load
document.addEventListener('DOMContentLoaded', () => {
  updateAuthUI();
});

function updateAuthUI() {
  const token = localStorage.getItem('authToken');
  const user = JSON.parse(localStorage.getItem('user'));
  const authLinks = document.getElementById('authLinks');

  if (!authLinks) return;

  if (token && user) {
    authLinks.innerHTML = `
      <span style="font-weight:600; margin-right:10px;">
        <i class="fas fa-user-circle"></i> Hi, ${user.name}
        ${user.is_admin ? '<span style="color:#2563eb;">(Admin)</span>' : ''}
      </span>
      <button onclick="logout()" class="btn-secondary">
        <i class="fas fa-sign-out-alt"></i> Logout
      </button>
    `;
  } else {
    authLinks.innerHTML = `
      <a href="login.html" class="btn-secondary">Login</a>
      <a href="register.html" class="btn-primary">Sign Up</a>
    `;
  }
}

function logout() {
  localStorage.removeItem('authToken');
  localStorage.removeItem('user');

  showMessage('Logged out successfully', 'success');
  setTimeout(() => location.href = 'index.html', 1000);
}

function showMessage(msg, type = 'info') {
  const div = document.createElement('div');
  div.textContent = msg;
  div.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 15px 20px;
    border-radius: 5px;
    color: white;
    background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#2563eb'};
    z-index: 9999;
    animation: slideIn 0.3s ease;
  `;
  document.body.appendChild(div);
  setTimeout(() => div.remove(), 3000);
}

// Check login status
function isLoggedIn() {
  return !!localStorage.getItem('authToken');
}

// Get current user
function getCurrentUser() {
  return JSON.parse(localStorage.getItem('user'));
}

// 🔐 Protect admin pages
function requireAdmin() {
  const user = getCurrentUser();

  if (!user) {
    alert("Please login as admin.");
    window.location.href = "login.html?redirect=admin.html";
    return false;
  }

  if (!user.is_admin) {
    alert("Access denied. Admins only.");
    window.location.href = "index.html";
    return false;
  }

  return true;
}

// API request helper
async function apiRequest(endpoint, options = {}) {
  const token = localStorage.getItem('authToken');

  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
    ...(token ? { 'Authorization': `Bearer ${token}` } : {})
  };

  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || 'API request failed');
  }

  return response.json();
}

// Export globally
window.AUTH = {
  API_URL,
  isLoggedIn,
  getCurrentUser,
  requireAdmin,
  logout,
  showMessage,
  updateAuthUI,
  apiRequest
};
