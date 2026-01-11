/* ===========================
   REUSABLE AUTH SCRIPT
   Include this in all pages: <script src="js/auth.js"></script>
=========================== */

const API_URL = 'http://localhost:3000';

// Update auth UI on page load
document.addEventListener('DOMContentLoaded', () => {
  updateAuthUI();
});

function updateAuthUI() {
  const token = localStorage.getItem('authToken');
  const username = localStorage.getItem('username');
  const authLinks = document.getElementById('authLinks');
  
  if (!authLinks) return;

  if (token && username) {
    authLinks.innerHTML = `
      <span style="font-weight:600; margin-right:10px;">
        <i class="fas fa-user-circle"></i> Hi, ${username}
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
  localStorage.removeItem('username');
  
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

// Helper to check if user is logged in
function isLoggedIn() {
  return !!localStorage.getItem('authToken');
}

// Helper to get current user
function getCurrentUser() {
  return {
    token: localStorage.getItem('authToken'),
    username: localStorage.getItem('username')
  };
}

// Export for use in other scripts
window.AUTH = {
  API_URL,
  isLoggedIn,
  getCurrentUser,
  logout,
  showMessage,
  updateAuthUI
};``