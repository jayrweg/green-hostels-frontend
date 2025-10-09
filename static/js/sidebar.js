// Universal Sidebar Toggle Function
function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  
  if (window.innerWidth <= 600) {
    // Mobile behavior - toggle show/hide with text visibility
    sidebar.classList.toggle('show');
  } else if (window.innerWidth <= 900) {
    // Tablet behavior - keep collapsed but allow toggle for testing
    sidebar.classList.toggle('collapsed');
  } else {
    // Desktop behavior - toggle collapsed/expanded
    sidebar.classList.toggle('collapsed');
  }
}

// Close sidebar when clicking outside on mobile
document.addEventListener('click', function(event) {
  const sidebar = document.getElementById('sidebar');
  const toggleButtons = document.querySelectorAll('.sidebar-toggle, .sidebar-toggle-global');
  
  if (window.innerWidth <= 600 && 
      sidebar.classList.contains('show') && 
      !sidebar.contains(event.target) && 
      !Array.from(toggleButtons).some(btn => btn.contains(event.target))) {
    sidebar.classList.remove('show');
  }
});

// Handle window resize
window.addEventListener('resize', function() {
  const sidebar = document.getElementById('sidebar');
  
  if (window.innerWidth > 600) {
    // Desktop/Tablet - remove mobile show class
    sidebar.classList.remove('show');
  } else {
    // Mobile - remove desktop collapsed class
    sidebar.classList.remove('collapsed');
  }
});

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
  // Ensure proper initial state
  const sidebar = document.getElementById('sidebar');
  if (window.innerWidth <= 600) {
    sidebar.classList.remove('collapsed');
    sidebar.classList.remove('show');
  } else {
    sidebar.classList.remove('show');
  }
});

