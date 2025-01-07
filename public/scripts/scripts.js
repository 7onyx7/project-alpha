// scripts.js

document.addEventListener("DOMContentLoaded", () => {
  // Event listeners for the buttons
  document.getElementById("anon").addEventListener("click", () => {
    window.location.href = "chat.html"; // Redirect to the chat page
  });

  document.getElementById("login").addEventListener("click", () => {
    window.location.href = "login.html"; // Redirect to the login page
  });
});
