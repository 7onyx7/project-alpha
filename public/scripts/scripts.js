document.addEventListener("DOMContentLoaded", () => {
  // Redirect to chat when clicking the "Anon" button
  document.getElementById("anon").addEventListener("click", () => {
    window.location.href = "chat.html";
  });

  // Redirect to login when clicking the "Login" button
  document.getElementById("login").addEventListener("click", () => {
    window.location.href = "login.html";
  });
});
