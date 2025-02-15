document.addEventListener("DOMContentLoaded", () => {
  console.log("DOM fully loaded!");

  /********************************************************/
  /*                   LOGIN HANDLER                     */
  /********************************************************/
  const loginForm = document.getElementById("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      const username = document.getElementById("username").value.trim();
      const password = document.getElementById("password").value.trim();
      const errorMessage = document.getElementById("errorMessage");

      try {
        const response = await fetch("/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });

        const result = await response.json();

        if (response.ok && result.success) {
          localStorage.setItem("username", result.username); // save username
          localStorage.setItem("token", result.token); // save token
          localStorage.setItem("isLoggedIn", "true");

          window.location.href = "/chat.html"; // redirect to chat page
        } else {
          errorMessage.style.display = "block";
          errorMessage.textContent =
            result.message || "Invalid username or password";
        }
      } catch (error) {
        console.error("Error:", error);
        errorMessage.style.display = "block";
        errorMessage.textContent = "An error occurred. Please try again.";
      }
    });
  }

  /********************************************************/
  /*               SHOW/HIDE REGISTER MODAL              */
  /********************************************************/
  // For the modal registration approach:
  const createAccountButton = document.getElementById("createAccountButton");
  const registerModal = document.getElementById("registerModal");
  const closeModal = document.getElementById("closeModal");

  registerModal.style.display = "none"; // hide modal by default

  if (createAccountButton && registerModal) {
    createAccountButton.addEventListener("click", (event) => {
      event.preventDefault();
      registerModal.style.display = "block";
    });
  }

  if (closeModal && registerModal) {
    closeModal.addEventListener("click", () => {
      registerModal.style.display = "none";
    });
  }

  /********************************************************/
  /*           PASSWORD STRENGTH METER (LIVE)            */
  /********************************************************/
  const passwordInput = document.getElementById("regPassword");
  const strengthMeter = document.getElementById("strengthMeter");
  if (passwordInput && strengthMeter) {
    passwordInput.addEventListener("input", function () {
      const val = passwordInput.value;
      let score = 0;

      if (val.length >= 6) score++;
      if (val.length >= 10) score++;
      if (/[A-Z]/.test(val)) score++;
      if (/[0-9]/.test(val)) score++;
      if (/[^a-zA-Z0-9]/.test(val)) score++;

      switch (score) {
        case 0:
        case 1:
          strengthMeter.textContent = "Weak";
          strengthMeter.style.color = "red";
          break;
        case 2:
        case 3:
          strengthMeter.textContent = "Medium";
          strengthMeter.style.color = "orange";
          break;
        case 4:
        case 5:
          strengthMeter.textContent = "Strong";
          strengthMeter.style.color = "green";
          break;
      }
    });
  }

  /********************************************************/
  /*               REGISTER FORM HANDLER                 */
  /********************************************************/
  const registerForm = document.getElementById("registerForm");
  const registerError = document.getElementById("registerError");

  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      // Grab values
      const firstName = document.getElementById("firstName").value.trim();
      const lastName = document.getElementById("lastName").value.trim();
      const email = document.getElementById("email").value.trim();
      const registerUsername = document.getElementById("regUsername").value.trim();
      const password = passwordInput.value.trim();
      const confirmPass = document.getElementById("confirmPassword").value.trim();

      // Client-side validation
      if (password.length < 6) {
        registerError.textContent = "Password must be at least 6 characters.";
        registerError.style.display = "block";
        return;
      }

      if (password !== confirmPass) {
        registerError.textContent = "Passwords do not match";
        registerError.style.display = "block";
        return;
      }

      try {
        const response = await fetch("/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            firstName,
            lastName,
            email,
            username: registerUsername,
            password,
          }),
        });

        const data = await response.json();

        if (response.ok && data.success) {
          registerError.style.display = "none";
          alert("Account created successfully!");
          if (registerModal) registerModal.style.display = "none";
          registerForm.reset();
        } else {
          registerError.textContent = data.message || "Registration failed";
          registerError.style.display = "block";
        }
      } catch (err) {
        console.error("Error:", err);
        registerError.textContent = "An error occurred. Please try again.";
        registerError.style.display = "block";
      }
    });
  }

  console.log("Login.js fully loaded!");
});
