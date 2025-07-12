document.addEventListener("DOMContentLoaded", () => {
  console.log("DOM fully loaded!");

  /********************************************************/
  /*                   LOGIN HANDLER                     */
  /********************************************************/
  const loginForm = document.getElementById("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", async function (event) {
      event.preventDefault();

      // Add CSRF token to form
      await csrfUtils.addTokenToForm(loginForm);

      const username = document.getElementById("username").value.trim();
      const password = document.getElementById("password").value.trim();
      const errorMessage = document.getElementById("errorMessage");

      try {
        // Get CSRF token and add to fetch options
        const fetchOptions = await csrfUtils.addTokenToFetchOptions({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });

        const response = await fetch("/login", fetchOptions);

        const result = await response.json();

        if (response.ok && result.success) {
          localStorage.setItem("username", result.username); // save username
          localStorage.setItem("token", result.token); // save token
          localStorage.setItem("isLoggedIn", "true");
          localStorage.setItem("userId", result.userId); // save user ID
          localStorage.setItem("role", result.role || 'user'); // save role

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
        // Get CSRF token and add to fetch options
        const fetchOptions = await csrfUtils.addTokenToFetchOptions({
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

        const response = await fetch("/register", fetchOptions);

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

  /********************************************************/
  /*             FORGOT PASSWORD FUNCTIONALITY            */
  /********************************************************/
  const forgotPasswordLink = document.getElementById("forgotPasswordLink");
  const forgotPasswordModal = document.getElementById("forgotPasswordModal");
  const closeForgotModal = document.getElementById("closeForgotModal");
  const forgotPasswordForm = document.getElementById("forgotPasswordForm");
  const forgotPasswordMessage = document.getElementById("forgotPasswordMessage");

  // Initialize the forgot password modal as hidden
  if (forgotPasswordModal) {
    forgotPasswordModal.style.display = "none";
  }

  // Show the forgot password modal when the link is clicked
  if (forgotPasswordLink && forgotPasswordModal) {
    forgotPasswordLink.addEventListener("click", (event) => {
      event.preventDefault();
      forgotPasswordModal.style.display = "block";
    });
  }

  // Close the forgot password modal when the close button is clicked
  if (closeForgotModal && forgotPasswordModal) {
    closeForgotModal.addEventListener("click", () => {
      forgotPasswordModal.style.display = "none";
    });
  }

  // Close the modal when clicking outside the modal content
  window.addEventListener("click", (event) => {
    if (event.target === forgotPasswordModal) {
      forgotPasswordModal.style.display = "none";
    }
  });

  // Handle forgot password form submission
  if (forgotPasswordForm) {
    forgotPasswordForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      
      const email = document.getElementById("resetEmail").value.trim();
      forgotPasswordMessage.textContent = "";
      forgotPasswordMessage.className = "";
      
      try {
        // Add CSRF token to form
        await csrfUtils.addTokenToForm(forgotPasswordForm);
        
        // Get CSRF token and add to fetch options
        const fetchOptions = await csrfUtils.addTokenToFetchOptions({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        });

        const response = await fetch("/api/auth/forgot-password", fetchOptions);
        const result = await response.json();

        if (response.ok && result.success) {
          forgotPasswordMessage.textContent = "Password reset link has been sent to your email.";
          forgotPasswordMessage.className = "success";
          
          // Clear the form
          document.getElementById("resetEmail").value = "";
          
          // Close the modal after 3 seconds
          setTimeout(() => {
            forgotPasswordModal.style.display = "none";
          }, 3000);
        } else {
          forgotPasswordMessage.textContent = result.message || "Failed to send reset link. Please try again.";
          forgotPasswordMessage.className = "error";
        }
      } catch (error) {
        console.error("Error:", error);
        forgotPasswordMessage.textContent = "An error occurred. Please try again.";
        forgotPasswordMessage.className = "error";
      }
    });
  }

  console.log("Login.js fully loaded!");
});
