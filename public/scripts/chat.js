document.addEventListener("DOMContentLoaded", () => {
  // DOM elements
  const messageBox = document.getElementById("messages");
  const messageInput = document.getElementById("messageInput");
  const sendButton = document.getElementById("sendButton");
  const userList = document.getElementById("users");

  // Determine the current user
  let currentUser;

  // Check if the user is logged in
  if (
    localStorage.getItem("isLoggedIn") === "true" &&
    localStorage.getItem("username")
  ) {
    // Logged-in user
    currentUser = localStorage.getItem("username");
  } else {
    // Anonymous user: generate a new random username
    currentUser = `Anon_${Math.floor(1000 + Math.random() * 9000)}`;
    localStorage.setItem("username", currentUser);
    localStorage.setItem("isLoggedIn", "false");
  }

  // Add the current user to the user list
  const addUserToList = (user) => {
    const li = document.createElement("li");
    li.textContent = user;
    userList.appendChild(li);
  };

  userList.innerHTML = ""; // Clear the user list
  addUserToList(currentUser); // Add the current user to the list

  // Fetch active users from the server
  userList.innerHTML = "<li>Loading users...</li>";
  fetch("/chat", {
    headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
  })
    .then((response) => response.json())
    .then((data) => {
      userList.innerHTML = ""; // Clear the loading message
      if (data.success) {
        data.users.forEach((user) => addUserToList(user.username));
      } else {
        console.error("Error fetching users:", data.message);
        userList.innerHTML = "<li>Error loading users</li>";
      }
    })
    .catch((err) => {
      console.error("Fetch error:", err);
      userList.innerHTML = "<li>Error loading users.</li>";
    });

  // Add a message to the chat box
  const addMessage = (message, type = "sent") => {
    const msgDiv = document.createElement("div");
    msgDiv.className = `message ${type}`;
    msgDiv.textContent = message;
    messageBox.appendChild(msgDiv);
    messageBox.scrollTop = messageBox.scrollHeight; // Auto-scroll
  };

  // Enable/Disable Send Button based on input value
  messageInput.addEventListener("input", () => {
    sendButton.disabled = !messageInput.value.trim();
  });

  // Send button click handler
  sendButton.addEventListener("click", () => {
    const message = messageInput.value.trim();
    if (message) {
      addMessage(`${currentUser}: ${message}`, "sent");
      messageInput.value = ""; // Clear input

      // Simulate a server response (remove this for production)
      setTimeout(
        () => addMessage("Server: Message received!", "received"),
        1000
      );
    }
  });

  // Enter key triggers the send button
  messageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      sendButton.click();
    }
  });
});

// Logout functionality
const logoutButton = document.getElementById("logoutButton");
if (logoutButton) {
  logoutButton.addEventListener("click", () => {
    localStorage.clear(); // Clear all stored data
    window.location.href = "index.html"; // Redirect to the homepage
  });
}
