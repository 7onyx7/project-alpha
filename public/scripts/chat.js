document.addEventListener("DOMContentLoaded", () => {
  // DOM elements
  const messageBox = document.getElementById("messages");
  const messageInput = document.getElementById("messageInput");
  const sendButton = document.getElementById("sendButton");
  const userList = document.getElementById("users");

  const adjectives = [
    "Adventurous", "Bold", "Brave", "Calm", "Clever", "Daring",
    "Determined", "Eager", "Fearless", "Gentle", 
    "Happy", "Horrific", "Jolly", "Kind", "Loyal", 
    "Mischievous", "Mysterious", "Noble", "Spooky", 
    "Strong", "Wise", "Witty"
  ];

  const nouns = [
    "Bear", "Cat", "Dog", "Elephant", "Eagle", 
    "Fox", "Giraffe", "Wolf", "Panda", "Tiger",
    "Lion", "Penguin", "Rabbit", "Lynx", "Bobcat"
  ];

  const generateRandomUsername = () => {
    const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
    const noun = nouns[Math.floor(Math.random() * nouns.length)];
    return `${adj} ${noun}`;
  };

  // Determine the current user
  let currentUser;
  let isLoggedIn = localStorage.getItem("isLoggedIn") === "true";
  let storedUsername = localStorage.getItem("username");

  if (isLoggedIn && storedUsername) {
    // Logged-in user
    currentUser = storedUsername;
  }
  else {
    // Generate a unique username for anonymous users only once per session
    let sessionUsername = sessionStorage.getItem("username");

    if (!sessionUsername) {
      sessionUsername = generateRandomUsername();
      sessionStorage.setItem("username", sessionUsername);
    }
    currentUser = sessionUsername;
  }

   // Clear previous login data when a user joins as anonymous
  if (!localStorage.getItem("isLoggedIn") || localStorage.getItem("isLoggedIn") === "false") {
    localStorage.clear(); // This prevents old user data from persisting
    localStorage.setItem("isLoggedIn", "false");
  }

  

  console.log("Current User:", currentUser);

  // Modify fetch request to handle anonymous users correctly
  const fetchOptions = isLoggedIn
    ? { headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } }
    : {};

      // After generating currentUser in the frontend:
  fetch(`/chat?username=${encodeURIComponent(currentUser)}`, fetchOptions)
  .then((response) => response.json())
  .then((data) => {
   if (data.success && data.username) {
    currentUser = data.username; // This should be the properly decoded version
   } else {
    currentUser = sessionStorage.getItem("username") || generateRandomUsername();
   }
   addUserToList(currentUser);
 })
 .catch((err) => console.error("Fetch error:", err));


  // Clear the user list
  userList.innerHTML = ""; 

  // Add user to list
  const addUserToList = (user) => {
    const li = document.createElement("li");
    li.textContent = user;
    userList.appendChild(li);
  };

  // Send messages to chat!
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
    if (message && currentUser) {
      addMessage(`${currentUser}: ${message}`, "sent");
      messageInput.value = ""; // Clear input

      // Simulate a server response (remove this for production)
      setTimeout(
        () => addMessage("Server: Hey there! Message received!", "received"),
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
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    localStorage.removeItem("isLoggedIn");
    localStorage.clear(); // Clear all stored data
    window.location.href = "index.html"; // Redirect to the homepage
  });
}

const socket = io();

// Notify server when user disconnects
window.addEventListener("beforeunload", () => {
  socket.emit("userDisconnected", localStorage.getItem("username"));
});


function clearAnonSessionOnExit() {
  if (localStorage.getItem("isLoggedIn") !== "true") {
    localStorage.removeItem("username"); // Remove only for anonymous users
    localStorage.removeItem("isLoggedIn");
  }
}

// Handle when the user **closes the tab or browser**
window.addEventListener("beforeunload", (event) => {
  clearAnonSessionOnExit();
});