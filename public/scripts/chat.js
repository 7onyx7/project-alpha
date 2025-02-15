let socket;
let escPressedOnce = false;

document.addEventListener("DOMContentLoaded", () => {
  // DOM elements
  const messageBox = document.getElementById("messages");
  const messageInput = document.getElementById("messageInput");
  const sendButton = document.getElementById("sendButton");
  const userList = document.getElementById("users");

  function generateRandomUsername() {
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
    const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
    const noun = nouns[Math.floor(Math.random() * nouns.length)];
    return `${adj} ${noun}`;
  }
  

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

  socket = io();

  function logoutUser() {
    localStorage.clear();
    sessionStorage.clear();
    alert("Session expired. Please log in again."); // Show a message
    window.location.href = "index.html"; // Redirect to login page
  }

  console.log("Current User:", currentUser);

  // Modify fetch request to handle anonymous users correctly
  const fetchOptions = isLoggedIn
    ? { headers: { Authorization: `Bearer ${localStorage.getItem("token")}` } }
    : {};

      // After generating currentUser in the frontend:
      fetch(`/chat?username=${encodeURIComponent(currentUser)}`, fetchOptions)
      .then((response) => {
        if (!response.ok) { // If response is NOT okay (e.g., 401 Unauthorized)
          throw new Error("Unauthorized");
        }
        return response.json();
      })
      .then((data) => {
        if (data.success && data.username) {
          currentUser = data.username; 
        } else {
          currentUser = sessionStorage.getItem("username") || generateRandomUsername();
        }
        addUserToList(currentUser);
      })
      .catch((err) => {
        console.error("Fetch error:", err);
        if (err.message === "Unauthorized") {
          logoutUser(); // Call logout function if unauthorized
        }
      });

  socket.emit("userJoined", currentUser);

  socket.on("userJoined", (data) => {
    console.log(`You joined ${data.room} with ${data.username}`);
});

  socket.on("roomReady", (data) => {
    console.log(`Chat room ${data.room} is now full!`);
});

  socket.on("updateUserList", (users) => {
        
    const userList = document.getElementById("users");
    userList.innerHTML = "";  // Clear current list
  
    users.forEach((user) => {
      const li = document.createElement("li");
      li.textContent = user;
      userList.appendChild(li);
    });

    console.log("👥 Users in the chat:", users);

  });
  
  let escListenerAdded = false;

  socket.on("chatMessage", (data) => {
    if (data.username === currentUser) return;
    addMessage(`${data.username}: ${data.message}`, "received");
  });

  socket.on("chatEnded", (data) => {
    console.log("📢 Received chatEnded event:", data);
    
    if (!data || !data.username) {
      console.error("❌ chatEnded event received but data is missing!");
      return;
    }  
    alert(`${data.username} has ended the chat. The session will now restart.`);

    setTimeout(() => {
      location.reload();
    }, 5000);
    
  });

// Ensure the leaving user does NOT see the alert
socket.on("selfDisconnect", () => {
    console.log("You have ended the chat.");
});



  // Enable/Disable Send Button based on input value
  messageInput.addEventListener("input", () => {
    sendButton.disabled = !messageInput.value.trim();
  });

  // Send button click handler
  sendButton.addEventListener("click", () => {
    const message = messageInput.value.trim();
    if (message && currentUser) {
      addMessage(`${currentUser}: ${message}`, "sent");
      socket.emit("chatMessage", { username: currentUser, message });
      messageInput.value = ""; // Clear input
    }
  });

  // Enter key triggers the send button
  messageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      sendButton.click();
    }
  });

  // Logout functionality
const logoutButton = document.getElementById("logoutButton");
if (logoutButton) {
  logoutButton.addEventListener("click", () => {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    localStorage.removeItem("isLoggedIn");
    localStorage.clear(); // Clear all stored data
    sessionStorage.clear(); // Clear session data
    window.location.href = "index.html"; // Redirect to the homepage
  });
}

let escPressedOnce = false;

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    if (!escPressedOnce) {
      // First ESC press: Show confirmation prompt
      escPressedOnce = true;
      alert("Press ESC again to confirm ending the chat.");
      
      // Reset the flag if no second ESC press happens within 3 seconds
      setTimeout(() => {
        escPressedOnce = false;
      }, 3000); 
    } else {
      // Second ESC press: End the chat
      endChat();
    }
  }
});

function endChat() {
  socket.emit("userDisconnected", currentUser);
  alert("Chat ended.");
  window.location.href = "index.html"; // Or disable UI elements if needed
}

});

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