let socket;
let escPressedOnce = false;
let isAdmin = false; // Track admin status

document.addEventListener("DOMContentLoaded", () => {
  // Initialize socket connection
  socket = io();
  
  // Handle reconnection
  socket.on('connect', function() {
    const urlParams = new URLSearchParams(window.location.search);
    const room = urlParams.get("room");
    const currentUser = sessionStorage.getItem("username");
    
    // If we already have a username and room, we might be reconnecting
    if (currentUser && room) {
      socket.emit("userReconnected", { username: currentUser, room });
    }
  });
  // DOM elements
  const messageBox = document.getElementById("messages");
  const messageInput = document.getElementById("messageInput");
  const sendButton = document.getElementById("sendButton");
  const userList = document.getElementById("users");
  const adminPanelButton = document.getElementById("adminPanelButton");

  // Check admin status when page loads
  checkAdminStatus();

  // Admin panel button click handler
  if (adminPanelButton) {
    adminPanelButton.addEventListener('click', async () => {
      try {
        // Check if we have admin token
        const hasAdminToken = document.cookie.includes('adminToken=');
        
        if (hasAdminToken) {
          // Try to access admin panel directly
          window.open('/admin/moderation', '_blank');
        } else {
          // Check if current user is admin and redirect to admin login
          const isUserAdmin = await checkIfUserIsAdmin();
          if (isUserAdmin) {
            // User is admin but needs to login through admin panel
            alert('Please login through the admin panel to access moderation features.');
            window.open('/admin/login', '_blank');
          } else {
            alert('Access denied. You are not an administrator.');
          }
        }
      } catch (error) {
        console.error('Error accessing admin panel:', error);
        alert('Error accessing admin panel. Please try again.');
      }
    });
  }

  async function checkIfUserIsAdmin() {
    try {
      const token = localStorage.getItem('token');
      if (!token) return false;
      
      const response = await fetch('/api/admin-status', {
        headers: { 'Authorization': `Bearer ${token}` },
        credentials: 'include'
      });
      const data = await response.json();
      return data.isAdmin || false;
    } catch (error) {
      console.error('Error checking admin status:', error);
      return false;
    }
  }

  function generateRandomUsername() {
    const adjectives = [
      "Adventurous", "Bold", "Brave", "Calm", "Clever", "Daring",
      "Determined", "Eager", "Fearless", "Gentle", 
      "Happy", "Horrific", "Jolly", "Kind", "Loyal", 
      "Mischievous", "Mysterious", "Noble", "Spooky", 
      "Strong", "Wise", "Witty", "Zealous"
    ];
    const nouns = [
      "Bear", "Cat", "Dog", "Elephant", "Eagle", 
      "Fox", "Giraffe", "Wolf", "Panda", "Tiger",
      "Lion", "Penguin", "Rabbit", "Lynx", "Bobcat",
      "Wizard", "Witch", "Vampire", "Zombie", "Ghost",
      "Knight", "Ninja", "Pirate", "Samurai", "Viking",
      "Dragon", "Hydra", "Phoenix", "Unicorn", "Yeti"
    ];
    const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
    const noun = nouns[Math.floor(Math.random() * nouns.length)];
    return `${adj} ${noun}`;
  }

  function generateRandomRoomName() {
    const timestamp = Date.now();
    const randomValue = Math.floor(Math.random() * 10000);
    return `${timestamp}-${randomValue}`;
  }
  

  let currentUser;
  let isLoggedIn = localStorage.getItem("isLoggedIn") === "true";
  let storedUsername = localStorage.getItem("username"); 
  
  const urlParams = new URLSearchParams(window.location.search);
  let room = urlParams.get("room");

  // If no room specified in URL, create a new room and redirect
  if (!room) {
    room = generateRandomRoomName();
    window.location.href = `chat.html?room=${room}`;
    return;
  }

  const roomNameElem = document.getElementById("room-name");
  if (roomNameElem) {
    roomNameElem.textContent = `Room: ${room}`;
  }

  loadMessageHistory(room);

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

      

  // Clear the user list securely
  userList.innerHTML = ""; // This is safe here as we're clearing 

  // Add user to list
  const addUserToList = (user) => {
    const li = document.createElement("li");
    li.textContent = user;
    userList.appendChild(li);
  };

  // Send messages to chat!
  const addMessage = (message, type = "sent", username = null, timestamp = null) => {
    const msgDiv = document.createElement("div");
    msgDiv.className = `message ${type}`;
    
    console.log("Adding message:", { message, type, username, timestamp }); // Debug log
    
    if (type === "received" && username) {
      // Create message with report button
      const messageContent = document.createElement("div");
      messageContent.className = "message-content";
      messageContent.textContent = message; // Just use the message directly
      
      const messageHeader = document.createElement("div");
      messageHeader.className = "message-header";
      
      // Create username span securely
      const usernameSpan = document.createElement("span");
      usernameSpan.className = "username";
      usernameSpan.textContent = username; // Safe text content
      
      // Create report button securely
      const reportBtn = document.createElement("button");
      reportBtn.className = "report-btn";
      reportBtn.textContent = "⚠️";
      reportBtn.onclick = () => reportUser(username, message);
      
      messageHeader.appendChild(usernameSpan);
      messageHeader.appendChild(reportBtn);
      
      msgDiv.appendChild(messageHeader);
      msgDiv.appendChild(messageContent);
    } else if (type === "system") {
      // System messages
      msgDiv.textContent = message;
      msgDiv.classList.add("system-message");
    } else {
      // Sent messages
      msgDiv.textContent = `${currentUser}: ${message}`;
    }
    
    if (timestamp) {
      msgDiv.title = new Date(timestamp).toLocaleString();
    }
    
    messageBox.appendChild(msgDiv);
    messageBox.scrollTop = messageBox.scrollHeight;
  };

  async function loadMessageHistory(room) {
    try {
      const fetchOptions = await csrfUtils.addTokenToFetchOptions();
      const response = await fetch(`/messages/${encodeURIComponent(room)}`, fetchOptions);
      const data = await response.json();
      if (data.success && Array.isArray(data.messages)) {
        data.messages.forEach(msg => {
          console.log("History message:", msg); // Debug log
          // Pass username separately to properly format the message
          addMessage(msg.message, "received", msg.username, msg.timestamp);
        });
      }
    } catch (err) {
      console.error("Error fetching message history:", err);
    }
  }

  function logoutUser() {
    localStorage.clear();
    sessionStorage.clear();
    alert("Session expired. Please log in again."); // Show a message
    window.location.href = "index.html"; // Redirect to login page
  }

  console.log("Current User:", currentUser);

  // Modify fetch request to handle anonymous users correctly
  const fetchOptions = isLoggedIn
    ? { 
        headers: { Authorization: `Bearer ${localStorage.getItem("token")}` },
        credentials: 'include'
      }
    : { credentials: 'include' };

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

  socket.emit("userJoined", { username: currentUser, room });

  socket.on("userJoined", (data) => {
    console.log(`You joined ${data.room} with ${data.username}`);
});

  socket.on("roomReady", (data) => {
    console.log(`Chat room ${data.room} is now full!`);
    addMessage("Chat room is ready! You can now start chatting.", "system");
  });

  socket.on("waitingForPartner", (data) => {
    addMessage(data.message, "system"); // "system" can be styled differently in your CSS
  });

  socket.on("updateUserList", (users) => {
        
    const userList = document.getElementById("users");
    userList.innerHTML = "";  // Safe clearing operation
  
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
    console.log("Received message:", data); // Debug log
    console.log("Current user:", currentUser); // Debug log
    addMessage(data.message, "received", data.username, data.timestamp);
  });

  // Handle message blocking
  socket.on("messageBlocked", (data) => {
    alert(`Message blocked: ${data.reason}`);
    addMessage(`⚠️ Your message was blocked: ${data.reason}`, "system");
  });

  // Handle errors
  socket.on("error", (data) => {
    alert(`Error: ${data.message}`);
    addMessage(`❌ Error: ${data.message}`, "system");
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
      // Just pass the message without username prefix - the addMessage function will add it
      addMessage(message, "sent");
      socket.emit("chatMessage", { username: currentUser, message, room });
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
    localStorage.clear(); 
    sessionStorage.clear();
    window.location.href = "index.html";
  });
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    if (!escPressedOnce) {
      
      escPressedOnce = true;
      alert("Press ESC again to confirm ending the chat.");
      
      // Reset the flag if no second ESC press happens within 3 seconds
      setTimeout(() => {
        escPressedOnce = false;
      }, 3000); 
    } else {
      // Second ESC press: End the chat
      endChat();
      escPressedOnce = false;
    }
  }
});

function endChat() {
  if (currentUser && socket) {
    socket.emit("userDisconnected");
    sessionStorage.removeItem("username");
    alert("Chat ended.");
    window.location.href = "index.html"; 
  }
}

});


// Only disconnect when the window is actually being closed
// The visibilitychange event helps differentiate between tab switching and closing
let isWindowClosing = false;

window.addEventListener('beforeunload', (event) => {
  isWindowClosing = true;
  // Only perform cleanup on actual window close, not tab switching
  if (socket && isWindowClosing) {
    socket.emit("userDisconnected");
  }
  clearAnonSessionOnExit();
});

// Report user function
function reportUser(username, message) {
  const urlParams = new URLSearchParams(window.location.search);
  const roomParam = urlParams.get("room");
  const reportUrl = `/report.html?username=${encodeURIComponent(username)}&room=${encodeURIComponent(roomParam)}`;
  window.open(reportUrl, 'reportWindow', 'width=600,height=700,scrollbars=yes');
}

// Global report function for external access
window.reportUser = reportUser;

// Reset the flag when just switching tabs
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') {
    // User might be switching tabs or closing the window
    // We'll set a timeout to distinguish between the two
    setTimeout(() => {
      // If we reach this point and the page isn't unloaded, 
      // it was just a tab switch, not a window close
      isWindowClosing = false;
    }, 100);
  } else if (document.visibilityState === 'visible' && socket) {
    // User returned to the tab, ensure we're still connected
    const urlParams = new URLSearchParams(window.location.search);
    const room = urlParams.get("room");
    const currentUser = sessionStorage.getItem("username");
    
    if (currentUser && room) {
      socket.emit("userReconnected", { username: currentUser, room });
    }
  }
});

function clearAnonSessionOnExit() {
  if (localStorage.getItem("isLoggedIn") !== "true") {
    localStorage.removeItem("username");
    localStorage.removeItem("isLoggedIn");
  }
}

// Check admin status function
async function checkAdminStatus() {
  try {
    const token = localStorage.getItem('token');
    const headers = { 'Content-Type': 'application/json' };
    // If token exists, set Authorization header
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
      // Also set cookie for server-side check (if not already set)
      if (!document.cookie.includes('token=')) {
        document.cookie = `token=${token}; path=/`;
      }
    }
    const response = await fetch('/api/admin-status', {
      headers,
      credentials: 'include' // Include cookies
    });
    const data = await response.json();
    isAdmin = data.isAdmin;
    // Show/hide admin panel button
    const adminButton = document.getElementById('adminPanelButton');
    if (adminButton) {
      adminButton.style.display = isAdmin ? 'inline-block' : 'none';
    }
  } catch (error) {
    console.error('Error checking admin status:', error);
  }
}