// CSRF Token Utility
const csrfUtils = {
  // Get a CSRF token from the server
  getToken: async function() {
    try {
      const response = await fetch('/csrf-token', { 
        credentials: 'include' // Important for cookies
      });
      if (!response.ok) throw new Error('Failed to fetch CSRF token');
      const data = await response.json();
      return data.csrfToken;
    } catch (error) {
      console.error('Error fetching CSRF token:', error);
      return null;
    }
  },

  // Add CSRF token to fetch options
  addTokenToFetchOptions: async function(options = {}) {
    const token = await this.getToken();
    if (!token) return options;

    // Create headers if they don't exist
    if (!options.headers) {
      options.headers = {};
    }
    
    // Add token to headers
    options.headers['CSRF-Token'] = token;
    
    // Make sure credentials are included
    options.credentials = 'include';
    
    return options;
  },

  // Add CSRF token to a form
  addTokenToForm: async function(formElement) {
    const token = await this.getToken();
    if (!token || !formElement) return;

    // Remove any existing CSRF input
    const existingToken = formElement.querySelector('input[name="_csrf"]');
    if (existingToken) existingToken.remove();

    // Create and add hidden input with CSRF token
    const hiddenInput = document.createElement('input');
    hiddenInput.type = 'hidden';
    hiddenInput.name = '_csrf';
    hiddenInput.value = token;
    formElement.appendChild(hiddenInput);
  }
};
