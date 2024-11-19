// popup.js
document.addEventListener("DOMContentLoaded", () => {
    const unlockScreen = document.getElementById("unlockScreen");
    const passwordScreen = document.getElementById("passwordScreen");
    const passkeyInput = document.getElementById("passkey");
    const unlockButton = document.getElementById("unlock");
    const passwordList = document.getElementById("passwordList");
    
    // Add Password Modal Elements
    const addPasswordBtn = document.getElementById("addPasswordBtn");
    const addPasswordModal = document.getElementById("addPasswordModal");
    const closeModalBtn = document.querySelector(".modal-close");
    const websiteInput = document.getElementById("websiteInput");
    const usernameInput = document.getElementById("usernameInput");
    const passwordInput = document.getElementById("passwordInput");
    const savePasswordBtn = document.getElementById("savePasswordBtn");
  
    // Check if a passkey is already set
    chrome.storage.sync.get("isPasskeySet", (data) => {
      if (!data.isPasskeySet) {
        // First-time setup
        setupFirstTimePasskey();
      }
    });
  
    // Unlock functionality
    unlockButton.addEventListener("click", async () => {
      const passkey = passkeyInput.value;
      
      try {
        // Verify the passkey
        const isValid = await verifyPasskey(passkey);
        
        if (isValid) {
          // Store current passkey in session
          sessionStorage.setItem('currentPasskey', passkey);
          
          // Load and display passwords
          await loadPasswords(passkey);
          
          // Switch screens
          unlockScreen.style.display = "none";
          passwordScreen.style.display = "block";
        } else {
          showToast("Invalid passkey. Please try again.", "error");
        }
      } catch (error) {
        console.error("Error unlocking:", error);
        showToast("An error occurred while unlocking.", "error");
      }
    });
  
    // Add Password Modal Functionality
    addPasswordBtn.addEventListener("click", () => {
      addPasswordModal.style.display = "block";
    });
  
    closeModalBtn.addEventListener("click", () => {
      addPasswordModal.style.display = "none";
    });
  
    // Save Password
    savePasswordBtn.addEventListener("click", async () => {
      const website = websiteInput.value.trim();
      const username = usernameInput.value.trim();
      const password = passwordInput.value;
  
      if (!website || !username || !password) {
        showToast("Please fill in all fields", "warning");
        return;
      }
  
      try {
        // Retrieve current passkey from session
        const currentPasskey = sessionStorage.getItem('currentPasskey');
        
        if (!currentPasskey) {
          throw new Error("No active session");
        }
  
        // Save the password
        await savePassword(website, username, password, currentPasskey);
  
        // Reload passwords
        await loadPasswords(currentPasskey);
  
        // Clear inputs and close modal
        websiteInput.value = "";
        usernameInput.value = "";
        passwordInput.value = "";
        addPasswordModal.style.display = "none";
        
        showToast("Password saved successfully!", "success");
      } catch (error) {
        console.error("Error saving password:", error);
        showToast("Failed to save password", "error");
      }
    });
  
    // Function to load and display passwords
    async function loadPasswords(passkey) {
      try {
        const passwords = await retrievePasswords(passkey);
        
        // Clear existing list
        passwordList.innerHTML = "";
  
        if (Object.keys(passwords).length === 0) {
          passwordList.innerHTML = `
            <div class="empty-state" style="text-align:center; color:#888; padding:20px;">
              <i class="fas fa-lock-open" style="font-size:48px; color:#3498db; margin-bottom:10px;"></i>
              <p>No passwords saved yet</p>
              <p>Click the '+' button to add your first password</p>
            </div>
          `;
          return;
        }
  
        // Populate password list
        Object.entries(passwords).forEach(([website, { username, password }]) => {
          const passwordItem = document.createElement("div");
          passwordItem.classList.add("password-item");
          
          // Create a unique ID for the password reveal element
          const passwordRevealId = `password-reveal-${website.replace(/[^a-zA-Z0-9]/g, '-')}`;
          
          passwordItem.innerHTML = `
            <div class="password-icon">
              <i class="fas fa-globe"></i>
            </div>
            <div class="password-details">
              <strong>${website}</strong>
              <p>${username}</p>
              <div id="${passwordRevealId}" class="password-reveal" style="display:none;"></div>
            </div>
            <div class="password-actions">
              <button class="action-btn view-btn" data-website="${website}" data-password="${password}">
                <i class="fas fa-eye"></i>
              </button>
              <button class="action-btn delete-btn" data-website="${website}">
                <i class="fas fa-trash"></i>
              </button>
            </div>
          `;
  
          // View Password Functionality
          const viewBtn = passwordItem.querySelector(".view-btn");
          const passwordReveal = passwordItem.querySelector(".password-reveal");
          viewBtn.addEventListener("click", (e) => {
            const website = e.currentTarget.dataset.website;
            const password = e.currentTarget.dataset.password;
            const passwordElement = document.getElementById(`password-reveal-${website.replace(/[^a-zA-Z0-9]/g, '-')}`);
            
            if (passwordElement.style.display === "none") {
              passwordElement.textContent = password;
              passwordElement.style.display = "block";
              viewBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
            } else {
              passwordElement.textContent = "";
              passwordElement.style.display = "none";
              viewBtn.innerHTML = '<i class="fas fa-eye"></i>';
            }
          });
  
          // Delete Password Functionality
          const deleteBtn = passwordItem.querySelector(".delete-btn");
          deleteBtn.addEventListener("click", async (e) => {
            const website = e.currentTarget.dataset.website;
            
            // Confirm deletion
            const confirmDelete = confirm(`Are you sure you want to delete the password for ${website}?`);
            
            if (confirmDelete) {
              try {
                // Delete the password
                await deletePassword(website);
  
                // Retrieve current passkey from session
                const currentPasskey = sessionStorage.getItem('currentPasskey');
                
                // Reload passwords
                await loadPasswords(currentPasskey);
                
                showToast(`Password for ${website} deleted`, "success");
              } catch (error) {
                console.error("Error deleting password:", error);
                showToast("Failed to delete password", "error");
              }
            }
          });
  
          passwordList.appendChild(passwordItem);
        });
      } catch (error) {
        console.error("Error loading passwords:", error);
        passwordList.innerHTML = `
          <div class="error-state" style="text-align:center; color:red; padding:20px;">
            <i class="fas fa-exclamation-triangle" style="font-size:48px; margin-bottom:10px;"></i>
            <p>Error loading passwords</p>
          </div>
        `;
      }
    }
  
    // New function to delete a password
    async function deletePassword(website) {
      return new Promise((resolve, reject) => {
        chrome.storage.sync.get(['passwordStore'], (data) => {
          const passwordStore = data.passwordStore || {};
          
          // Remove the specific website's password
          delete passwordStore[website];
          
          // Save the updated password store
          chrome.storage.sync.set({ passwordStore }, () => {
            if (chrome.runtime.lastError) {
              reject(chrome.runtime.lastError);
            } else {
              resolve();
            }
          });
        });
      });
    }
  
    // Toast Notification Function
    function showToast(message, type = 'info') {
      // Create toast element
      const toast = document.createElement('div');
      toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px;
        background-color: ${
          type === 'success' ? '#2ecc71' : 
          type === 'error' ? '#e74c3c' : 
          type === 'warning' ? '#f39c12' : 
          '#3498db'
        };
        color: white;
        border-radius: 5px;
        z-index: 1000;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        transition: opacity 0.3s;
      `;
      toast.textContent = message;
      
      // Add to body
      document.body.appendChild(toast);
      
      // Remove after 3 seconds
      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => document.body.removeChild(toast), 300);
      }, 3000);
    }
});
  
  // Existing functions for encryption and passkey management
  // Passkey Setup Function
  function setupFirstTimePasskey() {
    // Modify HTML to prompt for initial passkey setup
    document.body.innerHTML = `
      <div class="container">
        <h1>Set Up Passkey</h1>
        <br/>
        <input type="password" id="newPasskey" placeholder="Create a strong passkey" />
        <br/>
        <input type="password" id="confirmPasskey" placeholder="Confirm passkey" />
        <br/>
        <button id="savePasskey" class="btn">Save Passkey</button>
      </div>
    `;
  
    const newPasskeyInput = document.getElementById("newPasskey");
    const confirmPasskeyInput = document.getElementById("confirmPasskey");
    const savePasskeyButton = document.getElementById("savePasskey");
  
    savePasskeyButton.addEventListener("click", async () => {
      const newPasskey = newPasskeyInput.value;
      const confirmPasskey = confirmPasskeyInput.value;
  
      if (newPasskey !== confirmPasskey) {
        alert("Passkeys do not match. Please try again.");
        return;
      }
  
      if (newPasskey.length < 8) {
        alert("Passkey must be at least 8 characters long.");
        return;
      }
  
      try {
        // Generate and store the salt and passkey hash
        await initializePasskey(newPasskey);
        
        // Redirect to main interface
        window.location.reload();
      } catch (error) {
        console.error("Error setting up passkey:", error);
        alert("Failed to set up passkey. Please try again.");
      }
    });
  }
  
  // Derive encryption key from passkey using PBKDF2
  async function deriveKey(passkey, salt) {
    const encoder = new TextEncoder();
    const passkeyBuffer = encoder.encode(passkey);
    const saltBuffer = base64ToBuffer(salt);
  
    const key = await window.crypto.subtle.importKey(
      'raw',
      passkeyBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );
  
    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 100000,
        hash: 'SHA-256'
      },
      key,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }
  
  // Initialize passkey for first-time setup
  async function initializePasskey(passkey) {
    // Generate a random salt
    const salt = bufferToBase64(crypto.getRandomValues(new Uint8Array(16)));
    
    // Create a hash of the passkey for verification
    const hashedPasskey = await hashPasskey(passkey);
  
    // Store salt and hashed passkey
    await chrome.storage.sync.set({
      passkeySalt: salt,
      hashedPasskey: hashedPasskey,
      isPasskeySet: true
    });
  }
  
  // Hash the passkey for verification
  async function hashPasskey(passkey) {
    const encoder = new TextEncoder();
    const data = encoder.encode(passkey);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return bufferToBase64(hash);
  }
  
  // Verify the provided passkey
  async function verifyPasskey(passkey) {
    return new Promise((resolve, reject) => {
      chrome.storage.sync.get(['hashedPasskey'], async (data) => {
        if (!data.hashedPasskey) {
          reject(new Error("No passkey set"));
          return;
        }
  
        const providedHash = await hashPasskey(passkey);
        resolve(providedHash === data.hashedPasskey);
      });
    });
  }
  
  // Encrypt a password
  async function encryptPassword(password, passkey) {
    // Retrieve the salt
    const salt = await new Promise((resolve) => {
      chrome.storage.sync.get(['passkeySalt'], (data) => {
        resolve(data.passkeySalt);
      });
    });
  
    // Derive the encryption key
    const key = await deriveKey(passkey, salt);
  
    // Generate a random IV
    const iv = crypto.getRandomValues(new Uint8Array(12));
  
    // Encrypt the password
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(password);
  
    const encryptedContent = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      dataBuffer
    );
  
    // Combine IV and encrypted content
    const encryptedData = new Uint8Array(iv.length + encryptedContent.byteLength);
    encryptedData.set(iv);
    encryptedData.set(new Uint8Array(encryptedContent), iv.length);
  
    return bufferToBase64(encryptedData);
  }
  
  // Decrypt a password
  async function decryptPassword(encryptedPassword, passkey) {
    // Retrieve the salt
    const salt = await new Promise((resolve) => {
      chrome.storage.sync.get(['passkeySalt'], (data) => {
        resolve(data.passkeySalt);
      });
    });
  
    // Derive the encryption key
    const key = await deriveKey(passkey, salt);
  
    // Convert encrypted password to buffer
    const encryptedBuffer = base64ToBuffer(encryptedPassword);
  
    // Extract IV (first 12 bytes)
    const iv = encryptedBuffer.slice(0, 12);
    const data = encryptedBuffer.slice(12);
  
    // Decrypt
    const decryptedContent = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      data
    );
  
    // Convert decrypted content to text
    const decoder = new TextDecoder();
    return decoder.decode(decryptedContent);
  }
  
  // Save a new password
  async function savePassword(website, username, password, currentPasskey) {
    // Encrypt the password
    const encryptedPassword = await encryptPassword(password, currentPasskey);
  
    // Retrieve existing password store
    const passwordStore = await new Promise((resolve) => {
      chrome.storage.sync.get(['passwordStore'], (data) => {
        resolve(data.passwordStore || {});
      });
    });
  
    // Update password store
    passwordStore[website] = { 
      username, 
      encryptedPassword 
    };
  
    // Save updated password store
    await chrome.storage.sync.set({ passwordStore });
  }
  
  // Retrieve passwords
  async function retrievePasswords(passkey) {
    return new Promise((resolve, reject) => {
      chrome.storage.sync.get(['passwordStore'], async (data) => {
        if (!data.passwordStore) {
          resolve({});
          return;
        }
  
        try {
          const decryptedStore = {};
          for (const [website, { username, encryptedPassword }] of Object.entries(data.passwordStore)) {
            const decryptedPassword = await decryptPassword(encryptedPassword, passkey);
            decryptedStore[website] = { username, password: decryptedPassword };
          }
          resolve(decryptedStore);
        } catch (error) {
          reject(error);
        }
      });
    });
  }
  
  // Utility functions for base64 conversion
  function bufferToBase64(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
  }
  
  function base64ToBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }