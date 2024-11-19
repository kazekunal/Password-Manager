// Initialize the password store
let passwordStore = {};

// Function to encrypt and store the password
function storePassword(website, username, password) {
  const encryptedPassword = encryptPassword(password);
  passwordStore[website] = { username, encryptedPassword };
  chrome.storage.sync.set({ passwordStore }, () => {
    console.log("Password stored successfully!");
  });
}

// Function to encrypt the password using a secret passkey
function encryptPassword(password) {
  const secretPasskey = getSecretPasskey();
  // Implement encryption logic using the secretPasskey
  // (e.g., using SHA-256 hashing)
  return encryptedPassword;
}

// Function to retrieve the secret passkey
function getSecretPasskey() {
  // Implement logic to retrieve the secret passkey
  // (e.g., stored in Chrome storage or user input)
  return "your_secret_passkey";
}

// Listen for form submissions and store the password
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    chrome.tabs.executeScript(
      tabId,
      {
        code: `
          document.querySelectorAll('input[type="password"]').forEach((input) => {
            input.addEventListener('focusout', () => {
              const website = window.location.hostname;
              const username = document.querySelector('input[type="text"], input[type="email"]').value;
              const password = input.value;
              chrome.runtime.sendMessage({ website, username, password });
            });
          });
        `
      },
      () => {
        if (chrome.runtime.lastError) {
          console.error(chrome.runtime.lastError.message);
        }
      }
    );
  }
});

// Handle password storage request from the content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const { website, username, password } = request;
  storePassword(website, username, password);
  sendResponse({ status: "success" });
});

// // background.js
// chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
//     if (message.type === 'CAPTURE_CREDENTIALS') {
//         // Create a notification for password capture
//         chrome.notifications.create({
//             type: 'basic',
//             iconUrl: 'path/to/icon.png', // Replace with your extension icon
//             title: 'Save Login Credentials?',
//             message: `Do you want to save login for ${message.website}?`,
//             buttons: [
//                 { title: 'Save' },
//                 { title: 'Cancel' }
//             ]
//         });

//         // Store temporary credentials
//         chrome.storage.session.set({
//             capturedCredentials: {
//                 website: message.website,
//                 username: message.username,
//                 password: message.password
//             }
//         });
//     }
// });

// // Handle notification button clicks
// chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
//     if (buttonIndex === 0) { // Save button
//         // Retrieve captured credentials
//         const { capturedCredentials } = await chrome.storage.session.get('capturedCredentials');
        
//         if (capturedCredentials) {
//             // Open popup to confirm and save
//             chrome.runtime.sendMessage({
//                 type: 'OPEN_SAVE_CREDENTIALS_POPUP',
//                 website: capturedCredentials.website,
//                 username: capturedCredentials.username,
//                 password: capturedCredentials.password
//             });
//         }
//     }

//     // Clear the notification
//     chrome.notifications.clear(notificationId);
// });