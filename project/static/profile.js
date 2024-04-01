// Assume userName is populated with the user's name
var userName = "shreema Rendi"; // You would get this from your system or database

// Function to show welcome message with the user's name
function showWelcomeMessage() {
    var welcomeMessageDiv = document.getElementById('welcomeMessage');
    welcomeMessageDiv.innerHTML = "Welcome, " + userName + "!";
}

// Call the function to display the welcome message
showWelcomeMessage();