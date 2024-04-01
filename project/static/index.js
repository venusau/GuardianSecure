const features = [
    "Password Strength Testing",
    "Plain text to Cipher text",
    "Vulnerability Matcher tool",
    "AI Chatbot"
];

let featureIndex = 0;
const weWillProvide = document.getElementById('weWillProvide');
const featureText = document.querySelector('.feature-text');

// Display each feature letter by letter with a delay
function displayFeatures() {
    const currentFeature = features[featureIndex];
    const currentFeatureLength = currentFeature.length;

    let letters = '';
    let letterIndex = 0;

    function addNextLetter() {
        if (letterIndex < currentFeatureLength) {
            letters += currentFeature.charAt(letterIndex);
            featureText.textContent = letters;
            letterIndex++;

            setTimeout(addNextLetter, 100); // Delay between each letter
        } else {
            setTimeout(() => {
                featureText.textContent = ''; // Clear the text
                featureIndex++;
                if (featureIndex >= features.length) {
                    featureIndex = 0;
                }
                setTimeout(displayFeatures, 1000); // Delay before showing the next feature
            }, 1000); // Time for each full feature to display (1 second in this case)
        }
    }

    addNextLetter();
}

// Call the function when the page is loaded
window.onload = () => {
    weWillProvide.style.visibility = 'visible';
    displayFeatures();
};

// JavaScript to update color dynamically
function updateColor() {
    const loginNotice = document.getElementById('loginNotice');
    const r = Math.floor(Math.random() * 256);
    const g = Math.floor(Math.random() * 256);
    const b = Math.floor(Math.random() * 256);
    loginNotice.style.color = `rgb(${r}, ${g}, ${b})`;
}

// Update color every 2 seconds
setInterval(updateColor, 2000);

// Initial color update on page load
updateColor();