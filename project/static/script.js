// Function to show login popup
function showLoginPopup() {
    document.getElementById('loginPopupBackground').style.display = 'block';
    document.getElementById('loginPopup').style.display = 'block';
}

// Function to hide login popup
function hideLoginPopup() {
    document.getElementById('loginPopupBackground').style.display = 'none';
    document.getElementById('loginPopup').style.display = 'none';
}

// Function to show signup popup
function showSignupPopup() {
    document.getElementById('signupPopupBackground').style.display = 'block';
    document.getElementById('signupPopup').style.display = 'block';
}

// Function to hide signup popup
function hideSignupPopup() {
    document.getElementById('signupPopupBackground').style.display = 'none';
    document.getElementById('signupPopup').style.display = 'none';
}

// Function to show forgot password popup
function showForgotPasswordPopup() {
    document.getElementById('forgotPasswordPopupBackground').style.display = 'block';
    document.getElementById('forgotPasswordPopup').style.display = 'block';
}

// Function to hide forgot password popup
function hideForgotPasswordPopup() {
    document.getElementById('forgotPasswordPopupBackground').style.display = 'none';
    document.getElementById('forgotPasswordPopup').style.display = 'none';
}

// Function to validate reset password form

function validateResetPasswordForm() {
    var newPassword = document.getElementById('newPassword').value;
    var confirmNewPassword = document.getElementById('confirmNewPassword').value;
    // var newPasswordRegEx = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%?&])[A-Za-z\d@$!%?&]{8,}$/;

    if (newPassword !== confirmNewPassword) {
        alert("Passwords do not match!");
        return false;
    } 
    // else if (!newPassword.match(newPasswordRegEx)) {
    //     document.getElementById('resetPasswordError').style.display = 'none';
    //     document.getElementById('resetPasswordRequirements').style.display = 'block';
    //     return false;
    // } 
    else {
        document.getElementById('resetPasswordError').style.display = 'none';
        // document.getElementById('resetPasswordRequirements').style.display = 'none';
        return true;
    }
}

// Function to show dropdown content
function showDropdown(id) {
    document.getElementById(id).style.display = 'block';
}

// Function to hide dropdown content
function hideDropdown(id) {
    document.getElementById(id).style.display = 'none';
}

// Function to validate form
function validateForm() {
    var password = document.getElementById('signupPassword').value;
    var confirmPassword = document.getElementById('confirmPassword').value;
    // var passwordRegex = /^(?=.[a-z])(?=.[A-Z])(?=.\d)(?=.[@$!%?&])[A-Za-z\d@$!%?&]{8,}$/;

    if (password !== confirmPassword) {
        document.getElementById('passwordMatchError').style.display = 'block';
        // document.getElementById('passwordRequirements').style.display = 'none';
        return false;
    }
        //  else if (!password.match(passwordRegex)) {
    //     document.getElementById('passwordMatchError').style.display = 'none';
    //     document.getElementById('passwordRequirements').style.display = 'block';
    //     return false;
    // }
     else {
        document.getElementById('passwordMatchError').style.display = 'none';
        // document.getElementById('passwordRequirements').style.display = 'none';
        return true;
    }
}

// Function to show login popup automatically after signup
function showLoginAfterSignup() {
    document.getElementById('loginPopupBackground').style.display = 'block';
    document.getElementById('loginPopup').style.display = 'block';
}

// Function to handle signup form submission
function handleSignupFormSubmission() {
    var isValid = validateForm(); // Validate the signup form
    if (isValid) {
        // If form is valid, show login popup after successful signup
        showLoginAfterSignup();
    }
    return isValid; // Return the result of form validation
}
