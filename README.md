# GuardianSecure

**Guardian Secure** is a robust web application focused on enhancing user security and privacy through a suite of cybersecurity tools and features. Built with Flask, it provides secure user authentication, account management, and a range of security tools to safeguard user data.

## Key Features

- **Secure Registration:** Users can securely create accounts with encrypted passwords and personalized security questions, ensuring the confidentiality of their data.
- **Efficient Login:** Streamlined login process with password hashing for enhanced security and protection against unauthorized access.
- **Password Management:** Users can reset their passwords using security questions to verify their identity, maintaining the security of their accounts.
- **Responsive Design:** The application is built with a responsive design, ensuring optimal performance and user experience across various devices.

## Table of Contents

1. [Introduction](#introduction)
2. [Landing Page and Authentication](#landing-page-and-authentication)
3. [User Authentication](#user-authentication)
4. [Password Reset Mechanism](#password-reset-mechanism)
5. [Profile Page](#profile-page)
6. [Cybersecurity Tools](#cybersecurity-tools)
7. [Conclusion](#conclusion)
8. [Future Work](#future-work)

## Introduction

The **Guardian Secure** web application provides users with comprehensive cybersecurity tools and functionalities to enhance their online security posture. This documentation outlines the key features, functionalities, and implementation details of the application following the IEEE format.

## Landing Page and Authentication

- The landing page (`index.html`) is rendered using Flask's `render_template` function.
- A base template (`base.html`) is created to contain common elements shared across multiple pages, ensuring consistency in design and layout.

## User Authentication

- Users are required to sign up and log in to access the functionalities of the web app.
- Authentication is implemented using Flask-Login's `@login_required` decorator to restrict access to authenticated users only.

## Password Reset Mechanism

- Users can reset their passwords by providing their email, new password, security question, and security answer.
- Flask's `@login_required` decorator ensures that only authenticated users can access the password reset functionality.

## Profile Page

- Upon successful login, users are redirected to `profile.html`, where they can access all the tools provided by the web app.
- Access to the profile page is restricted to logged-in users using Flask's `@login_required` decorator.

## Cybersecurity Tools

- **Password Strength Checker:** Allows users to assess the strength of their passwords.
- **Plain Text to Cipher (SHA256 and MD5):** Converts plain text input into cipher text using SHA256 and MD5 encryption algorithms.
- **Vulnerability Matcher Tool:** Users can input their web app's URL to identify OWASP's top 10 vulnerabilities using spidering process with options for active and passive scans.
- **AI Chatbot:** Users can interact with an AI chatbot to get responses to cybersecurity-related queries.

## Conclusion

The **Guardian Secure** web application provides users with a comprehensive suite of cybersecurity tools, enhancing their online security posture. The implementation of Flask and Flask-Login ensures secure authentication and access control, while the range of tools empowers users to protect their digital assets effectively.

## Future Work

- Further enhancements and optimizations to existing functionalities.
- Integration of additional cybersecurity tools and features.
- Continuous testing, feedback gathering, and refinement to ensure robustness and usability of the web application.
