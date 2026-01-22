// Security and Validation Functions
let attemptCount = 0;
let isLocked = false;
let lockTimer = null;
let inactivityTimer = null;
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 30; // seconds

// Sanitize input to prevent XSS
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// Validate email format
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Check password strength
function checkPasswordStrength(password) {
    let strength = 0;
    const strengthBar = document.getElementById('strengthBar');
    const strengthText = document.getElementById('strengthText');
    
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    
    strengthBar.className = 'strength-bar';
    
    if (password.length === 0) {
        strengthBar.style.width = '0%';
        strengthText.textContent = 'Password strength';
        strengthText.style.color = '#666';
        return 0;
    } else if (strength <= 2) {
        strengthBar.style.width = '33%';
        strengthBar.style.backgroundColor = '#f44336';
        strengthText.textContent = 'Weak';
        strengthText.style.color = '#f44336';
        return 1;
    } else if (strength <= 3) {
        strengthBar.style.width = '66%';
        strengthBar.style.backgroundColor = '#ff9800';
        strengthText.textContent = 'Medium';
        strengthText.style.color = '#ff9800';
        return 2;
    } else {
        strengthBar.style.width = '100%';
        strengthBar.style.backgroundColor = '#4caf50';
        strengthText.textContent = 'Strong';
        strengthText.style.color = '#4caf50';
        return 3;
    }
}

// Validate form and enable/disable login button
function validateForm() {
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const loginButton = document.getElementById('loginButton');
    const emailError = document.getElementById('emailError');
    const passwordError = document.getElementById('passwordError');
    
    let isValid = true;
    
    // Validate email
    if (!email) {
        emailError.textContent = '';
        isValid = false;
    } else if (!validateEmail(email)) {
        emailError.textContent = 'Please enter a valid email address';
        isValid = false;
    } else {
        emailError.textContent = '';
    }
    
    // Validate password
    if (password.length < 8) {
        passwordError.textContent = 'Password must be at least 8 characters';
        isValid = false;
    } else {
        passwordError.textContent = '';
    }
    
    // Enable/disable button
    if (isValid && !isLocked) {
        loginButton.disabled = false;
    } else {
        loginButton.disabled = true;
    }
    
    return isValid;
}

// Password toggle visibility
function initPasswordToggle() {
    const toggle = document.getElementById('passwordToggle');
    const passwordInput = document.getElementById('password');
    const eyeIcon = toggle.querySelector('.eye-icon');
    const eyeOffIcon = toggle.querySelector('.eye-off-icon');
    
    toggle.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        
        if (type === 'text') {
            eyeIcon.style.display = 'none';
            eyeOffIcon.style.display = 'block';
        } else {
            eyeIcon.style.display = 'block';
            eyeOffIcon.style.display = 'none';
        }
    });
}

// Attempt limiter
function handleLoginAttempt() {
    if (isLocked) {
        return false;
    }
    
    attemptCount++;
    
    if (attemptCount >= MAX_ATTEMPTS) {
        lockLogin();
        return false;
    }
    
    return true;
}

function lockLogin() {
    isLocked = true;
    const loginButton = document.getElementById('loginButton');
    const attemptWarning = document.getElementById('attemptWarning');
    const waitTimeSpan = document.getElementById('waitTime');
    const countdownSpan = document.getElementById('countdown');
    
    loginButton.disabled = true;
    attemptWarning.style.display = 'block';
    
    let timeLeft = LOCKOUT_TIME;
    
    lockTimer = setInterval(() => {
        timeLeft--;
        waitTimeSpan.textContent = timeLeft;
        countdownSpan.textContent = ` (${timeLeft}s)`;
        countdownSpan.style.display = 'inline';
        
        if (timeLeft <= 0) {
            clearInterval(lockTimer);
            isLocked = false;
            attemptCount = 0;
            loginButton.disabled = false;
            attemptWarning.style.display = 'none';
            countdownSpan.style.display = 'none';
        }
    }, 1000);
}

// OTP Input Handling
function initOTPInputs() {
    const otpInputs = document.querySelectorAll('.otp-input');
    const otpCodeInput = document.getElementById('otpCode');
    
    otpInputs.forEach((input, index) => {
        input.addEventListener('input', (e) => {
            const value = e.target.value.replace(/[^0-9]/g, '');
            e.target.value = value;
            
            if (value && index < otpInputs.length - 1) {
                otpInputs[index + 1].focus();
            }
            
            updateOTPCode();
        });
        
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !e.target.value && index > 0) {
                otpInputs[index - 1].focus();
            }
        });
        
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const paste = e.clipboardData.getData('text').replace(/[^0-9]/g, '').slice(0, 6);
            paste.split('').forEach((char, i) => {
                if (otpInputs[index + i]) {
                    otpInputs[index + i].value = char;
                }
            });
            updateOTPCode();
            otpInputs[Math.min(index + paste.length - 1, otpInputs.length - 1)].focus();
        });
    });
    
    function updateOTPCode() {
        const code = Array.from(otpInputs).map(input => input.value).join('');
        otpCodeInput.value = code;
    }
}

// Transition to OTP screen
function showOTPScreen() {
    const loginForm = document.getElementById('loginForm');
    const otpScreen = document.getElementById('otpScreen');
    
    loginForm.style.display = 'none';
    otpScreen.style.display = 'block';
    
    // Focus first OTP input
    setTimeout(() => {
        document.querySelector('.otp-input').focus();
    }, 300);
}

function showLoginForm() {
    const loginForm = document.getElementById('loginForm');
    const otpScreen = document.getElementById('otpScreen');
    
    otpScreen.style.display = 'none';
    loginForm.style.display = 'block';
}

// Inactivity timer
function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(() => {
        // Clear session data
        sessionStorage.clear();
        localStorage.removeItem('rememberMe');
        alert('Session expired due to inactivity. Please login again.');
        window.location.href = '/';
    }, 30 * 60 * 1000); // 30 minutes
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const loginForm = document.getElementById('loginFormElement');
    const backButton = document.getElementById('backToLogin');
    const loginFormContainer = document.getElementById('loginForm');
    const otpScreen = document.getElementById('otpScreen');
    
    // Check if OTP screen should be shown on load
    if (otpScreen && otpScreen.style.display !== 'none' && window.getComputedStyle(otpScreen).display !== 'none') {
        // OTP screen is visible, focus first input
        setTimeout(() => {
            const firstOtpInput = document.querySelector('.otp-input');
            if (firstOtpInput) firstOtpInput.focus();
        }, 100);
    }
    
    // Initialize password toggle
    initPasswordToggle();
    
    // Initialize OTP inputs
    initOTPInputs();
    
    // Handle OTP form submission
    const otpForm = document.getElementById('otpForm');
    if (otpForm) {
        otpForm.addEventListener('submit', (e) => {
            const otpCode = document.getElementById('otpCode').value;
            if (otpCode.length !== 6) {
                e.preventDefault();
                alert('Please enter all 6 digits');
                return false;
            }
        });
    }
    
    // Real-time validation
    emailInput.addEventListener('input', (e) => {
        e.target.value = sanitizeInput(e.target.value);
        validateForm();
    });
    
    passwordInput.addEventListener('input', (e) => {
        e.target.value = sanitizeInput(e.target.value);
        checkPasswordStrength(e.target.value);
        validateForm();
    });
    
    // Form submission
    if (loginForm) {
        loginForm.addEventListener('submit', (e) => {
            if (!handleLoginAttempt()) {
                e.preventDefault();
                return false;
            }
            
            if (!validateForm()) {
                e.preventDefault();
                return false;
            }
            
            // Allow form to submit normally - backend will redirect to OTP
            // The backend handles the OTP generation and redirect
        });
    }
    
    // Back to login
    if (backButton) {
        backButton.addEventListener('click', () => {
            // Clear pending OTP session and redirect
            window.location.href = '/';
        });
    }
    
    // Reset inactivity timer on user activity
    ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
        document.addEventListener(event, resetInactivityTimer, { passive: true });
    });
    
    resetInactivityTimer();
    
    // Check Remember Me on load
    const rememberMe = localStorage.getItem('rememberMe');
    if (rememberMe) {
        document.getElementById('rememberMe').checked = true;
        const savedEmail = localStorage.getItem('savedEmail');
        if (savedEmail) {
            emailInput.value = savedEmail;
            validateForm();
        }
    }
    
    // Handle Remember Me checkbox
    document.getElementById('rememberMe').addEventListener('change', (e) => {
        if (e.target.checked) {
            localStorage.setItem('rememberMe', 'true');
            localStorage.setItem('savedEmail', emailInput.value);
        } else {
            localStorage.removeItem('rememberMe');
            localStorage.removeItem('savedEmail');
        }
    });
});

