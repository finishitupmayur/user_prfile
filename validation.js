function validateRegisterForm() {
    const name = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();
    const confirmPassword = document.getElementById("confirm_password").value.trim();

    if (!name || !email || !password || !confirmPassword) {
        alert("❗ Please fill in all fields.");
        return false;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        alert("❗ Invalid email format.");
        return false;
    }

    if (password !== confirmPassword) {
        alert("❗ Passwords do not match.");
        return false;
    }

    return true;
}
function validateLoginForm() {
    const email = document.getElementById("login_email").value.trim();
    const password = document.getElementById("login_password").value.trim();

    if (!email || !password) {
        alert("❗ Please enter both email and password.");
        return false;
    }

    return true;
}
