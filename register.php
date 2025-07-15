<?php

session_start();

include('header.php');
include('db.php');

$message = '';
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name     = trim($_POST['name']);
    $email    = trim($_POST['email']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);

    // Backend validation
    if (empty($name)) {
        $errors[] = "Username is required.";
    }
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "A valid email is required.";
    }
    if (empty($password)) {
        $errors[] = "Password is required.";
    }
    if ($password !== $confirm_password) {
        $errors[] = "Passwords do not match.";
    }

    if (empty($errors)) {
        // Hash the password before storing
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        $checkStmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        if (!$checkStmt) {
            die("Email check prepare failed: (" . $conn->errno . ") " . $conn->error);
        }
        $checkStmt->bind_param("s", $email);
        $checkStmt->execute();
        $checkStmt->store_result();

        if ($checkStmt->num_rows > 0) {
            $message = "❌ Email already registered.";
        } else {
            $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
            if (!$stmt) {
                die("Prepare failed: (" . $conn->errno . ") " . $conn->error);
            }
            $stmt->bind_param("sss", $name, $email, $hashed_password);
            if ($stmt->execute()) {
                header("Location: login.php");
                exit;
            } else {
                $message = "❌ Error: " . $conn->error;
            }
            $stmt->close();
        }
        $checkStmt->close();
    } else {
        $message = "❌ " . implode("<br>❌ ", $errors);
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>User Registration</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script>
    // Frontend validation
    function validateRegisterForm() {
        let name = document.getElementById('name').value.trim();
        let email = document.getElementById('email').value.trim();
        let password = document.getElementById('password').value;
        let confirm_password = document.getElementById('confirm_password').value;
        let errors = [];

        if (!name) errors.push("Username is required.");
        if (!email || !/^\S+@\S+\.\S+$/.test(email)) errors.push("A valid email is required.");
        if (!password) errors.push("Password is required.");
        if (password !== confirm_password) errors.push("Passwords do not match.");

        if (errors.length > 0) {
            alert(errors.join('\n'));
            return false;
        }
        return true;
    }
    </script>
</head>
<body>
<div class="container mt-5 col-md-6">
    <h2 class="mb-4">Register</h2>
    <form method="POST" onsubmit="return validateRegisterForm();">
        <div class="mb-3">
            <label for="name">Username</label>
            <input type="text" class="form-control" id="name" name="name" required>
        </div>

        <div class="mb-3">
            <label for="email">Email address</label>
            <input type="email" class="form-control" id="email" name="email" required>
        </div>

        <div class="mb-3">
            <label for="password">Password</label>
            <input type="password" class="form-control" id="password" name="password" required>
        </div>

        <div class="mb-3">
            <label for="confirm_password">Confirm Password</label>
            <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
        </div>

        <button type="submit" class="btn btn-primary">Register</button>

        <p class="mt-3 text-danger"><?= $message ?></p>
    </form>
</div>