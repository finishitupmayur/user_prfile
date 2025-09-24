

<?php
session_start();
include('header.php');
include('db.php');

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    $stmt = $conn->prepare("SELECT id, name, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows === 1) {
        $stmt->bind_result($id, $name, $hashed_password);
        $stmt->fetch();

        if (password_verify($password, $hashed_password)) {
            
            $_SESSION['user_id'] = $id;
            $_SESSION['user_name'] = $name;
            header("Location: profile.php");
            exit();
        } else {
            $message = "❌ Incorrect password.";
        }
    } else {
        $message = "❌ No user found with this email.";
    }

    $stmt->close();
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="../assets/js/validation.js"></script>
</head>
<body>
<div class="container mt-5 col-md-6">
    <h2 class="mb-4">Login</h2>
    <form method="POST" onsubmit="return validateLoginForm();">
        <div class="mb-3">
            <label>Email</label>
            <input type="email" name="email" id="login_email" class="form-control">
        </div>
        <div class="mb-3">
            <label>Password</label>
            <input type="password" name="password" id="login_password" class="form-control">
        </div>
        <button type="submit" class="btn btn-success">Login</button>
        <p class="mt-3 text-danger"><?= $message ?></p>
    </form>
</div>
</body>
</html>

