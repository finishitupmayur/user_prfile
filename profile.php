<?php
session_start();

// Redirect to login if not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location:login.php");
    exit();
}

include('db.php');

// Fetch user details
$user_id = $_SESSION['user_id'];

$stmt = $conn->prepare("SELECT name, email, created_at FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result && $result->num_rows === 1) {
    $user = $result->fetch_assoc();
} else {
    // Optional: fallback if user not found
    $user = [
        'name' => 'Unknown',
        'email' => 'Unknown',
        'created_at' => date('Y-m-d')
    ];
}

$stmt->close();
?>
<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>

<?php include('header.php'); ?>

<div class="container mt-5">
    <div class="card shadow p-4">
        <h2 class="mb-3">👤 Welcome, <?= htmlspecialchars($user['name']) ?></h2>
        <p><strong>Email:</strong> <?= htmlspecialchars($user['email']) ?></p>
        <p><strong>Joined:</strong> <?= date('d M Y', strtotime($user['created_at'])) ?></p>

        <div class="mt-4">
            <a href="edit_profile.php" class="btn btn-warning me-2">Edit Profile</a>
            <a href="delete_profile.php" class="btn btn-danger me-2" onclick="return confirm('Are you sure you want to delete your account?');">Delete Account</a>
            <a href="tasks.php" class="btn btn-primary">Manage Tasks</a>
        </div>
    </div>
</div>

<?php include('footer.php'); ?>
</body>
</html>
