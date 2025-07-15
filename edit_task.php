<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

include('db.php');

$user_id = $_SESSION['user_id'];
$message = '';
$task_id = $_GET['id'] ?? null;

if (!$task_id) {
    header("Location: tasks.php");
    exit();
}

// Fetch the task
$stmt = $conn->prepare("SELECT * FROM tasks WHERE id = ? AND user_id = ?");
$stmt->bind_param("ii", $task_id, $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows !== 1) {
    header("Location: tasks.php");
    exit();
}

$task = $result->fetch_assoc();
$stmt->close();

// Handle update
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = trim($_POST['title']);
    $description = trim($_POST['description']);

    if ($title !== '') {
        $stmt = $conn->prepare("UPDATE tasks SET title = ?, description = ? WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ssii", $title, $description, $task_id, $user_id);

        if ($stmt->execute()) {
            header("Location: tasks.php");
            exit();
        } else {
            $message = "❌ Failed to update task.";
        }
        $stmt->close();
    } else {
        $message = "❗ Title is required.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Edit Task</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<?php include('header.php'); ?>

<div class="container mt-5 col-md-6">
    <h2>Edit Task</h2>

    <?php if ($message): ?>
        <div class="alert alert-warning"><?= $message ?></div>
    <?php endif; ?>

    <form method="POST">
        <div class="mb-3">
            <label>Task Title</label>
            <input type="text" name="title" class="form-control" value="<?= htmlspecialchars($task['title']) ?>" required>
        </div>

        <div class="mb-3">
            <label>Description</label>
            <textarea name="description" class="form-control" rows="4"><?= htmlspecialchars($task['description']) ?></textarea>
        </div>

        <button type="submit" class="btn btn-primary">Update Task</button>
        <a href="tasks.php" class="btn btn-secondary">Back</a>
    </form>
</div>

<?php include('footer.php'); ?>
</body>
</html>
