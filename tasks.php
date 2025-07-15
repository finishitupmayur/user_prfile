<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location:login.php");
    exit();
}

include('db.php');
$user_id = $_SESSION['user_id'];

// Fetch all tasks for this user
$stmt = $conn->prepare("SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
?>

<!DOCTYPE html>
<html>
<head>
    <title>My Tasks</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<?php include('header.php'); ?>

<div class="container mt-5">
    <h2 class="mb-4">📝 Your Tasks</h2>
    <a href="create_task.php" class="btn btn-primary mb-3">+ Add New Task</a>

    <?php if ($result->num_rows > 0): ?>
        <table class="table table-bordered table-striped">
            <thead class="table-dark">
                <tr>
                    <th>Title</th>
                    <th>Description</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($task = $result->fetch_assoc()): ?>
                    <tr>
                        <td><?= htmlspecialchars($task['title']) ?></td>
                        <td><?= nl2br(htmlspecialchars($task['description'])) ?></td>
                        <td><?= date('d M Y', strtotime($task['created_at'])) ?></td>
                        <td>
                            <a href="edit_task.php?id=<?= $task['id'] ?>" class="btn btn-sm btn-warning">Edit</a>
                            <a href="delete_task.php?id=<?= $task['id'] ?>" class="btn btn-sm btn-danger"
                               onclick="return confirm('Are you sure to delete this task?');">Delete</a>
                        </td>
                    </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p class="text-muted">No tasks found. Click "Add New Task" to create one.</p>
    <?php endif; ?>
</div>

<?php include('footer.php'); ?>
</body>
</html>
