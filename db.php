<?php 
$servername = "localhost";
$username = "root";
$password = "root";
$dbname = "task_manager";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
echo "";
?>
