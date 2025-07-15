<?php
session_start();
session_unset();  // clear all session variables
session_destroy();  

header("Location: login.php");
exit();
?>