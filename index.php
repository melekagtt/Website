<?php
session_start();

require_once '../includes/db.class.php';

$error_message = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = (string)$_POST['password'];

    if (empty($username) || empty($password)) {
        $error_message = "Username and password are required";
    } else {
        $database = new Database();
        $db = $database->connect();

        // Prepare SQL statement to prevent SQL injection
        $stmt = $db->prepare("SELECT username, password FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            // Verify password (assuming passwords are hashed)
            if ($password == $user['password']) {
                $_SESSION['username'] = $user['username'];
                $_SESSION['logged_in'] = true;

                // Redirect to dashboard
                header("Location: dashboard.php");
                exit();
            } else {
                $error_message = "Invalid username or password";
            }
        } else {
            $error_message = "Invalid username or password";
        }

        $stmt->close();
        $db->close();
    }
}

// If not POST request or login failed, redirect back to login page with error
if (!empty($error_message)) {
    $_SESSION['error_message'] = $error_message;
    var_dump($_SESSION);
    //header("Location: login.php");
    exit();
}
