<?php 
include('rsa.php');
?>
<html>
<body>

<h1>Lab 8 Server</h1>
<?php

$ciphertext = $_POST["userInput"];

echo("<p>Ciphertext: " . $ciphertext . "</p>");

// Get the private Key
$privateKey = get_rsa_privatekey('private.key');

// compute the decrypted value
$decrypted = rsa_decryption($ciphertext, $privateKey);

echo("<p>Decrypted text: " . $decrypted . "</p>");

// Your task: append the Decrypted text in the database.txt

// // Get the public Key
// $publicKey = get_rsa_publickey('public.key');

// // compute the ciphertext
// $encrypted = rsa_encryption($plaintext, $publicKey);
// echo $encrypted."<br/><br/><br/>";

?>
</body>
</html>
