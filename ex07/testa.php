<?php
// Desactivamos la visualización de errores para que no ensucien el output
error_reporting(0); 

try {
    $db = new SQLite3(':memory:');
    $db->exec("CREATE TABLE users (id INTEGER, user TEXT, pass TEXT)");
    $db->exec("INSERT INTO users VALUES (1, 'admin', 'p4ss_sqlite')");

    $id = isset($_GET['id']) ? $_GET['id'] : '1';

    // Importante: Consultamos 2 columnas para que el UNION funcione con más juego
    $query = "SELECT user, pass FROM users WHERE id = '$id'";
    
    $res = @$db->query($query); // El @ silencia el warning de SQLite

    if ($res) {
        $row = $res->fetchArray(SQLITE3_ASSOC);
        if ($row) {
            // Mantenemos el formato que tu Ruby busca con .scan
            echo "First name: " . $row['user'] . "<br>";
        } else {
            echo "No hay resultados.";
        }
    } else {
        // Si el SQL falla (por el ORDER BY), imprimimos esto para que Ruby lo detecte
        echo "Error en la consulta SQL.";
    }
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
?>
