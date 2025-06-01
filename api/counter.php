<?php
header('Content-Type: application/json');

// Chemin vers le fichier du compteur
$counterFile = '/var/www/wallet-nito/data/counter.txt';

// Fonction pour lire le compteur
function readCounter($file) {
    if (!file_exists($file)) {
        return 0;
    }
    return (int)file_get_contents($file);
}

// Fonction pour incrémenter le compteur
function incrementCounter($file) {
    $count = readCounter($file);
    $count++;
    file_put_contents($file, $count, LOCK_EX);
    return $count;
}

// Gérer les requêtes
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Endpoint /api/get-counter
    $count = readCounter($counterFile);
    echo json_encode(['count' => $count]);
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Endpoint /api/increment-counter
    $count = incrementCounter($counterFile);
    echo json_encode(['count' => $count]);
} else {
    http_response_code(405);
    echo json_encode(['error' => 'Méthode non autorisée']);
}
?>
