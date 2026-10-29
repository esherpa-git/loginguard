<?php
/**
 * Test-Skript für die User-Agent-Blocklist
 *
 * Alternativ: Einzeiliger curl-Befehl (ohne PHP):
 *   curl -A "EsherpaTestBot/1.0" https://DEINE-SEITE.de/wp-login.php
 *   curl -A "Mozilla/5.0" https://DEINE-SEITE.de/wp-login.php  # Für exakte Übereinstimmung
 *
 * Verwendung (mit PHP):
 * 1. Diesen User-Agent in Login Guard → Einstellungen → "Geblockte User-Agents" eintragen:
 *    EsherpaTestBot/1.0
 *
 * 2. URL anpassen (unten) und ausführen:
 *    php test-user-agent-block.php
 *
 * Erwartung bei Sperre: HTML enthält "Zugriff gesperrt" oder "Login gesperrt"
 * Erwartung ohne Sperre: HTML enthält das Login-Formular (z.B. "Anmelden")
 */

$url = 'https://DEINE-SEITE.de/wp-login.php';  // <-- Hier deine WordPress-URL eintragen
$user_agent = 'EsherpaTestBot/1.0';

$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_USERAGENT      => $user_agent,
    CURLOPT_SSL_VERIFYPEER => true,
]);
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

echo "URL: $url\n";
echo "User-Agent: $user_agent\n";
echo "HTTP-Code: $http_code\n";
echo "---\n";

if (strpos($response, 'Zugriff gesperrt') !== false || strpos($response, 'Login gesperrt') !== false) {
    echo "✓ BLOCKLIST AKTIV – User-Agent wurde blockiert.\n";
} elseif (strpos($response, 'Anmelden') !== false || strpos($response, 'log in') !== false || strpos($response, 'wp-login') !== false) {
    echo "✗ Nicht blockiert – Login-Formular wurde angezeigt.\n";
    echo "  Prüfe: Ist '$user_agent' in der Blockliste eingetragen?\n";
} else {
    echo "? Unklare Antwort. HTML-Ausschnitt:\n";
    echo substr(strip_tags($response), 0, 300) . "...\n";
}
