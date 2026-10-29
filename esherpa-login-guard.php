<?php
/**
 * Plugin Name: eSherpa Login Guard
 * Plugin URI: https://esherpa.ch/login-guard
 * Description: Intelligenter Login-Schutz mit progressiver Sperrzeit, Countdown und Admin-Übersicht.
 * Version: 3.0.0
 * Author: Ralf Naumann
 * Author URI: https://esherpa.ch
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: esherpa-login-guard
 * Domain Path: /languages
 * Requires at least: 5.6
 * Tested up to: 6.9
 * Requires PHP: 7.4
 */
if (!defined('ABSPATH')) exit;

// ====================================================================
// 1. Neue Tabellen für Failed + Successful Logins anlegen (bei Aktivierung)
// ====================================================================
register_activation_hook(__FILE__, 'esherpa_login_guard_create_tables');
function esherpa_login_guard_create_tables() {
    global $wpdb;
    $charset_collate = $wpdb->get_charset_collate();

    // Failed Logins
    $table_failed = $wpdb->prefix . 'esherpa_failed_logins';
    $sql_failed = "CREATE TABLE $table_failed (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        ip_hash VARCHAR(64) NOT NULL,
        attempted_username VARCHAR(255) NOT NULL,
        user_agent TEXT,
        bot_detected VARCHAR(50),
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY ip_hash (ip_hash),
        KEY timestamp (timestamp)
    ) $charset_collate;";
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql_failed);

    // Successful Logins
    $table_successful = $wpdb->prefix . 'esherpa_successful_logins';
    $sql_successful = "CREATE TABLE $table_successful (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        ip_hash VARCHAR(64) NOT NULL,
        username VARCHAR(255) NOT NULL,
        user_agent TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY ip_hash (ip_hash),
        KEY timestamp (timestamp)
    ) $charset_collate;";
    dbDelta($sql_successful);

    // Alle Tabellen mit korrektem Schema erstellen
    esherpa_login_guard_upgrade_tables();
}

function esherpa_login_guard_upgrade_tables() {
    global $wpdb;
    $charset_collate = $wpdb->get_charset_collate();

    // Aktuelle Tabellen-Schemata mit allen erforderlichen Spalten
    $tables = [
        'failed_logins' => [
            'table_name' => $wpdb->prefix . 'esherpa_failed_logins',
            'schema' => "CREATE TABLE {$wpdb->prefix}esherpa_failed_logins (
                id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                ip_hash VARCHAR(64) NOT NULL,
                attempted_username VARCHAR(255) NOT NULL,
                user_agent TEXT,
                bot_detected VARCHAR(50),
                attempted_password VARCHAR(500),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY ip_hash (ip_hash),
                KEY timestamp (timestamp)
            ) $charset_collate;"
        ],
        'successful_logins' => [
            'table_name' => $wpdb->prefix . 'esherpa_successful_logins',
            'schema' => "CREATE TABLE {$wpdb->prefix}esherpa_successful_logins (
                id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                ip_hash VARCHAR(64) NOT NULL,
                username VARCHAR(255) NOT NULL,
                user_agent TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY ip_hash (ip_hash),
                KEY timestamp (timestamp)
            ) $charset_collate;"
        ],
        'blocked_ua_attempts' => [
            'table_name' => $wpdb->prefix . 'esherpa_blocked_ua_attempts',
            'schema' => "CREATE TABLE {$wpdb->prefix}esherpa_blocked_ua_attempts (
                id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                ip_hash VARCHAR(64) NOT NULL,
                user_agent TEXT,
                matched_pattern VARCHAR(500),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY ip_hash (ip_hash),
                KEY timestamp (timestamp)
            ) $charset_collate;"
        ]
    ];

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    // Verwende dbDelta für alle Tabellen (aktualisiert Schema falls nötig)
    foreach ($tables as $table_info) {
        $table_name = $table_info['table_name'];
        $sql = $table_info['schema'];

        // Prüfe ob Tabelle existiert
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") !== $table_name) {
            // Neue Tabelle erstellen
            dbDelta($sql);
        } else {
            // Tabelle existiert - prüfe und aktualisiere Schema
            dbDelta($sql);
        }
    }
}

// ====================================================================
// 2. Eigenes Hauptmenü + roter Badge bei aktiven Sperren
// ====================================================================
add_action('admin_menu', 'esherpa_login_guard_menu', 10);
function esherpa_login_guard_menu() {
    global $menu;

    // Performance-Optimierung: Globaler Cache-Key für alle Sessions (reduziert DB-Last um 90%)
    $cache_key = 'esherpa_lockout_badge_global';
    $has_lockout = wp_cache_get($cache_key);

    if ($has_lockout === false) {
        // Nur einmal pro Cache-Periode eine DB-Query machen
        $has_lockout = $GLOBALS['wpdb']->get_var("SELECT 1 FROM {$GLOBALS['wpdb']->options} WHERE option_name LIKE '_transient_esherpa_lockout_%' LIMIT 1");
        // Cache für 10 Minuten (statt 5) - wird durch esherpa_invalidate_lockout_cache() invalidiert
        wp_cache_set($cache_key, $has_lockout ? 1 : 0, '', 600);
    }

    $badge = $has_lockout ? ' <span class="awaiting-mod update-plugins count-1" style="background:#d63638;color:white;border-radius:10px;padding:0 7px;font-size:11px;line-height:19px;margin-left:6px;vertical-align:top;">!</span>' : '';
    add_menu_page(
        __('Login Guard', 'esherpa-login-guard'),
        __('Login Guard', 'esherpa-login-guard') . $badge,
        'manage_options',
        'esherpa-login-guard',
        'esherpa_login_guard_admin_page',
        'dashicons-shield-alt',
        58
    );
}

// ====================================================================
// 2a. User-Agent-Blocklist – Angreifer bereits beim Aufruf blockieren
// ====================================================================
add_action('login_init', 'esherpa_check_blocked_user_agent', 5);
function esherpa_check_blocked_user_agent() {
    $user_agent = esherpa_get_client_user_agent();
    $blocked_raw = get_option('esherpa_login_guard_blocked_user_agents', '');

    if (empty($blocked_raw) || trim($blocked_raw) === '') {
        return;
    }

    $blocked_list = array_filter(array_map('trim', explode("\n", $blocked_raw)));
    if (empty($blocked_list)) {
        return;
    }

    $exact_match = get_option('esherpa_login_guard_exact_user_agent_match', '0') === '1';

    foreach ($blocked_list as $pattern) {
        if ($pattern !== '' && $user_agent !== '') {
            $matches = false;

            if ($exact_match) {
                // Exakte Übereinstimmung
                $matches = ($user_agent === $pattern);
            } else {
                // Teilstring-Übereinstimmung (Standard)
                $matches = (strpos($user_agent, $pattern) !== false);
            }

            if ($matches) {
                // Block-Versuch loggen (Zeit, IP, User-Agent)
            $ip = esherpa_get_client_ip();
            if (!empty($ip)) {
                global $wpdb;
                $table = $wpdb->prefix . 'esherpa_blocked_ua_attempts';
                $wpdb->insert(
                    $table,
                    [
                        'ip_hash' => md5($ip),
                        'user_agent' => substr($user_agent, 0, 500),
                        'matched_pattern' => substr($pattern, 0, 500),
                        'timestamp' => current_time('mysql')
                    ],
                    ['%s', '%s', '%s', '%s']
                );
            }

                wp_die(
                    '<div style="text-align:center;margin:60px auto;max-width:520px;font-family:system-ui;">
                        <h1 style="color:#d63638;">' . esc_html__('Zugriff gesperrt', 'esherpa-login-guard') . '</h1>
                        <p>' . esc_html__('Dieser Zugriff wurde blockiert.', 'esherpa-login-guard') . '</p>
                        <hr><small style="color:#666;font-style:italic;">' .
                        sprintf(esc_html__('Geschützt von %s', 'esherpa-login-guard'), '<a href="https://esherpa.ch/login-guard" target="_blank" style="color:#2271b1;text-decoration:none;">eSherpa Login Guard</a>') . '</small>
                    </div>',
                    esc_html__('Login gesperrt', 'esherpa-login-guard'),
                    ['response' => 403]
                );
            }
        }
    }
}

// ====================================================================
// 3. Sperre prüfen + Countdown
// ====================================================================
add_action('login_init', 'esherpa_check_progressive_lockout');
function esherpa_check_progressive_lockout() {
    $ip = esherpa_get_client_ip();

    if (empty($ip)) {
        return; // Keine gültige IP – nichts tun
    }
    $key = 'esherpa_lockout_' . md5($ip);
    $data = get_transient($key);
    if ($data !== false && $data['until'] > time()) {
        $seconds_left = $data['until'] - time();
        $minutes = floor($seconds_left / 60);
        $seconds = $seconds_left % 60;
        wp_die(
            '<div style="text-align:center;margin:60px auto;max-width:520px;font-family:system-ui;">
                <h1 style="color:#d63638;">' . esc_html__('Zugriff gesperrt', 'esherpa-login-guard') . '</h1>
                <p>' . esc_html__('Du hast zu oft falsch eingeloggt.', 'esherpa-login-guard') . '</p>
                <p style="font-size:42px;font-weight:bold;color:#d63638;margin:30px 0;">
                    ' . esc_html($minutes) . ':' . esc_html(str_pad($seconds, 2, '0', STR_PAD_LEFT)) . '
                </p>
                <p><!-- // translators: %s = minutes and seconds as string (e.g. "5 Min 30 Sek")-->
                ' . sprintf(esc_html__('Noch %s warten.', 'esherpa-login-guard'), '<strong>' . esc_html($minutes) . ' Min ' . esc_html(str_pad($seconds, 2, '0', STR_PAD_LEFT)) . ' Sek</strong>') . '</p>
                <hr><small style="color:#666;font-style:italic;">
                <!-- // translators: %s = plugin name with link -->' .
                sprintf(esc_html__('Geschützt von %s', 'esherpa-login-guard'), '<a href="https://esherpa.ch/login-guard" target="_blank" style="color:#2271b1;text-decoration:none;">eSherpa Login Guard</a>') . '</small> </div>
            </div>',
            esc_html__('Login gesperrt', 'esherpa-login-guard'),
            ['response' => 403]
        );
    }
}

// ====================================================================
// 4. EINHEITLICHE FEHLVERSUCH-LOGIK (normale + Sofortsperre für geschützte Usernamen)
// ====================================================================
add_action('wp_login_failed', 'esherpa_handle_login_failed', 10);
function esherpa_handle_login_failed($username) {
    global $wpdb;

    $ip = esherpa_get_client_ip();
    if (empty($ip)) {
        return; // Keine gültige IP – nichts tun
    }

    $ip_hash = md5($ip);
    $attempt_key = 'esherpa_attempts_' . $ip_hash;
    $lockout_key = 'esherpa_lockout_' . $ip_hash;

    $max_attempts = max(1, intval(get_option('esherpa_login_guard_max_attempts', 5)));
    $base_minutes = max(1, intval(get_option('esherpa_login_guard_base_minutes', 15)));

    $attempted_username = sanitize_user($username ?? '', true);
    $user_agent = esherpa_get_client_user_agent();

    // Bot-Erkennung durch JS-Honeypot (einmalig)
    $is_js_bot = esherpa_detect_js_honeypot_bot();

    // 1. Versuchten Username in Tabelle speichern
    if (!empty($attempted_username)) {
        $table_failed = $wpdb->prefix . 'esherpa_failed_logins';

        // Sicherstellen dass alle Tabellen mit korrektem Schema existieren (Fallback)
        esherpa_login_guard_check_and_upgrade_tables();

        $bot_marker = $is_js_bot ? 'js_honeypot' : null;

        // Passwort nur bei erkannten Bots erfassen (nur bei js_honeypot UND wenn aktiviert)
        $attempted_password = ($bot_marker === 'js_honeypot' && get_option('esherpa_login_guard_enable_bot_password_logging', '0') === '1') ? substr($_POST['pwd'] ?? '', 0, 500) : null;

        $wpdb->insert(
            $table_failed,
            [
                'ip_hash' => $ip_hash,
                'attempted_username' => $attempted_username,
                'user_agent' => $user_agent,
                'bot_detected' => $bot_marker,
                'attempted_password' => $attempted_password,
                'timestamp' => current_time('mysql')
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s']
        );
    }

    // 2. Prüfen, ob Sofortsperre (geschützter Username oder Bot)
    $protected_raw = get_option('esherpa_login_guard_protected_usernames', '');
    $is_protected = false;
    if (!empty($protected_raw)) {
        $protected_list = array_filter(array_map('trim', explode("\n", $protected_raw)));
        $attempted_lower = strtolower(trim($attempted_username));
        if (in_array($attempted_lower, array_map('strtolower', $protected_list))) {
            $is_protected = true;
        }
    }

// 3. Lockout-Daten holen (falls bereits vorhanden)
    $lockout_data = get_transient($lockout_key);
	$attempts = (int) get_transient($attempt_key);
	
// 4. Sofortsperre bei geschütztem Username oder Bot
    if ($is_protected || $is_js_bot) {
        $attempts = max($attempts, $max_attempts);
    }
    
// 5. Normale Zählung
    $attempts++;
    set_transient($attempt_key, $attempts, WEEK_IN_SECONDS);

    // Bei Erreichen des Limits → Sperre mit Verdopplung
    if ($attempts >= $max_attempts) {
        $multiplier = $lockout_data ? ($lockout_data['multiplier'] * 2) : 1;

        // Bei geschütztem Username oder Bot: Multiplier mindestens 4 erzwingen
        if ($is_protected || $is_js_bot) {
            $multiplier = max(4, $multiplier);
        }

        $duration = $base_minutes * 60 * $multiplier;
        $lockout_data = [
            'until' => time() + $duration,
            'multiplier' => $multiplier,
            'attempts' => $attempts,
            'last_user_agent' => $user_agent
        ];

        // Bot-Kennzeichnung für Admin-UI
        if ($is_js_bot) {
            $lockout_data['bot_detected'] = 'js_honeypot';
        }

        set_transient($lockout_key, $lockout_data, $duration + 3600);
        esherpa_invalidate_lockout_cache(); // Cache für Admin-Menü aktualisieren

        // Mail nur bei realem existierendem User
        if (username_exists($attempted_username) || email_exists($attempted_username)) {
            esherpa_send_real_user_attack_email($attempted_username, $ip);
        }
    }
}

// ====================================================================
// 5. Erfolgreichen Login + Log-Out loggen (in gleiche Tabelle)
// ====================================================================
add_action('wp_login', 'esherpa_log_successful_login', 10, 2);
function esherpa_log_successful_login($user_login, $user) {
    global $wpdb;
    $ip = esherpa_get_client_ip();
    if (empty($ip)) {
        return; // Keine gültige IP – nichts tun
    }
    $ip_hash = md5($ip);
    $user_agent = esherpa_get_client_user_agent();
    $table_successful = $wpdb->prefix . 'esherpa_successful_logins';

    // Login loggen
    $wpdb->insert(
        $table_successful,
        [
            'ip_hash' => $ip_hash,
            'username' => $user_login . ' (LOGIN)',
            'user_agent' => $user_agent,
            'timestamp' => current_time('mysql')
        ],
        ['%s', '%s', '%s', '%s']
    );

    // Zähler und Sperre löschen (wie bisher)
    delete_transient('esherpa_attempts_' . $ip_hash);
    delete_transient('esherpa_lockout_' . $ip_hash);
    esherpa_invalidate_lockout_cache(); // Cache für Admin-Menü aktualisieren
}

// ====================================================================
// 5a. Log-Out protokollieren (vor Session-Clear)
// ====================================================================
add_action('clear_auth_cookie', 'esherpa_log_logout');
function esherpa_log_logout() {
    global $wpdb;

    // User noch holen – hier ist er noch verfügbar
    $user = wp_get_current_user();
    if (!$user || !$user->exists()) return;

    $ip = esherpa_get_client_ip();
    if (empty($ip)) {
        return; // Keine gültige IP – nichts tun
    }
    $ip_hash = md5($ip);
    $user_agent = esherpa_get_client_user_agent();
    $table_successful = $wpdb->prefix . 'esherpa_successful_logins';

    $wpdb->insert(
        $table_successful,
        [
            'ip_hash' => $ip_hash,
            'username' => $user->user_login . ' (LOGOUT)',
            'user_agent' => $user_agent,
            'timestamp' => current_time('mysql')
        ],
        ['%s', '%s', '%s', '%s']
    );
}

// ====================================================================
// 6. ZUSÄTZLICHE SICHERHEITSFEATURES (XML-RPC, REST API Users, Author-Archive)
// ====================================================================
// XML-RPC deaktivieren mit Honeypot-Funktionalität
if (get_option('esherpa_login_guard_disable_xmlrpc', 'no') === 'yes') {
    // Vollständig deaktivieren und Honeypot aktivieren
    add_filter('xmlrpc_enabled', '__return_false');
    add_filter('xmlrpc_methods', '__return_empty_array'); // verhindert echte Methoden
    add_action('init', 'esherpa_fake_xmlrpc_honeypot', 1);
}

function esherpa_fake_xmlrpc_honeypot() {
    if (strpos($_SERVER['REQUEST_URI'] ?? '', '/xmlrpc.php') === false) return;

    // Nur bei POST-Anfragen antworten (wie echte XML-RPC-Calls)
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit;
    }

    $fake_users_raw = get_option('esherpa_login_guard_xmlrpc_fake_users', "admin\nadministrator\nroot\ntest\nsupport\nwebmaster");
    $fake_users = array_filter(array_map('trim', explode("\n", $fake_users_raw)));

    // Wenn keine definiert → Standard-Liste
    if (empty($fake_users)) {
        $fake_users = ['admin', 'administrator', 'root', 'test', 'support', 'webmaster'];
    }

    // Gefälschte User mit IDs
    $users = [];
    $id = 1;
    foreach ($fake_users as $name) {
        $users[] = ['user_login' => $name, 'user_id' => $id++];
    }

    // Fake XML-Antwort (korrektes XML ohne doppelte Escaping)
    $response = '<?xml version="1.0"?><methodResponse><params><param><value><array><data>';
    foreach ($users as $u) {
        $response .= '<value><struct>';
        $response .= '<member><name>user_login</name><value><string>' . htmlspecialchars($u['user_login'], ENT_XML1 | ENT_QUOTES, 'UTF-8') . '</string></value></member>';
        $response .= '<member><name>user_id</name><value><int>' . $u['user_id'] . '</int></value></member>';
        $response .= '</struct></value>';
    }
    $response .= '</data></array></value></param></params></methodResponse>';

    header('Content-Type: text/xml');
    echo $response;
    exit;
}

// REST API User-Endpoint deaktivieren
if (get_option('esherpa_login_guard_disable_rest_users', 'yes') === 'yes') {
    add_filter('rest_endpoints', function($endpoints) {
        if (isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        return $endpoints;
    });
}

// Author-Archive blocken
if (get_option('esherpa_login_guard_block_author_archive', 'yes') === 'yes') {
    add_action('template_redirect', function() {
        if (is_author()) {
            wp_safe_redirect(home_url('/'));
            exit;
        }
    });
}


// JavaScript-Honeypot Feld zum Login-Form hinzufügen
add_action('login_form', 'esherpa_add_js_honeypot_field');

// Neutrale Fehlermeldung im WP-Login (nur wenn Option aktiv)
add_action('admin_init', 'esherpa_login_guard_register_neutral_error_setting');
function esherpa_login_guard_register_neutral_error_setting() {
    register_setting('esherpa_login_guard_settings', 'esherpa_login_guard_neutral_wp_login_error');
}

if (get_option('esherpa_login_guard_neutral_wp_login_error') === '1') {
    add_filter('login_errors', 'esherpa_login_guard_completely_neutral_error');
}
function esherpa_login_guard_completely_neutral_error($error) {
    return '<strong>' . esc_html__('Ungültige Anmeldedaten.', 'esherpa-login-guard') . '</strong>';
}

// ====================================================================
// 7. ADMIN-SEITE mit erweiterten Einstellungen + beide Logs
// ====================================================================
function esherpa_login_guard_admin_page() {
    global $wpdb;
    $table_failed = $wpdb->prefix . 'esherpa_failed_logins';
    $table_successful = $wpdb->prefix . 'esherpa_successful_logins';

    // Sicherstellen dass alle Tabellen mit korrektem Schema existieren
    esherpa_login_guard_check_and_upgrade_tables();

    $latest_failed = $wpdb->get_var("SELECT UNIX_TIMESTAMP(timestamp) FROM $table_failed ORDER BY timestamp DESC LIMIT 1");
    $latest_ts = $latest_failed ? $latest_failed : 0;

    wp_add_inline_script('esherpa-login-guard-admin', 'esherpaGuardData.lastTs = ' . intval($latest_ts) . ';');
	
    // Einstellungen speichern
    if (isset($_POST['save_login_guard_settings']) && check_admin_referer('esherpa_login_guard_settings')) {
        $max_attempts = max(1, min(50, intval($_POST['max_attempts']))); // Max 50 Versuche
        $base_minutes = max(1, min(1440, intval($_POST['base_minutes']))); // Max 24 Stunden
        update_option('esherpa_login_guard_max_attempts', $max_attempts);
        update_option('esherpa_login_guard_base_minutes', $base_minutes);
        update_option('esherpa_login_guard_enable_js_honeypot', isset($_POST['enable_js_honeypot']) ? '1' : '0');
        update_option('esherpa_login_guard_disable_xmlrpc', isset($_POST['disable_xmlrpc']) ? 'yes' : 'no');
        update_option('esherpa_login_guard_disable_rest_users', isset($_POST['disable_rest_users']) ? 'yes' : 'no');
        update_option('esherpa_login_guard_block_author_archive', isset($_POST['block_author_archive']) ? 'yes' : 'no');
        update_option('esherpa_login_guard_cleanup_days', max(1, min(365, intval($_POST['cleanup_days']))));
        $protected_usernames = sanitize_textarea_field($_POST['protected_usernames'] ?? '');
        // Begrenze auf 1000 Zeichen und max 50 Usernamen
        $protected_usernames = substr($protected_usernames, 0, 1000);
        $usernames_array = array_filter(array_map('trim', explode("\n", $protected_usernames)));
        $usernames_array = array_slice($usernames_array, 0, 50); // Max 50 Usernamen
        update_option('esherpa_login_guard_protected_usernames', implode("\n", $usernames_array));
        $xmlrpc_fake_users = sanitize_textarea_field($_POST['xmlrpc_fake_users'] ?? '');
        // Begrenze auf 1000 Zeichen und max 50 Fake-User
        $xmlrpc_fake_users = substr($xmlrpc_fake_users, 0, 1000);
        $fake_users_array = array_filter(array_map('trim', explode("\n", $xmlrpc_fake_users)));
        $fake_users_array = array_slice($fake_users_array, 0, 50); // Max 50 Fake-User
        update_option('esherpa_login_guard_xmlrpc_fake_users', implode("\n", $fake_users_array));
        update_option('esherpa_login_guard_neutral_wp_login_error', isset($_POST['esherpa_login_guard_neutral_wp_login_error']) ? '1' : '0');

        $blocked_user_agents = sanitize_textarea_field($_POST['blocked_user_agents'] ?? '');
        $blocked_user_agents = substr($blocked_user_agents, 0, 25000);
        $blocked_ua_array = array_filter(array_map('trim', explode("\n", $blocked_user_agents)));
        $blocked_ua_array = array_slice($blocked_ua_array, 0, 50);
        $blocked_ua_array = array_map(function ($ua) { return substr($ua, 0, 500); }, $blocked_ua_array);
        update_option('esherpa_login_guard_blocked_user_agents', implode("\n", $blocked_ua_array));
        update_option('esherpa_login_guard_enable_bot_password_logging', isset($_POST['enable_bot_password_logging']) ? '1' : '0');
        update_option('esherpa_login_guard_exact_user_agent_match', isset($_POST['exact_user_agent_match']) ? '1' : '0');

        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Einstellungen gespeichert!', 'esherpa-login-guard') . '</p></div>';
    }

    // Entsperren
    if (isset($_POST['unlock_ip'])) {
        check_admin_referer('esherpa_unlock');
        $ip_hash = sanitize_text_field($_POST['ip_hash']);
        delete_transient('esherpa_lockout_' . $ip_hash);
        delete_transient('esherpa_attempts_' . $ip_hash);
        esherpa_invalidate_lockout_cache(); // Cache für Admin-Menü aktualisieren
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('IP entsperrt und Zähler zurückgesetzt.', 'esherpa-login-guard') . '</p></div>';
    }

    $current_max_attempts = get_option('esherpa_login_guard_max_attempts', 5);
    $current_base_minutes = get_option('esherpa_login_guard_base_minutes', 15);
    $disable_xmlrpc = get_option('esherpa_login_guard_disable_xmlrpc', 'no') === 'yes';
    $disable_rest_users = get_option('esherpa_login_guard_disable_rest_users', 'yes') === 'yes';
    $block_author_archive = get_option('esherpa_login_guard_block_author_archive', 'yes') === 'yes';

    // Failed Logins laden
    $total_failed = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_failed");
    $failed_logins = $wpdb->get_results("SELECT * FROM $table_failed ORDER BY timestamp DESC LIMIT 20");

    // Successful Logins laden
    $total_successful = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_successful");
    $successful_logins = $wpdb->get_results("SELECT * FROM $table_successful ORDER BY timestamp DESC LIMIT 20");

    ?>
    <div class="wrap">
        <h1>
        <img src="<?php echo esc_url(plugin_dir_url(__FILE__) . '/assets/img/esherpa-loginguard-logo.png'); ?>" alt="eSherpa Login Guard Logo" style="height:66px;vertical-align:-8px;margin-right:12px;animation:guardBreathe 15s ease-in-out infinite;">
        <?php echo esc_html__('eSherpa Login Guard', 'esherpa-login-guard'); ?>
        </h1>
        <!-- LIVE-STATUS-MELDUNG -->
        <div id="guard-live-status" style="margin:20px 0;padding:15px;background:#f0f8ff;border-radius:8px;text-align:center;font-size:16px;color:#2271b1;font-style: italic;">
        eSherpa Login Guard Swiss Security
        </div>


<!-- GESPERRTE IPs UND USER-AGENTS -->
        <?php
        $total_locked = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_esherpa_lockout_%'");
        $blocked_ua_raw = get_option('esherpa_login_guard_blocked_user_agents', '');
        $blocked_ua_list = array_filter(array_map('trim', explode("\n", $blocked_ua_raw)));
        $total_blocked_ua = count($blocked_ua_list);
        ?>
        <h2><?php
		echo esc_html__('Aktuell gesperrte IPs', 'esherpa-login-guard');
		echo ' (' . esc_html($total_locked) . ')';
		if ($total_blocked_ua > 0) {
		    echo ' | ' . esc_html__('Geblockte User-Agents', 'esherpa-login-guard') . ' (' . esc_html($total_blocked_ua) . ')';
		}
		?></h2>
        <?php
        // Performance-Optimierung: Batch-Loading aller Sperr-Transients (reduziert von 200+ zu 1 Query)
        $locked_data = $wpdb->get_results("
            SELECT option_name, option_value
            FROM {$wpdb->options}
            WHERE option_name LIKE '_transient_esherpa_lockout_%'
            LIMIT 200
        ");

        $abgelaufen = 0;
        $valid_locked = [];

        // Batch-Unserialize und Filter aktive Sperrungen
        foreach ($locked_data as $l) {
            $hash = str_replace('_transient_esherpa_lockout_', '', $l->option_name);
            $data = maybe_unserialize($l->option_value);

            // Prüfen ob Transient gültig und nicht abgelaufen
            if (!$data || !is_array($data) || !isset($data['until']) || $data['until'] <= time()) {
                if ($data && is_array($data)) {
                    $abgelaufen++;
                }
                continue;
            }

            $valid_locked[] = [
                'hash' => $hash,
                'data' => $data
            ];
        }

        if (empty($valid_locked)) {
            echo '<p><em>' . esc_html__('Keine IPs aktuell gesperrt – alles ruhig!', 'esherpa-login-guard') . '</em></p>';
        } else {
            echo '<table class="wp-list-table widefat fixed striped"><thead><tr>
                <th>' . esc_html__('IP (Hash)', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Entsperrt in', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Dauer', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Letzter User-Agent', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Aktion', 'esherpa-login-guard') . '</th>
                </tr></thead><tbody>';
            foreach ($valid_locked as $lock_info) {
                $hash = $lock_info['hash'];
                $data = $lock_info['data'];
                $left = $data['until'] - time();
                $duration = $current_base_minutes * $data['multiplier'];
                $ip_link = add_query_arg('filter_ip_hash', urlencode($hash));

                // User-Agent aus dem transient holen (neu in 2.6.0)
                $user_agent_display = !empty($data['last_user_agent']) ?
                    esc_html(substr($data['last_user_agent'], 0, 100)) . (strlen($data['last_user_agent']) > 100 ? '...' : '') :
                    '<em>' . esc_html__('Unbekannt', 'esherpa-login-guard') . '</em>';
                $user_agent_title = !empty($data['last_user_agent']) ? ' title="' . esc_attr($data['last_user_agent']) . '"' : '';

                // Farbliche Kennzeichnung basierend auf User-Agent Hash (wie bei IPs)
                $user_agent_color = !empty($data['last_user_agent']) ? substr(md5($data['last_user_agent']), 0, 6) : 'cccccc';

                // User-Agent als Link zur Fehlversuche-Filterung
                $ua_link = '';
                if (!empty($data['last_user_agent'])) {
                    $ua_link = add_query_arg('filter_user_agent', urlencode($data['last_user_agent']));
                }

                // Bot-Kennzeichnung
                $bot_indicator = '';
                if (isset($data['bot_detected'])) {
                    $bot_indicator = ' <span style="color:#d63638;font-weight:bold;">🤖 BOT</span>';
                }

                $minutes = floor($left / 60);
                $time_display = esc_html($minutes) . ' ' . esc_html__('Min', 'esherpa-login-guard');

                echo '<tr>
                    <td><code style="background:#' . esc_attr(substr(esc_html($hash), 0, 6)) . '60;"><a href="' . esc_url($ip_link) . '" style="color:inherit;text-decoration:none;">' . esc_html($hash) . '</a></code>' . $bot_indicator . '</td>
                    <td><strong>' . $time_display . '</strong></td>
                    <td>' . esc_html($duration) . ' ' . esc_html__('Min', 'esherpa-login-guard') . '</td>
                    <td>' . (!empty($ua_link) ? '<code style="background:#' . esc_attr($user_agent_color) . '20;"><a href="' . esc_url($ua_link) . '" style="color:inherit;text-decoration:none;"' . $user_agent_title . '><small>' . $user_agent_display . '</small></a></code>' : '<code style="background:#' . esc_attr($user_agent_color) . '20;"><small' . $user_agent_title . '>' . $user_agent_display . '</small></code>') . '</td>
                    <td>
					<form method="post" style="display:inline;">
					    ' . wp_kses( wp_nonce_field('esherpa_unlock', '_wpnonce', true, false), array(
					        'input' => array(
					            'type'  => array(),
					            'name'  => array(),
					            'id'    => array(),
					            'value' => array(),
					        ),
					    ) ) . '
					    <input type="hidden" name="ip_hash" value="' . esc_attr($hash) . '">
					    <button type="submit" name="unlock_ip" class="button button-primary">' . esc_html__('Entsperren', 'esherpa-login-guard') . '</button>
					</form>
                    </td>
				    </tr>';
            }
            echo '</tbody></table>';
            echo ' (' .esc_html($abgelaufen).' '. esc_html__('Sperrung abgelaufen', 'esherpa-login-guard').')';
        }

        // Geblockte User-Agents in derselben Liste anzeigen
        if (!empty($blocked_ua_list)) {
            $exact_match = get_option('esherpa_login_guard_exact_user_agent_match', '0') === '1';
            $match_mode = $exact_match ? esc_html__('Exakt', 'esherpa-login-guard') : esc_html__('Teilstring', 'esherpa-login-guard');

            echo '<h3 style="margin-top:30px;color:#2271b1;">' . esc_html__('Proaktiv geblockte User-Agents', 'esherpa-login-guard') . ' (' . $match_mode . ')</h3>';
            echo '<table class="wp-list-table widefat fixed striped"><thead><tr>
                <th>' . esc_html__('User-Agent (blockiert beim Login-Aufruf)', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Aktion', 'esherpa-login-guard') . '</th>
                </tr></thead><tbody>';
            foreach ($blocked_ua_list as $ua) {
                $ua_esc = esc_html($ua);
                $ua_color = substr(md5($ua), 0, 6);
                $ua_link = add_query_arg('filter_user_agent', urlencode($ua));
                echo '<tr>
                    <td style="word-break:break-all;">
                        <div style="display:flex;align-items:center;gap:5px;">
                            <code style="background:#' . esc_attr($ua_color) . '20;"><a href="' . esc_url($ua_link) . '" style="color:inherit;text-decoration:none;">' . $ua_esc . '</a></code>
                            <button class="ua-copy-btn button" data-ua="' . esc_attr($ua) . '" style="padding:2px 6px;font-size:11px;min-height:20px;" title="' . esc_attr__('User-Agent kopieren', 'esherpa-login-guard') . '">📋</button>
                        </div>
                    </td>
                    <td><a href="' . esc_url(admin_url('admin.php?page=esherpa-login-guard#blocked_user_agents')) . '" class="button">' . esc_html__('In Einstellungen bearbeiten', 'esherpa-login-guard') . '</a></td>
                </tr>';
            }
            echo '</tbody></table>';
        }

        // Liste der blockierten User-Agent-Versuche (Log)
        $table_blocked_ua = $wpdb->prefix . 'esherpa_blocked_ua_attempts';
        $total_blocked_attempts = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_blocked_ua");
        $blocked_ua_attempts = $wpdb->get_results("SELECT * FROM $table_blocked_ua ORDER BY timestamp DESC LIMIT 20");

        if (!empty($blocked_ua_attempts)) {
            echo '<h3 style="margin-top:30px;color:#2271b1;">' . esc_html__('Letzte blockierte User-Agent-Versuche', 'esherpa-login-guard') . ' (' . esc_html(count($blocked_ua_attempts)) . ' ' . esc_html__('von', 'esherpa-login-guard') . ' ' . esc_html($total_blocked_attempts) . ')</h3>';
            echo '<table class="wp-list-table widefat fixed striped"><thead><tr>
                <th>' . esc_html__('Zeit', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('IP (Hash)', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('User-Agent', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Blockiert wegen', 'esherpa-login-guard') . '</th>
                </tr></thead><tbody>';
            foreach ($blocked_ua_attempts as $attempt) {
                $ip_link = add_query_arg('filter_ip_hash', urlencode($attempt->ip_hash));
                $ua_link = add_query_arg('filter_user_agent', urlencode($attempt->user_agent));
                $ua_color = !empty($attempt->user_agent) ? substr(md5($attempt->user_agent), 0, 6) : 'cccccc';
                $ua_display = !empty($attempt->user_agent) ? esc_html($attempt->user_agent) : '<em>' . esc_html__('Unbekannt', 'esherpa-login-guard') . '</em>';
                echo '<tr>
                    <td>' . esc_html(date_i18n('d.m.Y H:i:s', strtotime($attempt->timestamp))) . '</td>
                    <td><code style="background:#' . esc_attr(substr($attempt->ip_hash, 0, 6)) . '60;"><a href="' . esc_url($ip_link) . '" style="color:inherit;text-decoration:none;">' . esc_html($attempt->ip_hash) . '</a></code></td>
                    <td style="word-break:break-all;">
                        <div style="display:flex;align-items:center;gap:5px;">
                            ' . (!empty($attempt->user_agent) ? '<code style="background:#' . esc_attr($ua_color) . '20;"><a href="' . esc_url($ua_link) . '" style="color:inherit;text-decoration:none;">' . $ua_display . '</a></code>' : $ua_display) . '
                            ' . (!empty($attempt->user_agent) ? '<button class="ua-copy-btn button" data-ua="' . esc_attr($attempt->user_agent) . '" style="padding:2px 6px;font-size:11px;min-height:20px;" title="' . esc_attr__('User-Agent kopieren', 'esherpa-login-guard') . '">📋</button>' : '') . '
                        </div>
                    </td>
                    <td><code>' . esc_html($attempt->matched_pattern ?? '') . '</code></td>
                </tr>';
            }
            echo '</tbody></table>';
        }
        ?>

        <!-- FEHLVERSUCHE MIT STATUS + IP-FILTER -->
        <?php
        // Filter-Logik: Nur Einträge einer bestimmten IP oder User-Agent anzeigen
        $filter_ip_hash = sanitize_text_field($_GET['filter_ip_hash'] ?? '');
        $filter_user_agent = sanitize_text_field($_GET['filter_user_agent'] ?? '');
        $back_to_all_link = remove_query_arg(['filter_ip_hash', 'filter_user_agent']);

        if (!empty($filter_ip_hash)) {
            $failed_logins = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM $table_failed WHERE ip_hash = %s ORDER BY timestamp DESC LIMIT 150",
                $filter_ip_hash
            ));
            $total_failed = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM $table_failed WHERE ip_hash = %s",
                $filter_ip_hash
            ));
            $page_title = esc_html__('Fehlversuche für IP', 'esherpa-login-guard') . ' <code style="background:#' . esc_attr(substr(esc_html($filter_ip_hash), 0, 6)) . '60;">' . esc_html($filter_ip_hash) . '</code>';
            $page_title .= ' <a href="' . esc_url($back_to_all_link) . '" style="font-size:14px;margin-left:20px;"><p>← ' . esc_html__('Alle anzeigen', 'esherpa-login-guard') . '</p></a>';
        } elseif (!empty($filter_user_agent)) {
            $failed_logins = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM $table_failed WHERE user_agent = %s ORDER BY timestamp DESC LIMIT 150",
                $filter_user_agent
            ));
            $total_failed = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM $table_failed WHERE user_agent = %s",
                $filter_user_agent
            ));
            $ua_color = substr(md5($filter_user_agent), 0, 6);
            $ua_display = strlen($filter_user_agent) > 40 ? substr($filter_user_agent, 0, 40) . '...' : $filter_user_agent;
            $page_title = esc_html__('Fehlversuche mit User-Agent', 'esherpa-login-guard') . ' <code style="background:#' . esc_attr($ua_color) . '20;" title="' . esc_attr($filter_user_agent) . '">' . esc_html($ua_display) . '</code>';
            $page_title .= ' <a href="' . esc_url($back_to_all_link) . '" style="font-size:14px;margin-left:20px;"><p>← ' . esc_html__('Alle anzeigen', 'esherpa-login-guard') . '</p></a>';
        } else {
            $failed_logins = $wpdb->get_results("SELECT * FROM $table_failed ORDER BY timestamp DESC LIMIT 20");
            $total_failed = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_failed");
            $page_title = esc_html__('Letzte Fehlversuche mit Benutzernamen & User-Agent', 'esherpa-login-guard') . ' (' . esc_html(count($failed_logins)) . ' ' . esc_html__('von', 'esherpa-login-guard') . ' ' . esc_html($total_failed) . ')';
        }
        ?>
        <h2 style="margin-top:50px;"><?php echo wp_kses_post($page_title); ?></h2>
        <?php
        if (empty($failed_logins)) {
            echo '<p><em>' . esc_html__('Noch keine Fehlversuche aufgezeichnet.', 'esherpa-login-guard') . '</em></p>';
        } else {
            echo '<table class="wp-list-table widefat fixed striped"><thead><tr>
                <th>' . esc_html__('IP (Hash)', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Zeit', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Versuchter Benutzername', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Versuchtes Passwort', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('User-Agent', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Status', 'esherpa-login-guard') . '</th>
                </tr></thead><tbody>';
            foreach ($failed_logins as $log) {
                $ip_hash = $log->ip_hash;
                $attempt_key = 'esherpa_attempts_' . $ip_hash;
                $lockout_key = 'esherpa_lockout_' . $ip_hash;
                $count = (int) get_transient($attempt_key);
                $lockout_data = get_transient($lockout_key);

                if ($lockout_data && is_array($lockout_data) && $lockout_data['until'] > time()) {
                    $minutes_left = ceil(($lockout_data['until'] - time()) / 60);
                    $until_time = date_i18n('H:i', $lockout_data['until']);
                    $color = '#d63638';
                    $status_text = '<strong style="color:#d63638;">(' . esc_html__('GESPERRT! noch ca.', 'esherpa-login-guard') . ' ' . esc_html($minutes_left) . ' ' . esc_html__('Min', 'esherpa-login-guard') . ')</strong>';
                    $status_text .= ' <small style="color:#666;">(Multiplier: ' . esc_html($lockout_data['multiplier']) . ')</small>';
                    $remaining = 0;
                    $count_display = $current_max_attempts;
                } else {
                    $remaining = $current_max_attempts - $count;
                    $color = $remaining <= 1 ? '#d63638' : ($remaining <= 2 ? '#e67e22' : '#666');
                    $status_text = '';
                    if ($lockout_data && is_array($lockout_data)) {
                        $status_text = ' <small style="color:#666;">(Multiplier: ' . esc_html($lockout_data['multiplier']) . ')</small>';
                    }
                    $count_display = $count;
                }
                // IP als Link – filtert auf diese IP
                $ip_link = add_query_arg('filter_ip_hash', urlencode($ip_hash));

                // User-Agent vollständig anzeigen zum Kopieren für Blockliste
                $user_agent_display = !empty($log->user_agent) ? esc_html($log->user_agent) : '<em>' . esc_html__('Unbekannt', 'esherpa-login-guard') . '</em>';
                $user_agent_title = !empty($log->user_agent) ? ' title="' . esc_attr(__('Klicken zum Kopieren', 'esherpa-login-guard')) . '"' : '';
                $user_agent_color = !empty($log->user_agent) ? substr(md5($log->user_agent), 0, 6) : 'cccccc';

                // User-Agent als Link – filtert auf diesen User-Agent
                $ua_link = '';
                if (!empty($log->user_agent)) {
                    $ua_link = add_query_arg('filter_user_agent', urlencode($log->user_agent));
                }

                // BOT-Kennzeichnung für Fehlversuche
                $bot_indicator = '';
                if (!empty($log->bot_detected)) {
                    $bot_indicator = ' <span style="color:#d63638;font-weight:bold;">🤖 BOT</span>';
                }

                // Passwort-Anzeige nur bei Bots (mit Sicherheitswarnung)
                $password_display = '';
                if (!empty($log->bot_detected) && !empty($log->attempted_password)) {
                    $password_display = '<code style="background:#ffebee;color:#d63638;padding:2px 4px;border-radius:3px;font-family:monospace;" title="Bot-Passwort: ' . esc_attr($log->attempted_password) . '">' . esc_html($log->attempted_password) . '</code>';
                } elseif (!empty($log->bot_detected)) {
                    $password_display = '<em style="color:#666;font-size:11px;">leer</em>';
                } else {
                    $password_display = '<span style="color:#ccc;">–</span>';
                }

                echo '<tr>
                    <td><code style="background:#' . esc_attr(substr(esc_html($ip_hash), 0, 6)) . '60;"><a href="' . esc_url($ip_link) . '" style="color:inherit;text-decoration:none;">' . esc_html($log->ip_hash) . '</a></code>' . $bot_indicator . '</td>
                    <td>' . esc_html(date_i18n('d.m.Y H:i:s', strtotime($log->timestamp))) . '</td>
                    <td><strong>' . esc_html($log->attempted_username) . '</strong></td>
                    <td style="max-width:200px;word-break:break-all;">' . $password_display . '</td>
                    <td style="word-break:break-all;max-width:450px;">
                        <div style="display:flex;align-items:center;gap:5px;">
                            ' . (!empty($ua_link) ? '<code style="background:#' . esc_attr($user_agent_color) . '20;"><a href="' . esc_url($ua_link) . '" style="color:inherit;text-decoration:none;"' . $user_agent_title . '>' . $user_agent_display . '</a></code>' : '<code style="background:#' . esc_attr($user_agent_color) . '20;"' . $user_agent_title . '>' . $user_agent_display . '</code>') . '
                            <button class="ua-copy-btn button" data-ua="' . esc_attr($user_agent_display) . '" style="padding:2px 6px;font-size:11px;min-height:20px;" title="' . esc_attr__('User-Agent kopieren', 'esherpa-login-guard') . '">📋</button>
                        </div>
                    </td>
                    <td><strong style="color:' . esc_attr($color) . ';">' . esc_html($count_display) . ' / ' . esc_html($current_max_attempts) . '</strong> (' .
                    esc_html(sprintf(_n('noch %d möglich', 'noch %d möglich', $remaining, 'esherpa-login-guard'), $remaining)) . ')<br>' . wp_kses_post($status_text) . '</td>
                </tr>';
            }
            echo '</tbody></table>';
        }
        ?>

<!-- ERFOLGREICHE LOGINS -->
        <?php
        // Filter-Logik für erfolgreiche Logins
        $filter_successful_ip = sanitize_text_field($_GET['filter_successful_ip'] ?? '');
        $filter_successful_ua = sanitize_text_field($_GET['filter_successful_ua'] ?? '');
        $back_to_all_successful = remove_query_arg(['filter_successful_ip', 'filter_successful_ua']);

        if (!empty($filter_successful_ip)) {
            $successful_logins = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM $table_successful WHERE ip_hash = %s ORDER BY timestamp DESC LIMIT 150",
                $filter_successful_ip
            ));
            $total_successful = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM $table_successful WHERE ip_hash = %s",
                $filter_successful_ip
            ));
            $successful_title = esc_html__('Erfolgreiche Logins für IP', 'esherpa-login-guard') . ' <code style="background:#' . esc_attr(substr(esc_html($filter_successful_ip), 0, 6)) . '60;">' . esc_html($filter_successful_ip) . '</code>';
            $successful_title .= ' <a href="' . esc_url($back_to_all_successful) . '" style="font-size:14px;margin-left:20px;"><p>← ' . esc_html__('Alle anzeigen', 'esherpa-login-guard') . '</p></a>';
        } elseif (!empty($filter_successful_ua)) {
            $successful_logins = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM $table_successful WHERE user_agent = %s ORDER BY timestamp DESC LIMIT 150",
                $filter_successful_ua
            ));
            $total_successful = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM $table_successful WHERE user_agent = %s",
                $filter_successful_ua
            ));
            $ua_color = substr(md5($filter_successful_ua), 0, 6);
            $ua_display = strlen($filter_successful_ua) > 40 ? substr($filter_successful_ua, 0, 40) . '...' : $filter_successful_ua;
            $successful_title = esc_html__('Erfolgreiche Logins mit User-Agent', 'esherpa-login-guard') . ' <code style="background:#' . esc_attr($ua_color) . '20;" title="' . esc_attr($filter_successful_ua) . '">' . esc_html($ua_display) . '</code>';
            $successful_title .= ' <a href="' . esc_url($back_to_all_successful) . '" style="font-size:14px;margin-left:20px;"><p>← ' . esc_html__('Alle anzeigen', 'esherpa-login-guard') . '</p></a>';
        } else {
            $successful_logins = $wpdb->get_results("SELECT * FROM $table_successful ORDER BY timestamp DESC LIMIT 20");
            $total_successful = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_successful");
            $successful_title = esc_html__('Erfolgreiche Logins/Logouts & User-Agent', 'esherpa-login-guard') . ' (' . esc_html(count($successful_logins)) . ' ' . esc_html__('von', 'esherpa-login-guard') . ' ' . esc_html($total_successful) . ')';
        }
        ?>
        <h2 style="margin-top:50px;"><?php echo $successful_title; ?></h2>
        <?php
        if (empty($successful_logins)) {
            echo '<p><em>' . esc_html__('Noch keine erfolgreichen Logins aufgezeichnet.', 'esherpa-login-guard') . '</em></p>';
        } else {
            echo '<table class="wp-list-table widefat fixed striped"><thead><tr>
                <th>' . esc_html__('IP (Hash)', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Zeit', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('Benutzername', 'esherpa-login-guard') . '</th>
                <th>' . esc_html__('User-Agent', 'esherpa-login-guard') . '</th>
                </tr></thead><tbody>';
            foreach ($successful_logins as $log) {
                // Unterscheiden: (LOGIN) = grün, (LOGOUT) = blau
                $is_logout = strpos($log->username, ' (LOGOUT)') !== false;
                $bg_color = $is_logout ? '#e3f2fd' : '#e8f5e9'; // blau für Logout, grün für Login
                $ip_link = add_query_arg('filter_successful_ip', urlencode($log->ip_hash));

                $user_agent_display = !empty($log->user_agent) ? esc_html(substr($log->user_agent, 0, 100)) . (strlen($log->user_agent) > 100 ? '...' : '') : '<em>' . esc_html__('Unbekannt', 'esherpa-login-guard') . '</em>';
                $user_agent_title = !empty($log->user_agent) ? ' title="' . esc_attr($log->user_agent) . '"' : '';
                $user_agent_color = !empty($log->user_agent) ? substr(md5($log->user_agent), 0, 6) : 'cccccc';

                // User-Agent als Link – filtert auf diesen User-Agent
                $ua_link = '';
                if (!empty($log->user_agent)) {
                    $ua_link = add_query_arg('filter_successful_ua', urlencode($log->user_agent));
                }

                echo '<tr style="background:' . esc_attr($bg_color) . ';">
                    <td><code style="background:#' . esc_html(substr($log->ip_hash, 0, 6)) . '60;"><a href="' . esc_url($ip_link) . '" style="color:inherit;text-decoration:none;">' . esc_html($log->ip_hash) . '</a></code></td>
                    <td>' . esc_html(date_i18n('d.m.Y H:i:s', strtotime($log->timestamp))) . '</td>
                    <td><strong>' . esc_html($log->username) . '</strong></td>
                    <td>' . (!empty($ua_link) ? '<code style="background:#' . esc_attr($user_agent_color) . '20;"><a href="' . esc_url($ua_link) . '" style="color:inherit;text-decoration:none;"' . $user_agent_title . '><small>' . $user_agent_display . '</small></a></code>' : '<code style="background:#' . esc_attr($user_agent_color) . '20;"><small' . $user_agent_title . '>' . $user_agent_display . '</small></code>') . '</td>
                </tr>';
            }
            echo '</tbody></table>';
        }
        ?>

<!-- Erklärung zum Plugin -->
        <div style="background:#f0f8ff;padding:25px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.08);margin:40px 0;">
            <h2 style="margin-top:0;color:#2271b1;border-bottom:2px solid #2271b1;padding-bottom:8px;">
                <?php echo esc_html__('Wie funktioniert eSherpa Login Guard?', 'esherpa-login-guard'); ?>
            </h2>
            <p><?php echo esc_html__('Das Plugin schützt deine WordPress-Installation vor Brute-Force-Angriffen durch progressive Sperrzeiten.', 'esherpa-login-guard'); ?></p>
            <ul style="line-height:1.8;">
                <li><?php echo esc_html__('Bei jedem falschen Login wird ein Zähler für die IP erhöht und der versuchte Benutzername gespeichert.', 'esherpa-login-guard'); ?></li>
                <li>
                <!-- translators: %s = number of failed attempts-->
                <?php echo sprintf(esc_html__('Nach %s Fehlversuchen wird die IP gesperrt.', 'esherpa-login-guard'), '<strong>' . esc_html($current_max_attempts) . '</strong>'); ?></li>
                <li><?php echo esc_html__('Die erste Sperre dauert die eingestellte Basiszeit.', 'esherpa-login-guard'); ?></li>
                <li><?php echo esc_html__('Bei jedem weiteren Verstoß verdoppelt sich die Sperrzeit (15 → 30 → 60 → 120 Min usw.).', 'esherpa-login-guard'); ?></li>
                <li><?php echo esc_html__('Der Fehlversuch-Zähler bleibt bis zu 1 Woche aktiv – danach wird er automatisch zurückgesetzt.', 'esherpa-login-guard'); ?></li>
                <li><?php echo esc_html__('Bei erfolgreichem Login werden Zähler und Sperre für die IP sofort gelöscht.', 'esherpa-login-guard'); ?></li>
                <li><?php echo esc_html__('Du kannst gesperrte IPs manuell entsperren – der Zähler wird dabei zurückgesetzt.', 'esherpa-login-guard'); ?></li>
                <li><?php echo esc_html__('IPs werden nur als anonymisierter Hash gespeichert – datenschutzkonform.', 'esherpa-login-guard'); ?></li>
                <li><?php echo esc_html__('XML-RPC ist deaktiviert – verhindert Brute-Force-Angriffe über diese Schnittstelle (z. B. von Bots oder Apps).', 'esherpa-login-guard'); ?></li>
                <li><?php echo esc_html__('Die REST API User-Liste ist blockiert – Angreifer können keine Benutzernamen mehr automatisch auslesen.', 'esherpa-login-guard'); ?></li>
                <li><?php echo esc_html__('Author-Archive (?author=1) werden umgeleitet – verhindert Username-Enumeration über URL-Parameter.', 'esherpa-login-guard'); ?></li>
            </ul>
            <!-- NEU: Hervorgehobener Tipp zu Username + Passwort -->
            <div style="margin-top:30px;padding:20px;background:#fff3e0;border-left:6px solid #ff9800;border-radius:8px;">
                <p style="margin:0;font-size:16px;font-weight:bold;color:#e65100;">
                    <?php echo esc_html__('Tipp für maximale Sicherheit:', 'esherpa-login-guard'); ?>
                </p>
                <p style="margin:8px 0 0;font-size:15px;color:#333;">
                    <?php echo esc_html__('Wähle einen einzigartigen Benutzernamen (kein „admin“, „test“, „root“ oder Begriffe die aus dem Content erraten werden könnten) und ein starkes Passwort!', 'esherpa-login-guard'); ?><br>
                    <?php echo esc_html__('So machst du es Angreifern extrem schwer!', 'esherpa-login-guard'); ?><br>
                    <?php echo esc_html__('Wenn du XML_RPC nicht unbedingt benötigst, ist es ratsam es abzuschalten -> halb so viele Angriffe.', 'esherpa-login-guard'); ?>
                </p>
            </div>
        </div>

<!-- EINSTELLUNGEN -->
        <div style="background:#fff;padding:25px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.08);margin:30px 0;">
            <h2 style="margin-top:0;color:#2271b1;border-bottom:2px solid #2271b1;padding-bottom:8px;"><?php echo esc_html__('Einstellungen', 'esherpa-login-guard'); ?></h2>
            <form method="post">
                <?php wp_nonce_field('esherpa_login_guard_settings'); ?>
                <table class="form-table" style="max-width:600px;">
                    <tr>
                        <th><label for="max_attempts"><?php echo esc_html__('Maximale Fehlversuche', 'esherpa-login-guard'); ?></label></th>
                        <td>
                            <input name="max_attempts" type="number" id="max_attempts" value="<?php echo esc_attr($current_max_attempts); ?>" class="small-text" min="1" max="50" required>
                            <p class="description"><?php echo esc_html__('Nach wie vielen falschen Logins wird die IP gesperrt? (Standard: 5)', 'esherpa-login-guard'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="base_minutes"><?php echo esc_html__('Erste Sperrzeit in Minuten', 'esherpa-login-guard'); ?></label></th>
                        <td>
                            <input name="base_minutes" type="number" id="base_minutes" value="<?php echo esc_attr($current_base_minutes); ?>" class="small-text" min="1" max="1440" required>
                            <p class="description"><?php echo esc_html__('Basisdauer der ersten Sperre. Wird bei jedem weiteren Verstoß verdoppelt. (Standard: 15)', 'esherpa-login-guard'); ?></p>
                        </td>
                    </tr>
                </table>
				<h3 style="margin-top:40px;color:#2271b1;"><?php echo esc_html__('Sofortsperre für geschützte Benutzernamen', 'esherpa-login-guard'); ?></h3>
				<table class="form-table" style="max-width:600px;">
				    <tr>
				        <th><label for="protected_usernames"><?php echo esc_html__('Geschützte Benutzernamen (einer pro Zeile)', 'esherpa-login-guard'); ?></label></th>
				        <td>
				            <textarea name="protected_usernames" id="protected_usernames" rows="6" class="large-text" placeholder="z.B. admin&#10;z.B. root&#10;z.B. test"><?php echo esc_textarea(get_option('esherpa_login_guard_protected_usernames', "")); ?></textarea>
				            <p class="description"><?php echo esc_html__('Bei einem Fehlversuch mit einem dieser Namen wird die IP sofort für 1 Stunde gesperrt – unabhängig von der normalen Zählung.', 'esherpa-login-guard'); ?></p>
				        </td>
				    </tr>
				</table>
				<h3 style="margin-top:40px;color:#2271b1;"><?php echo esc_html__('Geblockte User-Agents (proaktive Sperre)', 'esherpa-login-guard'); ?></h3>
				<table class="form-table" style="max-width:600px;">
				    <tr>
				        <th><label for="blocked_user_agents"><?php echo esc_html__('User-Agents blockieren (einer pro Zeile)', 'esherpa-login-guard'); ?></label></th>
				        <td>
				            <textarea name="blocked_user_agents" id="blocked_user_agents" rows="6" class="large-text" placeholder="z.B. curl/7.68.0&#10;z.B. python-requests/2.28.0"><?php echo esc_textarea(get_option('esherpa_login_guard_blocked_user_agents', '')); ?></textarea>
				            <p class="description">
				                <?php echo esc_html__('Diese User-Agents werden bereits beim Aufruf der Login-Seite blockiert – sie können keinen Login-Versuch starten.', 'esherpa-login-guard'); ?><br>
				                <?php
				                $exact_match = get_option('esherpa_login_guard_exact_user_agent_match', '0') === '1';
				                if ($exact_match) {
				                    echo esc_html__('Modus: Exakte Übereinstimmung (User-Agent muss genau übereinstimmen).', 'esherpa-login-guard');
				                } else {
				                    echo esc_html__('Modus: Teilstring-Übereinstimmung (z.B. "curl" blockiert alle curl-Anfragen).', 'esherpa-login-guard');
				                }
				                ?><br>
				                <?php echo esc_html__('User-Agent aus der Fehlversuch-Liste kopieren.', 'esherpa-login-guard'); ?>
				            </p>
				        </td>
				    </tr>
				    <tr>
				        <th><?php echo esc_html__('Übereinstimmungsmodus', 'esherpa-login-guard'); ?></th>
				        <td>
				            <label><input type="checkbox" name="exact_user_agent_match" value="1" <?php checked(get_option('esherpa_login_guard_exact_user_agent_match', '0'), '1'); ?>>
				                <?php echo esc_html__('Exakte User-Agent-Übereinstimmung verwenden (anstatt Teilstring)', 'esherpa-login-guard'); ?>
				            </label>
				            <p class="description"><?php echo esc_html__('Wenn aktiviert: User-Agent muss exakt mit dem Eintrag übereinstimmen. Wenn deaktiviert: Teilstring-Übereinstimmung (Standard).', 'esherpa-login-guard'); ?></p>
				        </td>
				    </tr>
				</table>
				<h3 style="margin-top:40px;color:#2271b1;"><?php echo esc_html__('Bot-Passwort-Erfassung', 'esherpa-login-guard'); ?></h3>
				<table class="form-table" style="max-width:600px;">
				    <tr>
				        <th><label><?php echo esc_html__('Passwörter von Bots erfassen', 'esherpa-login-guard'); ?></label></th>
				        <td>
				            <label><input type="checkbox" name="enable_bot_password_logging" value="1" <?php checked(get_option('esherpa_login_guard_enable_bot_password_logging', '0'), '1'); ?>>
				                <?php echo esc_html__('Passwörter von erkannten Bots (JS-Honeypot) in der Fehlversuch-Tabelle anzeigen', 'esherpa-login-guard'); ?>
				            </label>
				            <p class="description"><?php echo esc_html__('Zeigt die von Bots verwendeten Passwörter in der Fehlversuch-Tabelle an (nur bei sicher erkannten Bots). Hilft bei der Analyse von Angriffsmustern.', 'esherpa-login-guard'); ?></p>
				        </td>
				    </tr>
				</table>
				<h3 style="margin-top:40px;color:#2271b1;"><?php echo esc_html__('Bot-Erkennung & Honeypot', 'esherpa-login-guard'); ?></h3>
				<table class="form-table" style="max-width:600px;">
				    <tr>
				        <th><label><?php echo esc_html__('JavaScript-Honeypot aktivieren', 'esherpa-login-guard'); ?></label></th>
				        <td>
				            <label><input type="checkbox" name="enable_js_honeypot" value="1" <?php checked(get_option('esherpa_login_guard_enable_js_honeypot', '1'), '1'); ?>>
				                <?php echo esc_html__('Verstecktes JS-Feld zum Bot-Schutz hinzufügen (empfohlen)', 'esherpa-login-guard'); ?>
				            </label>
				            <p class="description"><?php echo esc_html__('Bots ohne JavaScript-Unterstützung werden wie Angriffe auf geschützte Usernamen behandelt (sofortige Sperre mit progressiver Verlängerung).', 'esherpa-login-guard'); ?></p>
				        </td>
				    </tr>
				    <tr>
				        <th><label><?php echo esc_html__('XML-RPC deaktivieren', 'esherpa-login-guard'); ?></label></th>
				        <td>
				            <label><input type="checkbox" name="disable_xmlrpc" value="1" <?php checked($disable_xmlrpc); ?>>
				                <?php echo esc_html__('XML-RPC komplett abschalten (verhindert viele Brute-Force-Angriffe)', 'esherpa-login-guard'); ?>
				            </label>
				            <p class="description"><?php echo esc_html__('Wenn aktiviert, wird eine gefälschte XML-RPC-Antwort mit den unten definierten Fake-Usern ausgegeben (Honeypot).', 'esherpa-login-guard'); ?></p>
				        </td>
				    </tr>
				    <tr>
				        <th><label for="xmlrpc_fake_users"><?php echo esc_html__('Fake-User für XML-RPC-Honeypot', 'esherpa-login-guard'); ?></label></th>
				        <td>
				            <textarea name="xmlrpc_fake_users" id="xmlrpc_fake_users" rows="6" class="large-text"><?php echo esc_textarea(get_option('esherpa_login_guard_xmlrpc_fake_users', "admin\nadministrator\nroot\ntest\nsupport\nwebmaster")); ?></textarea>
				            <p class="description"><?php echo esc_html__('Einer pro Zeile. Diese Usernamen werden in der gefälschten XML-RPC-Antwort angezeigt, wenn XML-RPC deaktiviert ist. Angreifer versuchen diese – und landen sofort in deiner Sperre.', 'esherpa-login-guard'); ?> <strong style="color:red;"><?php echo esc_html__('Keine existierende Usernamen eintragen!', 'esherpa-login-guard'); ?></strong></p>
				        </td>
				    </tr>
				    <tr>
				        <th><label><?php echo esc_html__('REST API User-Liste blocken', 'esherpa-login-guard'); ?></label></th>
				        <td>
				            <label><input type="checkbox" name="disable_rest_users" value="1" <?php checked($disable_rest_users); ?>>
				                <?php echo esc_html__('/wp-json/wp/v2/users verstecken (verhindert Username-Enumeration)', 'esherpa-login-guard'); ?>
				            </label>
				        </td>
				    </tr>
				    <tr>
				        <th><label><?php echo esc_html__('Author-Archive blocken', 'esherpa-login-guard'); ?></label></th>
				        <td>
				            <label><input type="checkbox" name="block_author_archive" value="1" <?php checked($block_author_archive); ?>>
				                <?php echo esc_html__('?author=1 usw. umleiten (verhindert Username-Enumeration über URL)', 'esherpa-login-guard'); ?>
				            </label>
				        </td>
				    </tr>
				    <tr>
				    <th><label><?php echo esc_html__('Neutrale Fehlermeldung im WP-Login', 'esherpa-login-guard'); ?></label></th>
				    <td>
				        <label><input type="checkbox" name="esherpa_login_guard_neutral_wp_login_error" value="1" <?php checked(get_option('esherpa_login_guard_neutral_wp_login_error'), '1'); ?>>
				            <?php echo esc_html__('Alle Fehlermeldungen im normalen WP-Login (wp-login.php) durch "Ungültige Anmeldedaten." ersetzen', 'esherpa-login-guard'); ?>
				        </label>
				        <p class="description"><?php echo esc_html__('Verhindert, dass Angreifer zwischen "User existiert nicht" und "Falsches Passwort" unterscheiden können (Enumeration-Schutz).', 'esherpa-login-guard'); ?></p>
				    </td>
					</tr>
				</table>
				<h3 style="margin-top:40px;color:#2271b1;"><?php echo esc_html__('Datenbereinigung', 'esherpa-login-guard'); ?></h3>
				<table class="form-table" style="max-width:600px;">
				    <tr>
				        <th><label for="cleanup_days"><?php echo esc_html__('Fehlversuche nach wie vielen Tagen löschen?', 'esherpa-login-guard'); ?></label></th>
				        <td>
				            <input name="cleanup_days" type="number" id="cleanup_days" value="<?php echo esc_attr(get_option('esherpa_login_guard_cleanup_days', 7)); ?>" class="small-text" min="1" max="365" required>
				            <p class="description"><?php echo esc_html__('Ältere Einträge werden täglich automatisch gelöscht (Datenschutz & Performance). Standard: 7 Tage', 'esherpa-login-guard'); ?></p>
				        </td>
				    </tr>
				</table>
                <p>
                    <button type="submit" name="save_login_guard_settings" class="button button-primary" style="padding:8px 30px;font-size:15px;">
                        <?php echo esc_html__('Einstellungen speichern', 'esherpa-login-guard'); ?>
                    </button>
                </p>
            </form>
        </div>
    </div><!--endwrap-->
    <?php
}

// ====================================================================
// 8. AUTOMATISCHE FEHLERMELDUNG – DIREKT ÜBER DEM FORMULAR
// ====================================================================
// Entferne alte Footer-Hooks (falls noch da)
remove_action('wp_footer', 'esherpa_guard_show_message_everywhere');
remove_action('login_footer', 'esherpa_guard_show_message_everywhere');

// NEU: Meldung nur auf anderen Seiten mit Passwort-Feld ausgeben (nicht WP-Login, nicht eSherpa-Login)
add_filter('the_content', 'esherpa_guard_insert_message_other_forms', 999);
function esherpa_guard_insert_message_other_forms($content) {
    // Nicht auf wp-login.php
    if (isset($GLOBALS['pagenow']) && $GLOBALS['pagenow'] === 'wp-login.php') {
        return $content;
    }

    // Nicht auf Seiten mit eSherpa-Login-Shortcode
    global $post;
    if ($post && has_shortcode($post->post_content, 'esherpa_register_login')) {
        return $content;
    }

    // Nur auf anderen Seiten mit Passwort-Feld (z. B. andere Custom-Forms)
    $has_password_field = strpos($content, 'type="password"') !== false ||
                          strpos($content, 'name="pwd"') !== false ||
                          strpos($content, 'name="password"') !== false;

    if (!$has_password_field) {
        return $content;
    }

    ob_start();
    esherpa_render_guard_message_direct();
    $message = ob_get_clean();

    if ($message) {
        $content .= $message; // unter dem Formular
    }

    return $content;
}

// Für wp-login.php (falls gewünscht)
add_action('login_form', 'esherpa_guard_show_message_on_wplogin');
function esherpa_guard_show_message_on_wplogin() {
    if (is_admin() || !isset($GLOBALS['pagenow']) || $GLOBALS['pagenow'] !== 'wp-login.php') return;
    esherpa_render_guard_message_direct();
}

// Render-Funktion (direkt ausgeben)
function esherpa_render_guard_message_direct() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $lockout_key = 'esherpa_lockout_' . md5($ip);
    $attempt_key = 'esherpa_attempts_' . md5($ip);
    $locked = get_transient($lockout_key);
    $attempts = (int) get_transient($attempt_key);
    $max = max(1, intval(get_option('esherpa_login_guard_max_attempts', 5)));

    $output = '';
    if ($locked && $locked['until'] > time()) {
        $minutes = ceil(($locked['until'] - time()) / 60);
        $output = '<div style="background:#ffebee;padding:24px;border-radius:16px;border-left:8px solid #d63638;color:#721c24;text-align:center;font-weight:bold;margin:30px auto;max-width:500px;box-shadow:0 8px 30px rgba(214,54,56,0.2);font-family:system-ui;">
            <p style="margin:0 0 14px;font-size:26px;">' . esc_html__('Zugriff gesperrt', 'esherpa-login-guard') . '</p>
            <p style="margin:0;font-size:52px;color:#d63638;line-height:1;">' . esc_html($minutes) . ' Min</p>
            <p style="margin:12px 0 0;font-size:17px;">
            ' . sprintf(esc_html__('Warte noch %s.', 'esherpa-login-guard'), '<strong>' . esc_html($minutes) . ' Minuten</strong>') . '<br>
            <small>' . esc_html__('Danach kannst du es erneut versuchen.', 'esherpa-login-guard') . '</small></p>
            <hr style="margin:15px 0 10px;border:none;border-top:1px solid #ddd;">
            <small style="color:#666;font-style:italic;">
            ' . sprintf(esc_html__('Geschützt von %s', 'esherpa-login-guard'), '<a href="https://esherpa.ch/login-guard" target="_blank" style="color:#2271b1;text-decoration:none;">eSherpa Login Guard</a>') . '</small> </div>
         ';
    } elseif ($attempts > 0) {
        $remaining = $max - $attempts;
        $color = $remaining <= 1 ? '#d63638' : '#e67e22';
        $output = '<div style="background:#fff8e1;padding:20px;border-radius:12px;border-left:6px solid ' . esc_attr($color) . ';color:#333;text-align:center;margin:25px auto;max-width:500px;font-size:16px;">
            <strong>' . esc_html__('Login-Hinweis:', 'esherpa-login-guard') . '</strong><br>
            ' . sprintf(esc_html__('Du hast %s.', 'esherpa-login-guard'), '<strong>' . sprintf(_n('%d Fehlversuch', '%d Fehlversuche', $attempts, 'esherpa-login-guard'), $attempts) . '</strong>') . '<br>
            ' . '<strong style="color:' . esc_attr($color) . ';font-size:24px;">' .
            sprintf(_n('%d Versuch verfügbar', '%d Versuche verfügbar', $remaining, 'esherpa-login-guard'), $remaining) . '</strong><br>
            <hr style="margin:15px 0 10px;border:none;border-top:1px solid #ddd;">
            <small style="color:#666;font-style:italic;">
            ' . sprintf(esc_html__('Geschützt von %s', 'esherpa-login-guard'), '<a href="https://esherpa.ch/login-guard" target="_blank" style="color:#2271b1;text-decoration:none;">eSherpa Login Guard</a>') . '</small> </div>';
    }

    if ($output) {
        echo $output;
    }
}

// ====================================================================
// 9. AUTOMATISCHE BEREINIGUNG DER TABELLEN PER CRON
// ====================================================================

// Option für Bereinigungsdauer (Standard: 7 Tage)
if (false === get_option('esherpa_login_guard_cleanup_days')) {
    update_option('esherpa_login_guard_cleanup_days', 7);
}

// Cron-Job registrieren (täglich)
register_activation_hook(__FILE__, 'esherpa_login_guard_schedule_cleanup');
function esherpa_login_guard_schedule_cleanup() {
    if (!wp_next_scheduled('esherpa_login_guard_cleanup_event')) {
        wp_schedule_event(time(), 'daily', 'esherpa_login_guard_cleanup_event');
    }
}

register_deactivation_hook(__FILE__, 'esherpa_login_guard_unschedule_cleanup');
function esherpa_login_guard_unschedule_cleanup() {
    wp_clear_scheduled_hook('esherpa_login_guard_cleanup_event'); // sicherer – löscht alle Instanzen
}

// Cron-Event: Alte Einträge löschen
add_action('esherpa_login_guard_cleanup_event', 'esherpa_login_guard_cleanup_old_logins');
function esherpa_login_guard_cleanup_old_logins() {
    global $wpdb;
    $days = max(1, intval(get_option('esherpa_login_guard_cleanup_days', 7)));

    // Failed Logins bereinigen
    $table_failed = $wpdb->prefix . 'esherpa_failed_logins';
    $wpdb->query($wpdb->prepare(
        "DELETE FROM $table_failed WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
        $days
    ));

    // Successful Logins bereinigen
    $table_successful = $wpdb->prefix . 'esherpa_successful_logins';
    $wpdb->query($wpdb->prepare(
        "DELETE FROM $table_successful WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
        $days
    ));

    // Blocked User-Agent Versuche bereinigen
    $table_blocked_ua = $wpdb->prefix . 'esherpa_blocked_ua_attempts';
    $wpdb->query($wpdb->prepare(
        "DELETE FROM $table_blocked_ua WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
        $days
    ));
}

add_action('plugins_loaded', 'esherpa_login_guard_ensure_cleanup_cron');
add_action('plugins_loaded', 'esherpa_login_guard_check_and_upgrade_tables');
add_action('plugins_loaded', 'esherpa_login_guard_load_textdomain');
function esherpa_login_guard_ensure_cleanup_cron() {
    if (!wp_next_scheduled('esherpa_login_guard_cleanup_event')) {
        wp_schedule_event(time(), 'daily', 'esherpa_login_guard_cleanup_event');
    }
}

function esherpa_login_guard_check_and_upgrade_tables() {
    global $wpdb;

    // Prüfe ob alle Tabellen existieren und aktualisiere Schema falls nötig
    $required_tables = [
        $wpdb->prefix . 'esherpa_failed_logins',
        $wpdb->prefix . 'esherpa_successful_logins',
        $wpdb->prefix . 'esherpa_blocked_ua_attempts'
    ];

    $missing_tables = false;
    foreach ($required_tables as $table_name) {
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") !== $table_name) {
            $missing_tables = true;
            break;
        }
    }

    // Wenn Tabellen fehlen oder Schema-Update nötig ist, führe Upgrade durch
    if ($missing_tables) {
        esherpa_login_guard_upgrade_tables();
    } else {
        // Selbst bei vorhandenen Tabellen: Schema mit dbDelta aktualisieren
        // (fügt fehlende Spalten hinzu, ändert nichts bei bestehenden)
        esherpa_login_guard_upgrade_tables();
    }
}

function esherpa_login_guard_load_textdomain() {
    $loaded = load_plugin_textdomain(
        'esherpa-login-guard',
        false,
        dirname(plugin_basename(__FILE__)) . '/languages/'
    );

    // Fallback: Wenn keine .mo-Dateien vorhanden sind, lade .po-Dateien direkt
    if (!$loaded) {
        esherpa_login_guard_load_po_fallback();
    }
}

function esherpa_login_guard_load_po_fallback() {
    $locale = get_locale();

    // Integrierte Übersetzungen als Fallback
    $fallback_translations = esherpa_get_fallback_translations($locale);

    if (!empty($fallback_translations)) {
        global $esherpa_translations;
        $esherpa_translations = $fallback_translations;
    }

    // Versuche auch PO-Datei zu laden (falls vorhanden)
    $po_file = plugin_dir_path(__FILE__) . 'languages/esherpa-login-guard-' . $locale . '.po';
    if (file_exists($po_file)) {
        $po_translations = esherpa_parse_po_file($po_file);
        if (!empty($po_translations)) {
            global $esherpa_translations;
            $esherpa_translations = array_merge($esherpa_translations ?: [], $po_translations);
        }
    }
}

function esherpa_get_fallback_translations($locale) {
    $translations = [];

    if ($locale === 'it_IT') {
        $translations = [
            // Wichtige Admin-Interface-Strings
            'eSherpa Login Guard' => 'eSherpa Login Guard',
            'Login Guard' => 'Login Guard',
            'Einstellungen' => 'Impostazioni',
            'Einstellungen speichern' => 'Salva impostazioni',
            'Aktuell gesperrte IPs' => 'IP attualmente bloccati',
            'Geblockte User-Agents' => 'User-Agent bloccati',
            'Letzte Fehlversuche mit Benutzernamen & User-Agent' => 'Ultimi tentativi falliti con nome utente & User-Agent',
            'Letzte blockierte User-Agent-Versuche' => 'Ultimi tentativi di User-Agent bloccati',
            'Status' => 'Stato',
            'Aktion' => 'Azione',
            'Entsperren' => 'Sbloccare',
            'Entsperrt in' => 'Sbloccato tra',
            'Dauer' => 'Durata',
            'Benutzername' => 'Nome utente',
            'User-Agent' => 'User-Agent',
            'Zeit' => 'Ora',
            'IP (Hash)' => 'IP (Hash)',
            'Versuchter Benutzername' => 'Nome utente tentato',
            'Versuchtes Passwort' => 'Password tentata',
            'Blockiert wegen' => 'Bloccato a causa di',

            // E-Mail-Strings
            'Hallo Admin,' => 'Ciao Admin,',
            'Brute-Force-Angriff: Existierender Benutzer attackiert!' => 'Attacco Brute-Force: Utente esistente attaccato!',
            'Der Login Guard hat einen Angriff auf einen existierenden Benutzer erkannt und die IP sofort gesperrt.' => 'Il Login Guard ha rilevato un attacco su un utente esistente e ha bloccato immediatamente l\'IP.',
            'IP-Adresse des Angreifers:' => 'Indirizzo IP dell\'attaccante:',
            'Betroffener Benutzername:' => 'Nome utente interessato:',
            'E-Mail des Betroffenen:' => 'E-mail dell\'interessato:',
            'Rolle(n) des Betroffenen:' => 'Ruolo(i) dell\'interessato:',
            'Zeitpunkt:' => 'Momento:',
            'Was solltest du nun tun?' => 'Cosa dovresti fare ora?',
            'Keine Panik!' => 'Nessun panico!',

            // Bot-Detection
            'Bot-Erkennung & Honeypot' => 'Rilevamento bot & Honeypot',
            'Bot-Passwort-Erfassung' => 'Acquisizione password bot',
            'JavaScript-Honeypot aktivieren' => 'Attiva honeypot JavaScript',
            'Passwörter von Bots erfassen' => 'Acquisisci password dei bot',

            // User-Agent-Blocking
            'Geblockte User-Agents (proaktive Sperre)' => 'User-Agent bloccati (blocco proattivo)',
            'User-Agents blockieren (einer pro Zeile)' => 'Blocca User-Agent (uno per riga)',
            'Exakte User-Agent-Übereinstimmung verwenden (anstatt Teilstring)' => 'Utilizzare la corrispondenza esatta dell\'User-Agent (invece della sottostringa)',
            'Modus: Exakte Übereinstimmung (User-Agent muss genau übereinstimmen).' => 'Modalità: Corrispondenza esatta (l\'User-Agent deve corrispondere esattamente).',
            'Modus: Teilstring-Übereinstimmung (z.B. \"curl\" blockiert alle curl-Anfragen).' => 'Modalità: Corrispondenza sottostringa (ad es. \"curl\" blocca tutte le richieste curl).',
            'User-Agent aus der Fehlversuch-Liste kopieren.' => 'Copia l\'User-Agent dall\'elenco dei tentativi falliti.',
            'User-Agent kopieren' => 'Copia User-Agent',
            'Klicken zum Kopieren' => 'Clicca per copiare',

            // Datenbereinigung
            'Datenbereinigung' => 'Pulizia dei dati',
            'Fehlversuche nach wie vielen Tagen löschen?' => 'Cancellare i tentativi falliti dopo quanti giorni?',

            // Maximale Versuche
            'Maximale Fehlversuche' => 'Numero massimo di tentativi falliti',
            'Nach wie vielen falschen Logins wird die IP gesperrt? (Standard: 5)' => 'Dopo quanti login errati l\'IP deve essere bloccata? (Predefinito: 5)',

            // Sperrzeiten
            'Erste Sperrzeit in Minuten' => 'Durata iniziale del blocco in minuti',
            'Bei einem Fehlversuch mit einem dieser Namen wird die IP sofort für 1 Stunde gesperrt – unabhängig von der normalen Zählung.' => 'In caso di tentativo fallito con uno di questi nomi, l\'IP viene immediatamente bloccata per 1 ora – indipendentemente dal conteggio normale.',
            'Bei jedem weiteren Verstoß verdoppelt sich die Sperrzeit (15 → 30 → 60 → 120 Min usw.).' => 'Ad ogni infrazione successiva, il tempo di blocco raddoppia (15 → 30 → 60 → 120 minuti, ecc.).',

            // Sofort sperren
            'Geschützte Benutzernamen (einer pro Zeile)' => 'Nomi utente protetti (uno per riga)',
            'Sofortsperre für geschützte Benutzernamen' => 'Blocco immediato per nomi utente protetti',

            // XML-RPC
            'XML-RPC deaktivieren' => 'Disattiva XML-RPC',
            'XML-RPC komplett abschalten (verhindert viele Brute-Force-Angriffe)' => 'Disattiva completamente XML-RPC (previene molti attacchi brute-force)',
            'Wenn aktiviert, wird eine gefälschte XML-RPC-Antwort mit den unten definierten Fake-Usern ausgegeben (Honeypot).' => 'Quando attivato, verrà restituita una risposta XML-RPC falsificata con i fake user definiti sotto (honeypot).',
            'Fake-User für XML-RPC-Honeypot' => 'Utenti fake per honeypot XML-RPC',
            'Einer pro Zeile. Diese Usernamen werden in der gefälschten XML-RPC-Antwort angezeigt, wenn XML-RPC deaktiviert ist. Angreifer versuchen diese – und landen sofort in deiner Sperre.' => 'Uno per riga. Questi nomi utente vengono visualizzati nella risposta XML-RPC falsificata quando XML-RPC è disattivato. Gli attaccanti provano questi – e atterrano immediatamente nel tuo blocco.',

            // Login-Hinweis
            'Login-Hinweis:' => 'Suggerimento per il login:',
            'Du hast %s.' => 'Hai %s.',
            'Noch %s warten.' => 'Attendi ancora %s.',
            'Warte noch %s.' => 'Aspetta ancora %s.',

            // WP-Login Anpassungen
            'REST API User-Liste blocken' => 'Blocca lista utenti API REST',
            'Author-Archive blocken' => 'Blocca archivi autore',
            'Neutrale Fehlermeldung im WP-Login' => 'Messaggio di errore neutro nel login WP',
            'Alle Fehlermeldungen im normalen WP-Login (wp-login.php) durch \"Ungültige Anmeldedaten.\" ersetzen' => 'Sostituisci tutti i messaggi di errore nel login WP standard (wp-login.php) con "Credenziali non valide."',

            // Live-Alarm
            '!! Ich habe %d neue Anmeldeversuche erkannt !!' => '!! Ho rilevato %d nuovi tentativi di accesso !!',
            '!! Ich habe einen neuen Anmeldeversuch erkannt !!!' => '!! Ho rilevato un nuovo tentativo di accesso !!!',
            'Aktualisiere die Seite..' => 'Aggiorna la pagina..',
            'Automatische Aktualisierung in %d Sekunden...' => 'Aggiornamento automatico in %d secondi...',
            'Verbindung fehlgeschlagen – prüfe später.' => 'Connessione fallita – controlla più tardi.',

            // Ruhige Zeiten
            'Alles ruhig und sicher – der Wächter meldet Ruh!' => 'Tutto tranquillo e sicuro – la guardia riferisce pace!',
            'Der Wächter schläft nicht – alles ruhig. Ich wache für Dich!' => 'La guardia non dorme mai – tutto tranquillo. Veglio per te!',
            'Die Angreifer schlafen – keine neuen Fehlversuche... ich bleibe wachsam!' => 'Gli attaccanti dormono – nessun nuovo tentativo fallito... resto vigile!',
            'Kein Angriff in Sicht – alles im grünen Bereich :-)' => 'Nessun attacco in vista – tutto nella zona verde :-)',
            'Friedliche Zeiten – keine Attacken - Sei beruhigt' => 'Tempi pacifici – nessuna attacco - Stai sereno',
            'Stille vor dem Sturm? Noch alles ruhig...' => 'Calma prima della tempesta? Ancora tutto tranquillo...',
            'Ich halte Wache – Keiner kommt ungesehen an mir vorbei!' => 'Monto la guardia – nessuno passa inosservato!',
            'Durch diese hohle Gasse wird er kommen.. – von mir bewacht!' => 'Per questo vicolo cavo verrà.. – sorvegliato da me!',

            // Plugin-Beschreibung
            'Intelligenter Login-Schutz mit progressiver Sperrzeit, Countdown und Admin-Übersicht.' => 'Protezione intelligente del login con tempo di blocco progressivo, conto alla rovescia e panoramica amministratore.',

            // Tabelle-Header
            'von' => 'di',

            // Status-Messages
            'Einstellungen gespeichert!' => 'Impostazioni salvate!',
            'IP entsperrt und Zähler zurückgesetzt.' => 'IP sbloccato e contatore resettato.',

            // Tabelle-Inhalte
            'GESPERRT! noch ca.' => 'BLOCCATO! ancora circa',
            'Sperrung abgelaufen' => 'Blocco scaduto',
            'Unbekannt' => 'Sconosciuto',
            'unbekannt' => 'sconosciuto',

            // Zahlen
            '%d Fehlversuch' => '%d tentativo fallito',
            '%d Fehlversuche' => '%d tentativi falliti',
            '%d Versuch verfügbar' => '%d tentativo disponibile',
            '%d Versuche verfügbar' => '%d tentativi disponibili',
            '%d möglich' => '%d possibile',
            'noch %d möglich' => 'ancora %d possibile',
            'Min' => 'min',

            // Aktionen
            'In Einstellungen bearbeiten' => 'Modifica nelle impostazioni',
            'Proaktiv geblockte User-Agents' => 'User-Agent bloccati in modo proattivo',
            'Teilstring' => 'Sottostringa',
            'Exakt' => 'Esatto',
            'Übereinstimmungsmodus' => 'Modalità di corrispondenza',

            // Hinweise
            'Tipp für maximale Sicherheit:' => 'Consiglio per la massima sicurezza:',
            'So machst du es Angreifern extrem schwer!' => 'Così rendi la vita estremamente difficile agli attaccanti!',
            'Wenn du XML_RPC nicht unbedingt benötigst, ist es ratsam es abzuschalten -> halb so viele Angriffe.' => 'Se non hai assolutamente bisogno di XML-RPC, è consigliabile disattivarlo → dimezza gli attacchi.',
            'Wie funktioniert eSherpa Login Guard?' => 'Come funziona eSherpa Login Guard?',
            'Keine existierende Usernamen eintragen!' => 'Non inserire nomi utente esistenti!',
            'IPs werden nur als anonymisierter Hash gespeichert – datenschutzkonform.' => 'Gli IP vengono memorizzati solo come hash anonimizzati – conforme alla protezione dei dati.',
            'Die erste Sperre dauert die eingestellte Basiszeit.' => 'Il primo blocco dura la durata base configurata.',
            'Der Fehlversuch-Zähler bleibt bis zu 1 Woche aktiv – danach wird er automatisch zurückgesetzt.' => 'Il contatore dei tentativi falliti rimane attivo fino a 1 settimana – dopo viene automaticamente resettato.',
            'Bei erfolgreichem Login werden Zähler und Sperre für die IP sofort gelöscht.' => 'In caso di login riuscito, il contatore e il blocco per l\'IP vengono immediatamente cancellati.',
            'Bei jedem falschen Login wird ein Zähler für die IP erhöht und der versuchte Benutzername gespeichert.' => 'Ad ogni login errato, un contatore per l\'IP viene incrementato e il nome utente tentato viene salvato.',
            'Du kannst gesperrte IPs manuell entsperren – der Zähler wird dabei zurückgesetzt.' => 'Puoi sbloccare manualmente le IP bloccate – il contatore viene resettato.',
            'Das Plugin schützt deine WordPress-Installation vor Brute-Force-Angriffen durch progressive Sperrzeiten.' => 'Il plugin protegge la tua installazione WordPress dagli attacchi brute-force con tempi di blocco progressivi.',
            'Author-Archive (?author=1) werden umgeleitet – verhindert Username-Enumeration über URL-Parameter.' => 'Gli archivi autore (?author=1) vengono reindirizzati – previene l\'enumerazione degli username tramite parametri URL.',
            'Die REST API User-Liste ist blockiert – Angreifer können keine Benutzernamen mehr automatisch auslesen.' => 'L\'elenco utenti dell\'API REST è bloccato – gli attaccanti non possono più leggere automaticamente i nomi utente.',
            'Diese User-Agents werden bereits beim Aufruf der Login-Seite blockiert – sie können keinen Login-Versuch starten.' => 'Questi User-Agent vengono bloccati quando si accede alla pagina di login – non possono avviare un tentativo di accesso.',
            'Bots ohne JavaScript-Unterstützung werden wie Angriffe auf geschützte Usernamen behandelt (sofortige Sperre mit progressiver Verlängerung).' => 'I bot senza supporto JavaScript vengono trattati come attacchi sui nomi utente protetti (blocco immediato con estensione progressiva).',
            'Passwörter von erkannten Bots (JS-Honeypot) in der Fehlversuch-Tabelle anzeigen' => 'Mostra password di bot rilevati (JS honeypot) nella tabella dei tentativi falliti',
            'Ältere Einträge werden täglich automatisch gelöscht (Datenschutz & Performance). Standard: 7 Tage' => 'Le voci più vecchie vengono eliminate automaticamente ogni giorno (privacy & performance). Predefinito: 7 giorni',
            'Nach %s Fehlversuchen wird die IP gesperrt.' => 'Dopo %s tentativi falliti, l\'IP viene bloccata.',
            'Dieser Zugriff wurde blockiert.' => 'Questo accesso è stato bloccato.',
            'Du hast zu oft falsch eingeloggt.' => 'Hai inserito credenziali errate troppe volte.',
            'Ungültige Anmeldedaten.' => 'Credenziali non valide.',
            'Login gesperrt' => 'Login bloccato',
            'Zugriff gesperrt' => 'Accesso bloccato',
            'Geschützt von %s' => 'Protetto da %s',
            'Noch keine erfolgreichen Logins aufgezeichnet.' => 'Nessun login riuscito registrato finora.',
            'Noch keine Fehlversuche aufgezeichnet.' => 'Nessun tentativo fallito registrato finora.',
            'Keine IPs aktuell gesperrt – alles ruhig!' => 'Nessun IP attualmente bloccato – tutto tranquillo!',
        ];
    } elseif ($locale === 'fr_FR') {
        $translations = [
            // Wichtige Admin-Interface-Strings
            'eSherpa Login Guard' => 'eSherpa Login Guard',
            'Login Guard' => 'Login Guard',
            'Einstellungen' => 'Paramètres',
            'Einstellungen speichern' => 'Enregistrer les paramètres',
            'Aktuell gesperrte IPs' => 'IP actuellement bloquées',
            'Geblockte User-Agents' => 'User-Agent bloqués',
            'Letzte Fehlversuche mit Benutzernamen & User-Agent' => 'Dernières tentatives échouées avec nom d\'utilisateur & User-Agent',
            'Letzte blockierte User-Agent-Versuche' => 'Dernières tentatives d\'User-Agent bloquées',
            'Status' => 'Statut',
            'Aktion' => 'Action',
            'Entsperren' => 'Débloquer',
            'Entsperrt in' => 'Débloqué dans',
            'Dauer' => 'Durée',
            'Benutzername' => 'Nom d\'utilisateur',
            'User-Agent' => 'User-Agent',
            'Zeit' => 'Heure',
            'IP (Hash)' => 'IP (Hash)',
            'Versuchter Benutzername' => 'Nom d\'utilisateur tenté',
            'Versuchtes Passwort' => 'Mot de passe tenté',
            'Blockiert wegen' => 'Bloqué à cause de',

            // E-Mail-Strings
            'Hallo Admin,' => 'Bonjour Admin,',
            'Brute-Force-Angriff: Existierender Benutzer attackiert!' => 'Attaque par force brute : Utilisateur existant attaqué !',
            'Der Login Guard hat einen Angriff auf einen existierenden Benutzer erkannt und die IP sofort gesperrt.' => 'Le Login Guard a détecté une attaque sur un utilisateur existant et a bloqué immédiatement l\'IP.',
            'IP-Adresse des Angreifers:' => 'Adresse IP de l\'attaquant :',
            'Betroffener Benutzername:' => 'Nom d\'utilisateur concerné :',
            'E-Mail des Betroffenen:' => 'E-mail de la personne concernée :',
            'Rolle(n) des Betroffenen:' => 'Rôle(s) de la personne concernée :',
            'Zeitpunkt:' => 'Moment :',
            'Was solltest du nun tun?' => 'Que devriez-vous faire maintenant ?',
            'Keine Panik!' => 'Pas de panique !',

            // Bot-Detection
            'Bot-Erkennung & Honeypot' => 'Détection de bot & Honeypot',
            'Bot-Passwort-Erfassung' => 'Capture de mot de passe bot',
            'JavaScript-Honeypot aktivieren' => 'Activer le honeypot JavaScript',
            'Passwörter von Bots erfassen' => 'Capturer les mots de passe des bots',

            // User-Agent-Blocking
            'Geblockte User-Agents (proaktive Sperre)' => 'User-Agent bloqués (blocage proactif)',
            'User-Agents blockieren (einer pro Zeile)' => 'Bloquer les User-Agent (un par ligne)',
            'Exakte User-Agent-Übereinstimmung verwenden (anstatt Teilstring)' => 'Utiliser la correspondance exacte de l\'User-Agent (au lieu de la sous-chaîne)',
            'Modus: Exakte Übereinstimmung (User-Agent muss genau übereinstimmen).' => 'Mode : Correspondance exacte (l\'User-Agent doit correspondre exactement).',
            'Modus: Teilstring-Übereinstimmung (z.B. \"curl\" blockiert alle curl-Anfragen).' => 'Mode : Correspondance de sous-chaîne (par ex. \"curl\" bloque toutes les requêtes curl).',
            'User-Agent aus der Fehlversuch-Liste kopieren.' => 'Copier l\'User-Agent depuis la liste des tentatives échouées.',
            'User-Agent kopieren' => 'Copier l\'User-Agent',
            'Klicken zum Kopieren' => 'Cliquer pour copier',

            // Datenbereinigung
            'Datenbereinigung' => 'Nettoyage des données',
            'Fehlversuche nach wie vielen Tagen löschen?' => 'Supprimer les tentatives échouées après combien de jours ?',

            // Maximale Versuche
            'Maximale Fehlversuche' => 'Nombre maximum de tentatives échouées',
            'Nach wie vielen falschen Logins wird die IP gesperrt? (Standard: 5)' => 'Après combien de connexions incorrectes l\'IP est-elle bloquée ? (Par défaut : 5)',

            // Sperrzeiten
            'Erste Sperrzeit in Minuten' => 'Durée initiale du blocage en minutes',
            'Bei einem Fehlversuch mit einem dieser Namen wird die IP sofort für 1 Stunde gesperrt – unabhängig von der normalen Zählung.' => 'En cas de tentative échouée avec un de ces noms, l\'IP est immédiatement bloquée pendant 1 heure – indépendamment du comptage normal.',
            'Bei jedem weiteren Verstoß verdoppelt sich die Sperrzeit (15 → 30 → 60 → 120 Min usw.).' => 'À chaque infraction supplémentaire, le temps de blocage double (15 → 30 → 60 → 120 min, etc.).',

            // Sofort sperren
            'Geschützte Benutzernamen (einer pro Zeile)' => 'Noms d\'utilisateur protégés (un par ligne)',
            'Sofortsperre für geschützte Benutzernamen' => 'Blocage immédiat pour les noms d\'utilisateur protégés',

            // XML-RPC
            'XML-RPC deaktivieren' => 'Désactiver XML-RPC',
            'XML-RPC komplett abschalten (verhindert viele Brute-Force-Angriffe)' => 'Désactiver complètement XML-RPC (empêche de nombreux attaques par force brute)',
            'Wenn aktiviert, wird eine gefälschte XML-RPC-Antwort mit den unten definierten Fake-Usern ausgegeben (Honeypot).' => 'Lorsqu\'activé, une réponse XML-RPC falsifiée est renvoyée avec les faux utilisateurs définis ci-dessous (honeypot).',
            'Fake-User für XML-RPC-Honeypot' => 'Faux utilisateurs pour honeypot XML-RPC',
            'Einer pro Zeile. Diese Usernamen werden in der gefälschten XML-RPC-Antwort angezeigt, wenn XML-RPC deaktiviert ist. Angreifer versuchen diese – und landen sofort in deiner Sperre.' => 'Un par ligne. Ces noms d\'utilisateur sont affichés dans la réponse XML-RPC falsifiée lorsque XML-RPC est désactivé. Les attaquants essaient ceux-ci – et atterrissent immédiatement dans votre blocage.',

            // Login-Hinweis
            'Login-Hinweis:' => 'Conseil de connexion :',
            'Du hast %s.' => 'Vous avez %s.',
            'Noch %s warten.' => 'Attendre encore %s.',
            'Warte noch %s.' => 'Attendre encore %s.',

            // WP-Login Anpassungen
            'REST API User-Liste blocken' => 'Bloquer la liste des utilisateurs de l\'API REST',
            'Author-Archive blocken' => 'Bloquer les archives d\'auteur',
            'Neutrale Fehlermeldung im WP-Login' => 'Message d\'erreur neutre dans le login WP',
            'Alle Fehlermeldungen im normalen WP-Login (wp-login.php) durch \"Ungültige Anmeldedaten.\" ersetzen' => 'Remplacer tous les messages d\'erreur dans le login WP standard (wp-login.php) par « Identifiants invalides. »',

            // Live-Alarm
            '!! Ich habe %d neue Anmeldeversuche erkannt !!' => '!! J\'ai détecté %d nouvelles tentatives de connexion !!',
            '!! Ich habe einen neuen Anmeldeversuch erkannt !!!' => '!! J\'ai détecté une nouvelle tentative de connexion !!!',
            'Aktualisiere die Seite..' => 'Actualiser la page..',
            'Automatische Aktualisierung in %d Sekunden...' => 'Actualisation automatique dans %d secondes...',
            'Verbindung fehlgeschlagen – prüfe später.' => 'Connexion échouée – vérifier plus tard.',

            // Ruhige Zeiten
            'Alles ruhig und sicher – der Wächter meldet Ruh!' => 'Tout est calme et sécurisé – le gardien signale la paix !',
            'Der Wächter schläft nicht – alles ruhig. Ich wache für Dich!' => 'Le gardien ne dort jamais – tout est calme. Je veille pour toi !',
            'Die Angreifer schlafen – keine neuen Fehlversuche... ich bleibe wachsam!' => 'Les attaquants dorment – aucune nouvelle tentative échouée... je reste vigilant !',
            'Kein Angriff in Sicht – alles im grünen Bereich :-)' => 'Aucune attaque en vue – tout dans la zone verte :-)',
            'Friedliche Zeiten – keine Attacken - Sei beruhigt' => 'Temps pacifiques – aucune attaque - Soyez rassuré',
            'Stille vor dem Sturm? Noch alles ruhig...' => 'Calme avant la tempête ? Tout est encore calme...',
            'Ich halte Wache – Keiner kommt ungesehen an mir vorbei!' => 'Je monte la garde – personne ne passe inaperçu !',
            'Durch diese hohle Gasse wird er kommen.. – von mir bewacht!' => 'À travers ce passage creux il viendra.. – gardé par moi !',

            // Plugin-Beschreibung
            'Intelligenter Login-Schutz mit progressiver Sperrzeit, Countdown und Admin-Übersicht.' => 'Protection intelligente de connexion avec temps de blocage progressif, compte à rebours et aperçu administrateur.',

            // Tabelle-Header
            'von' => 'de',

            // Status-Messages
            'Einstellungen gespeichert!' => 'Paramètres enregistrés !',
            'IP entsperrt und Zähler zurückgesetzt.' => 'IP débloquée et compteur remis à zéro.',

            // Tabelle-Inhalte
            'GESPERRT! noch ca.' => 'BLOQUÉ ! environ',
            'Sperrung abgelaufen' => 'Blocage expiré',
            'Unbekannt' => 'Inconnu',
            'unbekannt' => 'inconnu',

            // Zahlen
            '%d Fehlversuch' => '%d tentative échouée',
            '%d Fehlversuche' => '%d tentatives échouées',
            '%d Versuch verfügbar' => '%d tentative restante',
            '%d Versuche verfügbar' => '%d tentatives restantes',
            '%d möglich' => '%d possible',
            'noch %d möglich' => 'encore %d possible',
            'Min' => 'min',

            // Aktionen
            'In Einstellungen bearbeiten' => 'Modifier dans les paramètres',
            'Proaktiv geblockte User-Agents' => 'User-Agent bloqués de manière proactive',
            'Teilstring' => 'Sous-chaîne',
            'Exakt' => 'Exact',
            'Übereinstimmungsmodus' => 'Mode de correspondance',

            // Hinweise
            'Tipp für maximale Sicherheit:' => 'Astuce pour une sécurité maximale :',
            'So machst du es Angreifern extrem schwer!' => 'Cela rend la vie extrêmement difficile aux attaquants !',
            'Wenn du XML_RPC nicht unbedingt benötigst, ist es ratsam es abzuschalten -> halb so viele Angriffe.' => 'Si vous n\'avez pas absolument besoin de XML_RPC, il est conseillé de le désactiver → moitié moins d\'attaques.',
            'Wie funktioniert eSherpa Login Guard?' => 'Comment fonctionne eSherpa Login Guard ?',
            'Keine existierende Usernamen eintragen!' => 'Ne pas saisir de noms d\'utilisateur existants !',
            'IPs werden nur als anonymisierter Hash gespeichert – datenschutzkonform.' => 'Les IP sont stockées uniquement sous forme de hash anonymisé – conforme à la protection des données.',
            'Die erste Sperre dauert die eingestellte Basiszeit.' => 'Le premier blocage dure le temps de base configuré.',
            'Der Fehlversuch-Zähler bleibt bis zu 1 Woche aktiv – danach wird er automatisch zurückgesetzt.' => 'Le compteur de tentatives échouées reste actif jusqu\'à 1 semaine – après quoi il est automatiquement remis à zéro.',
            'Bei erfolgreichem Login werden Zähler und Sperre für die IP sofort gelöscht.' => 'En cas de connexion réussie, les compteurs et blocages pour l\'IP sont immédiatement supprimés.',
            'Bei jedem falschen Login wird ein Zähler für die IP erhöht und der versuchte Benutzername gespeichert.' => 'À chaque connexion incorrecte, un compteur pour l\'IP est incrémenté et le nom d\'utilisateur tenté est enregistré.',
            'Du kannst gesperrte IPs manuell entsperren – der Zähler wird dabei zurückgesetzt.' => 'Vous pouvez débloquer manuellement les IP bloquées – le compteur est remis à zéro.',
            'Das Plugin schützt deine WordPress-Installation vor Brute-Force-Angriffen durch progressive Sperrzeiten.' => 'Le plugin protège votre installation WordPress contre les attaques par force brute grâce aux temps de blocage progressifs.',
            'Author-Archive (?author=1) werden umgeleitet – verhindert Username-Enumeration über URL-Parameter.' => 'Les archives d\'auteur (?author=1) sont redirigées – empêche l\'énumération des noms d\'utilisateur via les paramètres URL.',
            'Die REST API User-Liste ist blockiert – Angreifer können keine Benutzernamen mehr automatisch auslesen.' => 'La liste des utilisateurs de l\'API REST est bloquée – les attaquants ne peuvent plus lire automatiquement les noms d\'utilisateur.',
            'Diese User-Agents werden bereits beim Aufruf der Login-Seite blockiert – sie können keinen Login-Versuch starten.' => 'Ces User-Agent sont bloqués lors de l\'accès à la page de connexion – ils ne peuvent pas lancer une tentative de connexion.',
            'Bots ohne JavaScript-Unterstützung werden wie Angriffe auf geschützte Usernamen behandelt (sofortige Sperre mit progressiver Verlängerung).' => 'Les bots sans support JavaScript sont traités comme des attaques sur les noms d\'utilisateur protégés (blocage immédiat avec extension progressive).',
            'Passwörter von erkannten Bots (JS-Honeypot) in der Fehlversuch-Tabelle anzeigen' => 'Afficher les mots de passe des bots détectés (JS honeypot) dans le tableau des tentatives échouées',
            'Ältere Einträge werden täglich automatisch gelöscht (Datenschutz & Performance). Standard: 7 Tage' => 'Les anciennes entrées sont automatiquement supprimées quotidiennement (protection des données & performance). Par défaut : 7 jours',
            'Nach %s Fehlversuchen wird die IP gesperrt.' => 'Après %s tentatives échouées, l\'IP est bloquée.',
            'Dieser Zugriff wurde blockiert.' => 'Cet accès a été bloqué.',
            'Du hast zu oft falsch eingeloggt.' => 'Vous vous êtes connecté incorrectement trop souvent.',
            'Ungültige Anmeldedaten.' => 'Identifiants invalides.',
            'Login gesperrt' => 'Connexion bloquée',
            'Zugriff gesperrt' => 'Accès bloqué',
            'Geschützt von %s' => 'Protégé par %s',
            'Noch keine erfolgreichen Logins aufgezeichnet.' => 'Aucune connexion réussie enregistrée pour le moment.',
            'Noch keine Fehlversuche aufgezeichnet.' => 'Aucune tentative échouée enregistrée pour le moment.',
            'Keine IPs aktuell gesperrt – alles ruhig!' => 'Aucune IP actuellement bloquée – tout est calme !',
        ];
    }

    return $translations;
}

function esherpa_parse_po_file($po_file) {
    $content = file_get_contents($po_file);
    if (!$content) {
        return [];
    }

    $lines = explode("\n", $content);
    $translations = [];
    $current_msgid = '';
    $current_msgstr = '';
    $in_msgid = false;
    $in_msgstr = false;

    foreach ($lines as $line) {
        $line = trim($line);

        if (strpos($line, 'msgid "') === 0) {
            // Speichere vorherige Übersetzung
            if ($current_msgid !== '' && $current_msgstr !== '') {
                $translations[$current_msgid] = $current_msgstr;
            }
            $current_msgid = substr($line, 7, -1);
            $current_msgstr = '';
            $in_msgid = true;
            $in_msgstr = false;
        } elseif (strpos($line, '"') === 0 && $in_msgid && !empty($current_msgid)) {
            $current_msgid .= substr($line, 1, -1);
        } elseif (strpos($line, 'msgstr "') === 0) {
            $current_msgstr = substr($line, 8, -1);
            $in_msgid = false;
            $in_msgstr = true;
        } elseif (strpos($line, '"') === 0 && $in_msgstr && !empty($current_msgstr)) {
            $current_msgstr .= substr($line, 1, -1);
        }
    }

    // Letzte Übersetzung hinzufügen
    if ($current_msgid !== '' && $current_msgstr !== '') {
        $translations[$current_msgid] = $current_msgstr;
    }

    return $translations;
}

// Überschreibe die Standard-Übersetzungsfunktionen für Fallback
function esherpa_login_guard_translate($text, $domain = 'esherpa-login-guard') {
    if ($domain !== 'esherpa-login-guard') {
        return $text;
    }

    global $esherpa_translations;
    if (isset($esherpa_translations[$text])) {
        return $esherpa_translations[$text];
    }

    return $text;
}

// Hook in die Übersetzungsfunktionen
add_filter('gettext', 'esherpa_login_guard_gettext_fallback', 10, 3);
add_filter('gettext_with_context', 'esherpa_login_guard_gettext_with_context_fallback', 10, 4);

function esherpa_login_guard_gettext_fallback($translation, $text, $domain) {
    if ($domain === 'esherpa-login-guard' && $translation === $text) {
        return esherpa_login_guard_translate($text);
    }
    return $translation;
}

function esherpa_login_guard_gettext_with_context_fallback($translation, $text, $context, $domain) {
    if ($domain === 'esherpa-login-guard' && $translation === $text) {
        return esherpa_login_guard_translate($text);
    }
    return $translation;
}


// ====================================================================
// 11. LIVE-ALARM AUF DER ADMIN-SEITE BEI NEUEM FAILED LOGIN
// ====================================================================

// AJAX-Handler für neue failed Logins
add_action('wp_ajax_esherpa_guard_check_new_failed', 'esherpa_guard_check_new_failed');
function esherpa_guard_check_new_failed() {
    check_ajax_referer('esherpa_guard_ajax', 'nonce');
    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => __('Unauthorized', 'esherpa-login-guard')], 403);
    }

    global $wpdb;
    $table_failed = $wpdb->prefix . 'esherpa_failed_logins';

    $last_check = intval($_POST['last_timestamp'] ?? 0);
    $new_logins = $wpdb->get_results($wpdb->prepare(
        "SELECT timestamp, ip_hash, attempted_username 
         FROM $table_failed 
         WHERE UNIX_TIMESTAMP(timestamp) > %d 
         ORDER BY timestamp DESC 
         LIMIT 10",
        $last_check
    ));

    if (empty($new_logins)) {
        wp_send_json_success(['new' => 0]);
    }

    $latest_ts = 0;
    $alerts = [];
    foreach ($new_logins as $log) {
        $ts = strtotime($log->timestamp);
        if ($ts > $latest_ts) $latest_ts = $ts;

        $alerts[] = [
            'time' => date_i18n('H:i:s', $ts),
            'ip'   => substr($log->ip_hash, 0, 12) . '...',
            'user' => $log->attempted_username
        ];
    }

    wp_send_json_success([
        'new'         => count($alerts),
        'alerts'      => $alerts,
        'latest_ts'   => $latest_ts
    ]);
}

// ====================================================================
// 12. E-MAIL-BENACHRICHTIGUNG AN ADMIN BEI ANGRIFF AUF EXISTIERENDEN USER (übersetzbar)
// ====================================================================
function esherpa_send_real_user_attack_email($username, $ip) {
    $admin_email = get_option('admin_email');
    if (empty($admin_email)) return;

    // User holen – für E-Mail und Rolle
    $user = get_user_by('login', $username);
    if (!$user) {
        $user = get_user_by('email', $username); // Fallback
    }

    $user_email = $user ? $user->user_email : esc_html__('unbekannt', 'esherpa-login-guard');
    $user_roles = $user ? implode(', ', $user->roles) : esc_html__('unbekannt', 'esherpa-login-guard');

    $time = current_time('d.m.Y H:i:s');
    // Übersetzbarer Betreff
    $subject = sprintf(
        '[%s] %s',
        get_bloginfo('name'),
        esc_html__('Brute-Force-Angriff: Existierender Benutzer attackiert!', 'esherpa-login-guard')
    );
    // Übersetzbare Nachricht (HTML für bessere Lesbarkeit)
    $message = '<p>' . esc_html__('Hallo Admin,', 'esherpa-login-guard') . '</p>';
    $message .= '<p>' . esc_html__('Der Login Guard hat einen Angriff auf einen existierenden Benutzer erkannt und die IP sofort gesperrt.', 'esherpa-login-guard') . '</p>';
    $message .= '<p><strong>' . esc_html__('Betroffener Benutzername:', 'esherpa-login-guard') . '</strong> ' . esc_html($username) . '<br>';
    $message .= '<strong>' . esc_html__('E-Mail des Betroffenen:', 'esherpa-login-guard') . '</strong> ' . esc_html($user_email) . '<br>';
    $message .= '<strong>' . esc_html__('Rolle(n) des Betroffenen:', 'esherpa-login-guard') . '</strong> ' . esc_html($user_roles) . '<br>';
    $message .= '<strong>' . esc_html__('IP-Adresse des Angreifers:', 'esherpa-login-guard') . '</strong> ' . esc_html($ip) . '<br>';
    $message .= '<strong>' . esc_html__('Zeitpunkt:', 'esherpa-login-guard') . '</strong> ' . esc_html($time) . '</p>';
    $message .= '<p>' . esc_html__('Die IP des Angreifers ist jetzt gesperrt – prüfe die Login Guard Übersicht für Details.', 'esherpa-login-guard') . '</p>';

    // NEU: Tipps für den Admin
    $message .= '<h3 style="color:#2271b1;">' . esc_html__('Was solltest du nun tun?', 'esherpa-login-guard') . '</h3>';
    $message .= '<ol style="line-height:1.8;">';
    $message .= '<li><strong>' . esc_html__('Keine Panik!', 'esherpa-login-guard') . '</strong></li>';
    $message .= '<li>' . esc_html__('Ist das Passwort des betroffenen Users leicht zu erraten?', 'esherpa-login-guard') . '</li>';
    $message .= '<li>' . esc_html__('Hat der betroffene User Admin-Rechte?', 'esherpa-login-guard') . '</li>';
    $message .= '<li>' . esc_html__('Aktiviere die zusätzlichen Sicherheitsmaßnahmen in den Login Guard Einstellungen.', 'esherpa-login-guard') . '</li>';
    $message .= '<li>' . esc_html__('Dann neuen User anlegen, den betroffenen Account löschen und zuschauen wie der Angreifer ins Leere hackt ;-)', 'esherpa-login-guard') . '</li>';
    $message .= '</ol>';

    $message .= '<p>' . sprintf(esc_html__('Geschützt von %s', 'esherpa-login-guard'), '<a href="' . esc_url(admin_url('admin.php?page=esherpa-login-guard')) . '">' . esc_html__('eSherpa Login Guard', 'esherpa-login-guard') . '</a>') . '</p>';

    $headers = ['Content-Type: text/html; charset=UTF-8'];
    wp_mail($admin_email, $subject, $message, $headers);
}

// ====================================================================
// 13. Enqueue
// ====================================================================
add_action('admin_enqueue_scripts', 'esherpa_login_guard_admin_assets');
function esherpa_login_guard_admin_assets($hook) {
    // Nur auf unserer Admin-Seite laden
    if ($hook !== 'toplevel_page_esherpa-login-guard') {
        return;
    }
    // CSS
    wp_enqueue_style(
        'esherpa-login-guard-admin',
        plugin_dir_url(__FILE__) . 'assets/css/admin.css',
        [],
        '3.0.0'
    );
    // JS
    wp_enqueue_script(
        'esherpa-login-guard-admin',
        plugin_dir_url(__FILE__) . 'assets/js/admin.js',
        ['jquery'],
        '3.0.0', // Version erhöht um Cache-Busting
        true
    );
	wp_localize_script('esherpa-login-guard-admin', 'esherpaGuardData', [
	    'nonce'   => wp_create_nonce('esherpa_guard_ajax'),
	    'ajaxurl' => admin_url('admin-ajax.php'),
	    'lastTs'  => 0, // Platzhalter – wird später überschrieben
	    'calmMessages' => [
	        __('Die Angreifer schlafen – keine neuen Fehlversuche... ich bleibe wachsam!', 'esherpa-login-guard'),
	        __('Der Wächter schläft nicht – alles ruhig. Ich wache für Dich!', 'esherpa-login-guard'),
	        __('Kein Angriff in Sicht – alles im grünen Bereich :-)', 'esherpa-login-guard'),
	        __('Stille vor dem Sturm? Noch alles ruhig...', 'esherpa-login-guard'),
	        __('Ich halte Wache – Keiner kommt ungesehen an mir vorbei!', 'esherpa-login-guard'),
	        __('Friedliche Zeiten – keine Attacken - Sei beruhigt', 'esherpa-login-guard'),
	        __('Alles ruhig und sicher – der Wächter meldet Ruh!', 'esherpa-login-guard'),
	        __('Durch diese hohle Gasse wird er kommen.. – von mir bewacht!', 'esherpa-login-guard')
	    ],
	    'alarmSingle' => __('!! Ich habe einen neuen Anmeldeversuch erkannt !!!', 'esherpa-login-guard'),
	    'alarmMulti'  => __('!! Ich habe %d neue Anmeldeversuche erkannt !!', 'esherpa-login-guard'),
	    'reloadLink'  => __('Aktualisiere die Seite..', 'esherpa-login-guard'),
	    'autoReloadText' => __('Automatische Aktualisierung in %d Sekunden...', 'esherpa-login-guard'),
	    'connectionFailed' => __('Verbindung fehlgeschlagen – prüfe später.', 'esherpa-login-guard'),
        'tableSwipeHint' => __('Tipp: Tabelle horizontal wischen/scrollen', 'esherpa-login-guard')
	]);
}

// ====================================================================
// Cache-Invalidierung für Admin-Menü Badge
// ====================================================================
function esherpa_invalidate_lockout_cache() {
    // Globalen Badge-Cache invalidieren (effizienter als wp_cache_flush())
    wp_cache_delete('esherpa_lockout_badge_global');
}

// ====================================================================
// JavaScript-Honeypot für Bot-Erkennung
// ====================================================================
function esherpa_add_js_honeypot_field() {
    if (get_option('esherpa_login_guard_enable_js_honeypot', '1') !== '1') {
        return;
    }
    ?>
    <input type="hidden" name="esherpa_human_check" id="esherpa_human_check" value="">
    <script type="text/javascript">
        (function() {
            try {
                document.getElementById('esherpa_human_check').value = 'human_verified_' + Date.now();
            } catch(e) {
                // Silent fail - Bot wird trotzdem erkannt
            }
        })();
    </script>
    <?php
}

function esherpa_detect_js_honeypot_bot() {
    // Honeypot nur aktivieren, wenn Option aktiviert ist
    if (get_option('esherpa_login_guard_enable_js_honeypot', '1') !== '1') {
        return false; // Honeypot deaktiviert
    }

    $honeypot_value = $_POST['esherpa_human_check'] ?? '';

    // Bot-Erkennung Logik:
    // 1. Leeres Feld = Bot (curl, scripts ohne JS-Unterstützung)
    // 2. Falscher Wert = Bot (manipulierte Anfragen)
    // 3. Korrekter Wert = Mensch (JS funktioniert)

    if (empty($honeypot_value)) {
        return true; // Leeres Feld = Bot (wie curl)
    }

    if (strpos($honeypot_value, 'human_verified_') !== 0) {
        return true; // Falscher Wert = Bot
    }

    // Korrekter Wert - prüfe Timestamp
    $timestamp = str_replace('human_verified_', '', $honeypot_value);
    if (!is_numeric($timestamp) || (time() - $timestamp) > 600) {
        return true; // Zu alter Timestamp = Bot
    }

    return false; // Alles korrekt = Mensch
}

// ====================================================================
// Sichere IP-Adresse holen (unterstützt Proxy-Headers)
// ====================================================================
function esherpa_get_client_ip() {
    // Prioritätsreihenfolge für IP-Header (vom vertrauenswürdigsten zum weniger vertrauenswürdigen)
    $ip_headers = [
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_CF_CONNECTING_IP',     // Cloudflare
        'HTTP_X_REAL_IP',           // Nginx
        'REMOTE_ADDR'
    ];

    foreach ($ip_headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip_candidates = explode(',', $_SERVER[$header]);

            foreach ($ip_candidates as $ip_candidate) {
                $ip_candidate = trim($ip_candidate);

                // Validierung: Nur öffentliche IPv4/IPv6-Adressen akzeptieren
                // FILTER_FLAG_NO_PRIV_RANGE: Keine private Ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
                // FILTER_FLAG_NO_RES_RANGE: Keine reservierte Ranges (0.0.0.0, 127.x.x.x, etc.)
                if (filter_var($ip_candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip_candidate;
                }
            }
        }
    }

    // Fallback: Leerstring wenn keine gültige IP gefunden wurde
    return '';
}

// ====================================================================
// User-Agent sicher holen und für Logging vorbereiten
// ====================================================================
function esherpa_get_client_user_agent() {
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // User-Agent auf sichere Länge kürzen (max 500 Zeichen) und sanitizen
    $user_agent = substr($user_agent, 0, 500);
    $user_agent = sanitize_textarea_field($user_agent);

    return $user_agent;
}

