#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_flash.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/inet.h"
#include "nvs.h"
#include "telnet_server.h"
#include "display_task.h"
#include "intel.h"

static const char *TAG = "telnet_honeypot";

#define HONEYOPUS_SCHEMA "honeyopus.attack/v1"
#define HONEYOPUS_PROTOCOL "telnet"
#define MAX_SESSION_EVENTS 128
#define MAX_SESSION_EVENT_BYTES (24 * 1024)
#define MAX_SESSION_COMMANDS 64
#define MAX_SESSION_COMMAND_BYTES (8 * 1024)
#define MAX_CAPTURE_FIELD_LEN 128
#define MAX_HUB_URL_LEN 256
#define MAX_RESPONSE_BODY_LEN 256
#define MAX_COMMAND_SUMMARY_LEN 4000
#define HONEYPOT_FIRMWARE_VERSION "1"
#define IP_COOLDOWN_SECONDS CONFIG_IP_COOLDOWN_SECONDS
#define IP_COOLDOWN_US ((int64_t)IP_COOLDOWN_SECONDS * 1000000LL)
#define IP_COOLDOWN_ENTRIES 64

#if CONFIG_IDF_TARGET_ESP32C3
#define HONEYPOT_MCU "esp32-c3"
#define HONEYPOT_BOARD "esp32-c3-supermini"
#define HONEYPOT_DISPLAY "ssd1306-72x40"
#elif CONFIG_IDF_TARGET_ESP32S3
#define HONEYPOT_MCU "esp32-s3"
#define HONEYPOT_BOARD "esp32-s3-n16r8"
#define HONEYPOT_DISPLAY "none"
#else
#define HONEYPOT_MCU CONFIG_IDF_TARGET
#define HONEYPOT_BOARD "other"
#define HONEYPOT_DISPLAY "none"
#endif

typedef struct {
    char kind;
    char *data;
    size_t len;
} session_event_t;

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    int64_t last_allowed_us;
} ip_cooldown_entry_t;

typedef struct {
    int sock;
    char source_ip[INET6_ADDRSTRLEN];
    uint16_t source_port;
    char username[MAX_CAPTURE_FIELD_LEN];
    char password[MAX_CAPTURE_FIELD_LEN];
    uint32_t auth_attempts;
    bool authenticated;
    bool skip_next_lf;
    uint64_t started_us;
    uint64_t started_ts;
    uint32_t duration_ms;
    uint32_t attack_id;
    bool cast_truncated;
    size_t event_count;
    size_t total_event_bytes;
    session_event_t events[MAX_SESSION_EVENTS];
    size_t command_count;
    size_t total_command_bytes;
    char *commands[MAX_SESSION_COMMANDS];
} telnet_session_t;

typedef struct {
    const char *profile;
    uint8_t confidence;
} attack_classification_t;

static SemaphoreHandle_t s_sessions_mutex;
static SemaphoreHandle_t s_report_mutex;
static SemaphoreHandle_t s_ip_cooldown_mutex;
static SemaphoreHandle_t s_network_report_mutex;
static telnet_session_t *s_sessions[MAX_CONNECTIONS];
static ip_cooldown_entry_t s_ip_cooldown[IP_COOLDOWN_ENTRIES];

// ============================================================
// Simulated HiLinux NVR/DVR Environment
// ============================================================

// Current working directory
static char cwd[64] = "/";

// Simulated filesystem
static const char *filesystem[] = {
    "/bin", "/bin/busybox",
    "/tmp",
    "/var", "/var/tmp", "/var/run",
    "/dev", "/dev/shm",
    "/proc",
    "/etc", "/etc/init.d",
    "/mnt",
    NULL
};

// ============================================================
// Telnet Protocol Constants
// ============================================================
#define IAC 255
#define WILL 251
#define WONT 252
#define DO 253
#define DONT 254

// ============================================================
// Helper Functions
// ============================================================

static void session_record_event(telnet_session_t *session, char kind, const char *data, size_t len);
static void session_record_command(telnet_session_t *session, const char *cmd);
static telnet_session_t *session_find_by_sock(int sock);
static esp_err_t submit_attack_report(telnet_session_t *session);
static void free_session(telnet_session_t *session);
static void handle_telnet_options(unsigned char *buf, int len, int sock);
static bool ip_cooldown_allow(const char *ip, int64_t now_us, int64_t *remaining_us);

static void send_str(int sock, const char *str) {
    size_t len = strlen(str);
    send(sock, str, len, 0);
    session_record_event(session_find_by_sock(sock), 'o', str, len);
}

static void send_line(int sock, const char *str) {
    char buf[BUFFER_SIZE];
    int len = snprintf(buf, sizeof(buf), "%s\r\n", str);
    if (len > 0) {
        send(sock, buf, len, 0);
        session_record_event(session_find_by_sock(sock), 'o', buf, (size_t)len);
    }
}

static char* trim_whitespace(char *str) {
    while (*str == ' ' || *str == '\t') str++;
    if (*str == '\0') {
        return str;
    }

    char *end = str + strlen(str) - 1;
    while (end >= str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        if (end == str) {
            break;
        }
        end--;
    }
    return str;
}

static int build_path(char *dest, size_t dest_size, const char *base, const char *name) {
    int len;

    if (name[0] == '/') {
        len = snprintf(dest, dest_size, "%s", name);
    } else if (base[strlen(base) - 1] == '/') {
        len = snprintf(dest, dest_size, "%s%s", base, name);
    } else {
        len = snprintf(dest, dest_size, "%s/%s", base, name);
    }

    if (len < 0 || (size_t)len >= dest_size) {
        if (dest_size > 0) {
            dest[dest_size - 1] = 0;
        }
        return 0;
    }

    return 1;
}

static void ensure_runtime_state(void) {
    if (s_sessions_mutex == NULL) {
        s_sessions_mutex = xSemaphoreCreateMutex();
    }
    if (s_report_mutex == NULL) {
        s_report_mutex = xSemaphoreCreateMutex();
    }
    if (s_ip_cooldown_mutex == NULL) {
        s_ip_cooldown_mutex = xSemaphoreCreateMutex();
    }
    if (s_network_report_mutex == NULL) {
        s_network_report_mutex = xSemaphoreCreateMutex();
    }
}

static bool ip_cooldown_allow(const char *ip, int64_t now_us, int64_t *remaining_us) {
    int empty_slot = -1;
    int oldest_slot = 0;
    int64_t oldest_seen_us = INT64_MAX;

    if (remaining_us != NULL) {
        *remaining_us = 0;
    }

    if (ip == NULL || ip[0] == '\0') {
        return true;
    }

    if (s_ip_cooldown_mutex == NULL) {
        return true;
    }

    if (xSemaphoreTake(s_ip_cooldown_mutex, portMAX_DELAY) != pdTRUE) {
        return true;
    }

    for (int i = 0; i < IP_COOLDOWN_ENTRIES; i++) {
        if (s_ip_cooldown[i].ip[0] == '\0') {
            if (empty_slot < 0) {
                empty_slot = i;
            }
            continue;
        }

        if (strcmp(s_ip_cooldown[i].ip, ip) == 0) {
            int64_t elapsed = now_us - s_ip_cooldown[i].last_allowed_us;
            if (elapsed >= 0 && elapsed < IP_COOLDOWN_US) {
                if (remaining_us != NULL) {
                    *remaining_us = IP_COOLDOWN_US - elapsed;
                }
                xSemaphoreGive(s_ip_cooldown_mutex);
                return false;
            }

            s_ip_cooldown[i].last_allowed_us = now_us;
            xSemaphoreGive(s_ip_cooldown_mutex);
            return true;
        }

        if (s_ip_cooldown[i].last_allowed_us < oldest_seen_us) {
            oldest_seen_us = s_ip_cooldown[i].last_allowed_us;
            oldest_slot = i;
        }
    }

    int slot = empty_slot >= 0 ? empty_slot : oldest_slot;
    snprintf(s_ip_cooldown[slot].ip, sizeof(s_ip_cooldown[slot].ip), "%s", ip);
    s_ip_cooldown[slot].last_allowed_us = now_us;

    xSemaphoreGive(s_ip_cooldown_mutex);
    return true;
}


static telnet_session_t *session_find_by_sock(int sock) {
    telnet_session_t *session = NULL;

    if (s_sessions_mutex == NULL) {
        return NULL;
    }

    if (xSemaphoreTake(s_sessions_mutex, portMAX_DELAY) == pdTRUE) {
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (s_sessions[i] != NULL && s_sessions[i]->sock == sock) {
                session = s_sessions[i];
                break;
            }
        }
        xSemaphoreGive(s_sessions_mutex);
    }

    return session;
}

static void session_register(telnet_session_t *session) {
    if (session == NULL || s_sessions_mutex == NULL) {
        return;
    }

    if (xSemaphoreTake(s_sessions_mutex, portMAX_DELAY) == pdTRUE) {
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (s_sessions[i] == NULL) {
                s_sessions[i] = session;
                break;
            }
        }
        xSemaphoreGive(s_sessions_mutex);
    }
}

static void session_unregister(telnet_session_t *session) {
    if (session == NULL || s_sessions_mutex == NULL) {
        return;
    }

    if (xSemaphoreTake(s_sessions_mutex, portMAX_DELAY) == pdTRUE) {
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (s_sessions[i] == session) {
                s_sessions[i] = NULL;
                break;
            }
        }
        xSemaphoreGive(s_sessions_mutex);
    }
}

static void session_record_event(telnet_session_t *session, char kind, const char *data, size_t len) {
    char *next;

    if (session == NULL || data == NULL || len == 0 || session->cast_truncated) {
        return;
    }

    if (session->total_event_bytes + len > MAX_SESSION_EVENT_BYTES) {
        session->cast_truncated = true;
        return;
    }

    if (session->event_count > 0 && session->events[session->event_count - 1].kind == kind) {
        session_event_t *last = &session->events[session->event_count - 1];
        next = realloc(last->data, last->len + len + 1);
        if (next == NULL) {
            session->cast_truncated = true;
            return;
        }
        memcpy(next + last->len, data, len);
        last->len += len;
        next[last->len] = '\0';
        last->data = next;
        session->total_event_bytes += len;
        return;
    }

    if (session->event_count >= MAX_SESSION_EVENTS) {
        session->cast_truncated = true;
        return;
    }

    next = malloc(len + 1);
    if (next == NULL) {
        session->cast_truncated = true;
        return;
    }

    memcpy(next, data, len);
    next[len] = '\0';
    session->events[session->event_count].kind = kind;
    session->events[session->event_count].data = next;
    session->events[session->event_count].len = len;
    session->event_count++;
    session->total_event_bytes += len;
}

static void session_record_input_char(telnet_session_t *session, char ch) {
    session_record_event(session, 'i', &ch, 1);
}

static void session_record_command(telnet_session_t *session, const char *cmd) {
    char *copy;
    size_t len;

    if (session == NULL || cmd == NULL) {
        return;
    }

    while (*cmd == ' ' || *cmd == '\t' || *cmd == '\r' || *cmd == '\n') {
        cmd++;
    }
    len = strlen(cmd);
    while (len > 0 && (cmd[len - 1] == ' ' || cmd[len - 1] == '\t' ||
                       cmd[len - 1] == '\r' || cmd[len - 1] == '\n')) {
        len--;
    }

    if (len == 0) {
        return;
    }

    if (session->command_count >= MAX_SESSION_COMMANDS ||
        session->total_command_bytes + len > MAX_SESSION_COMMAND_BYTES) {
        session->cast_truncated = true;
        return;
    }

    copy = malloc(len + 1);
    if (copy == NULL) {
        session->cast_truncated = true;
        return;
    }
    memcpy(copy, cmd, len);
    copy[len] = '\0';

    session->commands[session->command_count++] = copy;
    session->total_command_bytes += len;
}

static int read_session_byte(int sock, unsigned char *byte) {
    while (1) {
        int len = recv(sock, byte, 1, 0);
        if (len <= 0) {
            return len;
        }

        if (*byte == IAC) {
            unsigned char option[3] = { *byte, 0, 0 };
            int extra = recv(sock, &option[1], 1, 0);
            if (extra <= 0) {
                return extra;
            }
            if (option[1] == WILL || option[1] == WONT || option[1] == DO || option[1] == DONT) {
                extra = recv(sock, &option[2], 1, 0);
                if (extra <= 0) {
                    return extra;
                }
                handle_telnet_options(option, 3, sock);
            } else {
                handle_telnet_options(option, 2, sock);
            }
            continue;
        }

        return len;
    }
}

static int read_client_line(int sock, char *dest, size_t dest_size, telnet_session_t *session) {
    size_t pos = 0;

    while (1) {
        unsigned char ch = 0;
        int len = read_session_byte(sock, &ch);
        if (len <= 0) {
            return -1;
        }

        // Telnet clients commonly terminate a line with CRLF (\r\n) or CRNUL
        // (\r\0). If the previous read ended on CR, swallow the paired LF/NUL
        // instead of treating it as an empty next line. This is critical during
        // login: otherwise "admin\r\npassword\r\n" is parsed as user="admin",
        // pass="".
        if (session != NULL && session->skip_next_lf) {
            session->skip_next_lf = false;
            if (ch == '\n' || ch == '\0') {
                continue;
            }
        }

        if (ch == '\r') {
            if (session != NULL) {
                session->skip_next_lf = true;
            }
            session_record_event(session, 'i', "\r\n", 2);
            break;
        }

        if (ch == '\n') {
            session_record_event(session, 'i', "\r\n", 2);
            break;
        }

        if ((ch == 8 || ch == 127) && pos > 0) {
            pos--;
            session_record_input_char(session, '\b');
            continue;
        }

        if (ch >= 32 && ch <= 126) {
            if (pos < dest_size - 1) {
                dest[pos++] = (char)ch;
            }
            session_record_input_char(session, (char)ch);
        }
    }

    dest[pos] = '\0';
    return (int)pos;
}

static uint32_t allocate_attack_id(void) {
    uint32_t next_id = 1;
    nvs_handle_t nvs_handle;

    ensure_runtime_state();
    if (s_report_mutex == NULL) {
        return 0;
    }

    if (xSemaphoreTake(s_report_mutex, portMAX_DELAY) != pdTRUE) {
        return 0;
    }

    if (nvs_open("hub_report", NVS_READWRITE, &nvs_handle) == ESP_OK) {
        if (nvs_get_u32(nvs_handle, "next_id", &next_id) != ESP_OK) {
            next_id = 1;
        }
        nvs_set_u32(nvs_handle, "next_id", next_id + 1);
        nvs_commit(nvs_handle);
        nvs_close(nvs_handle);
    } else {
        next_id = 0;
    }

    xSemaphoreGive(s_report_mutex);
    return next_id;
}

static void build_device_id(char *dest, size_t dest_size) {
    uint8_t mac[6] = {0};

    if (esp_read_mac(mac, ESP_MAC_WIFI_STA) != ESP_OK) {
        snprintf(dest, dest_size, "hp-unknown");
        return;
    }

    snprintf(dest, dest_size, "hp-%02x%02x%02x%02x%02x%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void build_ingest_url(char *dest, size_t dest_size) {
    size_t base_len = strlen(CONFIG_HUB_URL);

    while (base_len > 0 && CONFIG_HUB_URL[base_len - 1] == '/') {
        base_len--;
    }

    snprintf(dest, dest_size, "%.*s/api/v1/ingest", (int)base_len, CONFIG_HUB_URL);
}

static bool hub_reporting_enabled(void) {
    return CONFIG_HUB_URL[0] != '\0' && CONFIG_HUB_TOKEN[0] != '\0';
}

static uint32_t get_flash_size_mb(void) {
    uint32_t flash_size = 0;

    if (esp_flash_get_size(NULL, &flash_size) != ESP_OK) {
        return 0;
    }

    return flash_size / (1024 * 1024);
}

static bool char_equal_ci(char a, char b) {
    return tolower((unsigned char)a) == tolower((unsigned char)b);
}

static bool contains_ci(const char *haystack, const char *needle) {
    size_t needle_len;

    if (haystack == NULL || needle == NULL) {
        return false;
    }

    needle_len = strlen(needle);
    if (needle_len == 0) {
        return true;
    }

    for (const char *p = haystack; *p != '\0'; p++) {
        size_t i = 0;
        while (i < needle_len && p[i] != '\0' && char_equal_ci(p[i], needle[i])) {
            i++;
        }
        if (i == needle_len) {
            return true;
        }
    }

    return false;
}

static bool commands_contain_any(const telnet_session_t *session,
                                 const char *const *needles,
                                 size_t needle_count) {
    if (session == NULL || needles == NULL) {
        return false;
    }

    for (size_t i = 0; i < session->command_count; i++) {
        for (size_t j = 0; j < needle_count; j++) {
            if (contains_ci(session->commands[i], needles[j])) {
                return true;
            }
        }
    }

    return false;
}

static bool match_mirai_credentials(const char *user, const char *pass) {
    static const struct {
        const char *user;
        const char *pass;
    } pairs[] = {
        {"root", "xc3511"}, {"root", "vizxv"}, {"root", "admin"},
        {"admin", "admin"}, {"root", "888888"}, {"root", "xmhdipc"},
        {"root", "default"}, {"root", "juantech"}, {"root", "123456"},
        {"root", "54321"}, {"support", "support"}, {"root", ""},
        {"admin", ""}, {"root", "root"}, {"root", "12345"},
        {"user", "user"}, {"admin", "password"}, {"root", "pass"},
        {"root", "klv123"}, {"root", "Zte521"}, {"root", "hi3518"},
        {"root", "jvbzd"}, {"root", "anko"}, {"root", "zlxx."},
        {"root", "system"}, {"root", "ikwb"}, {"root", "dreambox"},
        {"root", "user"}, {"root", "realtek"}, {"root", "00000000"},
        {"admin", "1111111"}, {"admin", "1234"}, {"admin", "12345"},
        {"admin", "54321"}, {"admin", "123456"}, {"admin", "pass"},
        {"admin", "meinsm"}, {"tech", "tech"}, {"ubnt", "ubnt"},
        {"root", "666666"}, {"root", "password"}, {"root", "1234"},
        {"guest", "guest"}, {"guest", "12345"}, {"administrator", "1234"},
        {"666666", "666666"}, {"888888", "888888"},
    };

    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        if (strcmp(user, pairs[i].user) == 0 && strcmp(pass, pairs[i].pass) == 0) {
            return true;
        }
    }

    return false;
}

static bool ip_is_private_or_lan(const char *ip) {
    int a = 0;
    int b = 0;

    if (ip == NULL || ip[0] == '\0') {
        return true;
    }

    if (strcmp(ip, "::1") == 0 || strncmp(ip, "127.", 4) == 0 ||
        strncmp(ip, "10.", 3) == 0 || strncmp(ip, "192.168.", 8) == 0 ||
        strncmp(ip, "169.254.", 8) == 0) {
        return true;
    }

    if (sscanf(ip, "%d.%d.", &a, &b) == 2) {
        if (a == 172 && b >= 16 && b <= 31) {
            return true;
        }
        if (a == 100 && b >= 64 && b <= 127) {
            return true;
        }
    }

    return false;
}

static attack_classification_t classify_session(const telnet_session_t *session) {
    static const char *const mirai_markers[] = {
        "ECCHI", "MIRAI", "OWARI", "HOHO", "GAFGYT", "TSUNAMI", "LZRD",
        "/bin/busybox echo", "/bin/busybox cat /bin/sh"
    };
    static const char *const fetch_markers[] = {
        "wget ", "curl ", "tftp ", "ftpget "
    };
    static const char *const chmod_markers[] = {
        "chmod 777", "chmod +x", "chmod 755"
    };
    static const char *const exec_markers[] = {
        "/tmp/", "/var/run/", "./.x", "./loligang", "./"
    };
    static const char *const recon_markers[] = {
        "uname -a", "/proc/cpuinfo", "free", "df", "ifconfig", "netstat"
    };
    static const char *const manual_markers[] = {
        "history", "sudo ", "vi ", "vim ", "nano ", "clear"
    };
    bool mirai_creds = match_mirai_credentials(session->username, session->password);
    bool fetch = commands_contain_any(session, fetch_markers, sizeof(fetch_markers) / sizeof(fetch_markers[0]));
    bool chmod = commands_contain_any(session, chmod_markers, sizeof(chmod_markers) / sizeof(chmod_markers[0]));
    bool exec = commands_contain_any(session, exec_markers, sizeof(exec_markers) / sizeof(exec_markers[0]));
    bool recon = commands_contain_any(session, recon_markers, sizeof(recon_markers) / sizeof(recon_markers[0]));
    bool manual = commands_contain_any(session, manual_markers, sizeof(manual_markers) / sizeof(manual_markers[0]));

    if (commands_contain_any(session, mirai_markers, sizeof(mirai_markers) / sizeof(mirai_markers[0]))) {
        return (attack_classification_t){ "mirai", 95 };
    }

    if (fetch && (chmod || exec)) {
        return (attack_classification_t){ "iot-loader", 88 };
    }

    if (session->command_count == 0) {
        if (mirai_creds) {
            return (attack_classification_t){ "scanner", 75 };
        }
        return (attack_classification_t){ session->auth_attempts > 0 ? "creds-only" : "creds-probe", 60 };
    }

    if (mirai_creds && recon) {
        return (attack_classification_t){ "scanner", 80 };
    }

    if (recon && session->command_count >= 3) {
        return (attack_classification_t){ "recon-script", 75 };
    }

    if (manual) {
        return (attack_classification_t){ "manual", 55 };
    }

    if (session->command_count >= 3) {
        return (attack_classification_t){ "scripted", 70 };
    }

    if (mirai_creds) {
        return (attack_classification_t){ "scanner", 65 };
    }

    if (ip_is_private_or_lan(session->source_ip)) {
        return (attack_classification_t){ "lan", 30 };
    }

    return (attack_classification_t){ "scanner", 40 };
}

static char *build_command_summary(const telnet_session_t *session) {
    char *summary;
    size_t pos = 0;

    summary = malloc(MAX_COMMAND_SUMMARY_LEN + 1);
    if (summary == NULL) {
        return NULL;
    }

    summary[0] = '\0';
    for (size_t i = 0; i < session->command_count && pos < MAX_COMMAND_SUMMARY_LEN; i++) {
        const char *cmd = session->commands[i];
        size_t len = strlen(cmd);

        if (i > 0) {
            summary[pos++] = '\n';
        }

        if (pos + len > MAX_COMMAND_SUMMARY_LEN) {
            len = MAX_COMMAND_SUMMARY_LEN - pos;
        }

        memcpy(summary + pos, cmd, len);
        pos += len;
    }

    summary[pos] = '\0';
    return summary;
}

static cJSON *build_attack_report_json(const telnet_session_t *session) {
    cJSON *root = cJSON_CreateObject();
    cJSON *honeypot;
    cJSON *hardware;
    cJSON *attack;
    cJSON *source;
    cJSON *auth;
    cJSON *classification;
    cJSON *session_obj;
    cJSON *events;
    cJSON *term;
    attack_classification_t attack_classification;
    char *command_summary = NULL;
    char device_id[32];

    if (root == NULL) {
        return NULL;
    }

    build_device_id(device_id, sizeof(device_id));

    cJSON_AddStringToObject(root, "schema", HONEYOPUS_SCHEMA);

    honeypot = cJSON_AddObjectToObject(root, "honeypot");
    cJSON_AddStringToObject(honeypot, "device_id", device_id);
    cJSON_AddStringToObject(honeypot, "firmware_version", HONEYPOT_FIRMWARE_VERSION);
    cJSON_AddStringToObject(honeypot, "firmware_build", __DATE__ " " __TIME__);
    cJSON_AddNumberToObject(honeypot, "uptime_s", (double)(esp_timer_get_time() / 1000000ULL));

    hardware = cJSON_AddObjectToObject(honeypot, "hardware");
    cJSON_AddStringToObject(hardware, "mcu", HONEYPOT_MCU);
    cJSON_AddStringToObject(hardware, "board", HONEYPOT_BOARD);
    cJSON_AddStringToObject(hardware, "display", HONEYPOT_DISPLAY);
    cJSON_AddNumberToObject(hardware, "flash_mb", (double)get_flash_size_mb());

    attack = cJSON_AddObjectToObject(root, "attack");
    cJSON_AddNumberToObject(attack, "id", (double)session->attack_id);
    cJSON_AddNumberToObject(attack, "ts", (double)session->started_ts);
    cJSON_AddNumberToObject(attack, "duration_ms", (double)session->duration_ms);
    cJSON_AddStringToObject(attack, "protocol", HONEYOPUS_PROTOCOL);

    source = cJSON_AddObjectToObject(attack, "source");
    cJSON_AddStringToObject(source, "ip", session->source_ip);
    cJSON_AddNumberToObject(source, "port", (double)session->source_port);

    auth = cJSON_AddObjectToObject(attack, "auth");
    cJSON_AddStringToObject(auth, "user", session->username);
    cJSON_AddStringToObject(auth, "pass", session->password);
    cJSON_AddBoolToObject(auth, "authenticated", session->authenticated);
    cJSON_AddNumberToObject(auth, "attempts", (double)session->auth_attempts);

    attack_classification = classify_session(session);
    command_summary = build_command_summary(session);
    classification = cJSON_AddObjectToObject(attack, "classification");
    if (classification != NULL) {
        cJSON_AddStringToObject(classification, "profile", attack_classification.profile);
        cJSON_AddNumberToObject(classification, "confidence", (double)attack_classification.confidence);
        if (command_summary != NULL && command_summary[0] != '\0') {
            cJSON_AddStringToObject(classification, "command_summary", command_summary);
        }
    }
    free(command_summary);

    // Explicit command fields for hub dashboards. According to the protocol
    // (§3.4.3), session.commands MUST be an integer. The array of actual
    // command strings is moved to command_list to avoid clashing with the
    // count field while still being available in the raw payload.
    cJSON_AddNumberToObject(attack, "command_count", (double)session->command_count);
    if (session->command_count > 0) {
        cJSON *commands = cJSON_AddArrayToObject(attack, "command_list");
        for (size_t i = 0; i < session->command_count; i++) {
            cJSON_AddItemToArray(commands, cJSON_CreateString(session->commands[i]));
        }
    }

    session_obj = cJSON_AddObjectToObject(attack, "session");
    cJSON_AddNumberToObject(session_obj, "commands", (double)session->command_count);
    if (session->command_count > 0) {
        cJSON *session_commands = cJSON_AddArrayToObject(session_obj, "command_list");
        for (size_t i = 0; i < session->command_count; i++) {
            cJSON_AddItemToArray(session_commands, cJSON_CreateString(session->commands[i]));
        }
    }
    cJSON_AddBoolToObject(session_obj, "cast_truncated", session->cast_truncated);
    term = cJSON_AddObjectToObject(session_obj, "term");
    cJSON_AddNumberToObject(term, "cols", 80);
    cJSON_AddNumberToObject(term, "rows", 24);

    if (session->event_count > 0) {
        events = cJSON_AddArrayToObject(session_obj, "events");
        for (size_t i = 0; i < session->event_count; i++) {
            cJSON *event = cJSON_CreateObject();
            char kind[2] = { session->events[i].kind, '\0' };
            cJSON_AddStringToObject(event, "k", kind);
            cJSON_AddStringToObject(event, "d", session->events[i].data);
            cJSON_AddItemToArray(events, event);
        }
    }

    return root;
}

static esp_err_t submit_attack_report(telnet_session_t *session) {
    esp_http_client_config_t config = {0};
    esp_http_client_handle_t client;
    cJSON *json;
    char *body;
    char url[MAX_HUB_URL_LEN];
    char auth_header[128];
    char response_body[MAX_RESPONSE_BODY_LEN];
    int status;
    esp_err_t err;

    if (!hub_reporting_enabled()) {
        return ESP_ERR_NOT_FOUND;
    }

    if (session->attack_id == 0) {
        session->attack_id = allocate_attack_id();
        if (session->attack_id == 0) {
            return ESP_FAIL;
        }
    }

    json = build_attack_report_json(session);
    if (json == NULL) {
        return ESP_ERR_NO_MEM;
    }

    body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (body == NULL) {
        return ESP_ERR_NO_MEM;
    }

    build_ingest_url(url, sizeof(url));
    snprintf(auth_header, sizeof(auth_header), "Bearer %s", CONFIG_HUB_TOKEN);

    config.url = url;
    config.method = HTTP_METHOD_POST;
    config.timeout_ms = 15000;
    config.crt_bundle_attach = esp_crt_bundle_attach;

    client = esp_http_client_init(&config);
    if (client == NULL) {
        cJSON_free(body);
        return ESP_FAIL;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json; charset=utf-8");
    esp_http_client_set_header(client, "Authorization", auth_header);
    esp_http_client_set_header(client, "User-Agent", "HoneyMistNano/" HONEYPOT_FIRMWARE_VERSION);
    esp_http_client_set_post_field(client, body, (int)strlen(body));

    err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        status = esp_http_client_get_status_code(client);
        int len = esp_http_client_read_response(client, response_body, sizeof(response_body) - 1);
        if (len < 0) {
            len = 0;
        }
        response_body[len] = '\0';

        if (status == 200 || status == 201) {
            ESP_LOGI(TAG, "Reported attack %" PRIu32 " to HoneyOpus hub (%d)", session->attack_id, status);
        } else if (status == 401) {
            ESP_LOGW(TAG, "HoneyOpus hub rejected token for attack %" PRIu32, session->attack_id);
            err = ESP_ERR_INVALID_RESPONSE;
        } else {
            ESP_LOGW(TAG, "HoneyOpus hub returned %d for attack %" PRIu32 ": %s",
                     status, session->attack_id, response_body);
            err = ESP_ERR_INVALID_RESPONSE;
        }
    } else {
        ESP_LOGW(TAG, "HoneyOpus hub report failed for attack %" PRIu32 ": %s",
                 session->attack_id, esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    cJSON_free(body);
    return err;
}

static void free_session(telnet_session_t *session) {
    if (session == NULL) {
        return;
    }

    for (size_t i = 0; i < session->event_count; i++) {
        free(session->events[i].data);
    }
    for (size_t i = 0; i < session->command_count; i++) {
        free(session->commands[i]);
    }
    free(session);
}

static void log_command(const char *cmd) {
    ESP_LOGI(TAG, "CMD: %s", cmd);
}

// ============================================================
// Telnet Option Handler
// ============================================================

static void handle_telnet_options(unsigned char *buf, int len, int sock) {
    for (int i = 0; i < len; i++) {
        if (buf[i] == IAC) {
            if (i + 1 < len) {
                switch (buf[i + 1]) {
                    case WILL:
                    case WONT:
                    case DO:
                    case DONT:
                        if (i + 2 < len) {
                            // Respond with WONT/DONT for simplicity
                            unsigned char response[3] = {IAC, WONT, buf[i + 2]};
                            send(sock, response, 3, 0);
                        }
                        i += 2;
                        break;
                }
            }
        }
    }
}

// ============================================================
// Hex Escape Decoder (for echo -ne '\x4c\x4a...')
// ============================================================

static void decode_hex_escapes(char *dest, const char *src, size_t dest_size) {
    int i = 0, j = 0;
    while (src[i] && j < dest_size - 1) {
        if (src[i] == '\\' && i + 1 < strlen(src)) {
            i++;
            if (src[i] == 'x' && i + 2 < strlen(src)) {
                // Hex escape \xHH
                i++;
                char hex[3] = {src[i], src[i+1], 0};
                char *end;
                long val = strtol(hex, &end, 16);
                if (*end == 0 || isxdigit((unsigned char)*end)) {
                    dest[j++] = (char)val;
                    i++; // skip second hex digit
                } else {
                    dest[j++] = '\\';
                    dest[j++] = 'x';
                }
            } else if (src[i] == 'n') {
                dest[j++] = '\n';
            } else if (src[i] == 'r') {
                dest[j++] = '\r';
            } else if (src[i] == 't') {
                dest[j++] = '\t';
            } else if (src[i] == 'e') {
                dest[j++] = '\033';
            } else {
                dest[j++] = '\\';
                dest[j++] = src[i];
            }
        } else {
            dest[j++] = src[i];
        }
        i++;
    }
    dest[j] = 0;
}

// ============================================================
// Command Response Generator
// ============================================================

static char *skip_shell_spaces(char *str) {
    while (*str == ' ' || *str == '\t') {
        str++;
    }
    return str;
}

static void strip_outer_quotes(char *str) {
    size_t len = strlen(str);

    if (len >= 2 && ((str[0] == '\'' && str[len - 1] == '\'') ||
                     (str[0] == '"' && str[len - 1] == '"'))) {
        memmove(str, str + 1, len - 2);
        str[len - 2] = '\0';
    }
}

static void split_command_word(char *line, char **command, char **args) {
    char *space;

    line = skip_shell_spaces(line);
    *command = line;
    space = line;

    while (*space && *space != ' ' && *space != '\t') {
        space++;
    }

    if (*space) {
        *space++ = '\0';
        *args = skip_shell_spaces(space);
    } else {
        *args = space;
    }
}

static const char *shell_basename(const char *command) {
    const char *base = strrchr(command, '/');

    return base != NULL ? base + 1 : command;
}

static void handle_echo(char *args, int sock) {
    bool flag_n = false;
    bool flag_e = false;
    char *text = args;

    args = skip_shell_spaces(args);
    while (*args == '-') {
        char *end = args;
        while (*end && *end != ' ' && *end != '\t') {
            end++;
        }

        size_t len = (size_t)(end - args);
        if (len == 2 && strncmp(args, "-n", len) == 0) {
            flag_n = true;
        } else if (len == 2 && strncmp(args, "-e", len) == 0) {
            flag_e = true;
        } else if (len == 3 && (strncmp(args, "-ne", len) == 0 || strncmp(args, "-en", len) == 0)) {
            flag_n = true;
            flag_e = true;
        } else {
            break;
        }

        args = skip_shell_spaces(end);
    }

    text = args;
    strip_outer_quotes(text);

    if (*text == '\0') {
        if (!flag_n) {
            send_str(sock, "\r\n");
        }
        return;
    }

    char decoded[CMD_BUFFER_SIZE];
    if (flag_e) {
        decode_hex_escapes(decoded, text, sizeof(decoded));
        if (flag_n) {
            send_str(sock, decoded);
        } else {
            send_line(sock, decoded);
        }
    } else {
        if (flag_n) {
            send_str(sock, text);
        } else {
            send_line(sock, text);
        }
    }
}

static void handle_wget(char *args, int sock) {
    char *url = skip_shell_spaces(args);

    if (*url == '\0') {
        send_line(sock, "BusyBox v1.20.2 (2015-04-01 10:23:44 CST) multi-call binary.");
        send_line(sock, "");
        send_line(sock, "Usage: wget [-cq] [-O FILE] [--header 'HEADER: VALUE'] URL");
        return;
    }

    // Simulate wget output - looks like it's working
    send_str(sock, "Connecting to ");
    send_line(sock, url);
    vTaskDelay(50 / portTICK_PERIOD_MS);
    send_str(sock, "Connecting to ");
    send_str(sock, url);
    send_str(sock, " (");
    
    // Simulate progress
    char progress[64];
    snprintf(progress, sizeof(progress), "%d.%d.%d.%d:%d", 
            rand() % 256, rand() % 256, rand() % 256, rand() % 256, (rand() % 60000) + 1000);
    send_str(sock, progress);
    send_line(sock, ")");
    
    // Simulate saving
    send_line(sock, "saving to STDOUT");
    send_line(sock, "");
    send_str(sock, "            0K ");
    for (int i = 0; i < 10; i++) send_str(sock, ".");
    send_line(sock, " 100%  1234K=0.1s");
    send_line(sock, "");
    
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "2025-%02d-%02d %02d:%02d:%02d",
            (rand() % 12) + 1, (rand() % 28) + 1,
            (rand() % 24), (rand() % 60), (rand() % 60));
    send_str(sock, timestamp);
    send_line(sock, " (1234 KB/s) - saved [1234567]");
}

static void handle_curl(char *args, int sock) {
    // Simulate curl output
    send_line(sock, "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current");
    send_line(sock, "                                 Dload  Upload   Total   Spent    Left  Speed");
    vTaskDelay(20 / portTICK_PERIOD_MS);
    send_line(sock, "  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0");
    vTaskDelay(20 / portTICK_PERIOD_MS);
    send_line(sock, "100  1234K  100  1234K    0     0   1234K      0  0:00:01 --:--:--  0:00:01 1234K");
}

static void handle_ls(char *args, int sock) {
    char path[64] = "/";
    
    if (*args) {
        // Has arguments
        if (!build_path(path, sizeof(path), cwd, args)) {
            char error[128];
            snprintf(error, sizeof(error), "ls: %s: File name too long", args);
            send_line(sock, error);
            return;
        }
    } else {
        strncpy(path, cwd, sizeof(path) - 1);
    }
    path[sizeof(path) - 1] = 0;
    
    // Normalize path (remove trailing /)
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') path[--len] = 0;

    if (strcmp(path, "/") == 0) {
        send_line(sock, "bin  dev  etc  mnt  proc  tmp  usr  var");
        return;
    }
    
    // Find matching entries
    int found = 0;
    for (int i = 0; filesystem[i] != NULL; i++) {
        const char *fs_path = filesystem[i];
        if (strncmp(fs_path, path, len) == 0 &&
            (fs_path[len] == 0 || fs_path[len] == '/')) {
            found = 1;
        }
    }
    
    if (!found) {
        char error[128];
        snprintf(error, sizeof(error), "ls: cannot access '%s': No such file or directory", 
                args[0] ? args : cwd);
        send_line(sock, error);
        return;
    }
    
    // List entries
    int first = 1;
    for (int i = 0; filesystem[i] != NULL; i++) {
        const char *fs_path = filesystem[i];
        if (strncmp(fs_path, path, len) == 0 && fs_path[len] == '/') {
            const char *name = fs_path + len + 1;
            if (*name) {
                // Check if it's a directory
                int is_dir = 0;
                for (int j = 0; filesystem[j] != NULL; j++) {
                    if (strncmp(filesystem[j], fs_path, strlen(fs_path)) == 0 &&
                        filesystem[j][strlen(fs_path)] == '/') {
                        is_dir = 1;
                        break;
                    }
                }
                
                if (!first) send_str(sock, "  ");
                first = 0;
                if (is_dir) {
                    char entry[32];
                    snprintf(entry, sizeof(entry), "%s/", name);
                    send_str(sock, entry);
                } else {
                    send_str(sock, name);
                }
            }
        }
    }
    
    if (!first) {
        send_str(sock, "\r\n");
    }
}

static void handle_cd(char *args, int sock) {
    char path[64];
    
    if (*args == 0) {
        // cd with no args goes to home (which is / in this case)
        strcpy(cwd, "/");
        return;
    }
    
    if (!build_path(path, sizeof(path), cwd, args)) {
        char error[128];
        snprintf(error, sizeof(error), "cd: %s: File name too long", args);
        send_line(sock, error);
        return;
    }
    path[sizeof(path) - 1] = 0;
    
    // Normalize path
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') path[--len] = 0;
    
    // Check if path exists
    int found = 0;
    for (int i = 0; filesystem[i] != NULL; i++) {
        if (strncmp(filesystem[i], path, len) == 0 &&
            (filesystem[i][len] == 0 || filesystem[i][len] == '/')) {
            found = 1;
            break;
        }
    }
    
    if (found) {
        strncpy(cwd, path, sizeof(cwd) - 1);
        cwd[sizeof(cwd) - 1] = 0;
    } else {
        char error[128];
        snprintf(error, sizeof(error), "cd: can't cd to %s: No such file or directory", args);
        send_line(sock, error);
        return;
    }
}

static void handle_pwd(int sock) {
    send_line(sock, cwd);
}

static void handle_cat(char *args, int sock) {
    if (*args == 0) {
        send_line(sock, "Usage: cat [OPTION]... [FILE]...");
        send_line(sock, "Concatenate FILE(s) and print on standard output");
        return;
    }
    
    char path[64];
    if (!build_path(path, sizeof(path), cwd, args)) {
        char error[128];
        snprintf(error, sizeof(error), "cat: %s: File name too long", args);
        send_line(sock, error);
        return;
    }
    path[sizeof(path) - 1] = 0;
    
    // Special files
    if (strcmp(path, "/proc/cpuinfo") == 0) {
        send_line(sock, "Processor	: ARMv7 Processor rev 0 (v7l)");
        send_line(sock, "BogoMIPS	: 1396.82");
        send_line(sock, "Features	: swp half thumb fastmult edsp");
        send_line(sock, "CPU implementer	: 0x41");
        send_line(sock, "CPU architecture: 7");
        send_line(sock, "CPU variant	: 0x2");
        send_line(sock, "CPU part	: 0xc07");
        send_line(sock, "CPU revision	: 0");
        send_line(sock, "");
        send_line(sock, "Hardware	: Hi3518E_V2");
        send_line(sock, "Revision	: 0000");
        return;
    }
    if (strcmp(path, "/proc/version") == 0) {
        send_line(sock, "Linux version 3.4.35 (root@localhost.localdomain) (gcc version 4.8.3 20140624 (prerelease) (Hisilicon_v1.0) ) #1 SMP PREEMPT Fri Apr 1 10:23:44 CST 2015");
        return;
    }
    if (strcmp(path, "/etc/hosts") == 0) {
        send_line(sock, "127.0.0.1	localhost");
        send_line(sock, "::1		localhost");
        return;
    }
    
    // File not found
    char error[128];
    snprintf(error, sizeof(error), "cat: %s: No such file or directory", args);
    send_line(sock, error);
}

static void handle_uname(char *args, int sock) {
    if (strcmp(args, "-a") == 0) {
        send_line(sock, "Linux hilinux-nvrbox 3.4.35 #1 SMP PREEMPT Fri Apr 1 10:23:44 CST 2015 armv7l GNU/Linux");
    } else if (strcmp(args, "-m") == 0) {
        send_line(sock, "armv7l");
    } else if (strcmp(args, "-n") == 0) {
        send_line(sock, "hilinux-nvrbox");
    } else if (strcmp(args, "-s") == 0) {
        send_line(sock, "Linux");
    } else if (*args == 0) {
        send_line(sock, "Linux");
    } else {
        send_line(sock, "Linux hilinux-nvrbox 3.4.35 #1 SMP PREEMPT Fri Apr 1 10:23:44 CST 2015 armv7l GNU/Linux");
    }
}

static void handle_id(int sock, char *args) {
    send_line(sock, "uid=0(root) gid=0(root) groups=0(root)");
}

static void handle_whoami(int sock) {
    send_line(sock, "root");
}

static void handle_hostname(int sock, char *args) {
    if (*args == 0) {
        send_line(sock, "hilinux-nvrbox");
    }
}

static void handle_help(int sock) {
    send_line(sock, "BusyBox v1.20.2 (2015-04-01 10:23:44 CST) multi-call binary.");
    send_line(sock, "Usage: busybox [function] [arguments]...");
    send_line(sock, "   or: busybox --list");
    send_line(sock, "   or: busybox --install [-s] [DIR]");
    send_line(sock, "   or: busybox --config [DIR]");
    send_line(sock, "");
    send_line(sock, "Available applets:");
    send_line(sock, "[[-o OPT] FILE], ar, ash, awk, base64, basename, cat, chmod, chown, cp, date, dd, df, dmesg,");
    send_line(sock, "echo, egrep, env, expr, false, fgrep, find, free, grep, halt, head, id, ifconfig, insmod, kill,");
    send_line(sock, "killall, klogd, ln, login, ls, lsmod, md5sum, mkdir, mknod, mnt, mount, mv, netstat, nslookup,");
    send_line(sock, "pidof, ping, poweroff, printf, ps, pwd, reboot, rm, rmdir, rmmod, route, sed, sh, sleep, sort,");
    send_line(sock, "start-stop-daemon, stop, sync, syslogd, tail, tar, telnetd, test, tftp, time, top, touch, true,");
    send_line(sock, "udhcpc, umount, uname, usleep, vi, watch, wget");
}

static void handle_busybox(char *args, int sock) {
    char *applet;
    char *applet_args;

    args = skip_shell_spaces(args);
    if (*args == 0) {
        send_line(sock, "BusyBox v1.20.2 (2015-04-01 10:23:44 CST) multi-call binary.");
        send_line(sock, "Usage: busybox [function] [arguments]...");
        send_line(sock, "   or: busybox --list");
        return;
    }

    if (strcmp(args, "--list") == 0) {
        send_line(sock, "ash");
        send_line(sock, "cat");
        send_line(sock, "chmod");
        send_line(sock, "cp");
        send_line(sock, "df");
        send_line(sock, "echo");
        send_line(sock, "ls");
        send_line(sock, "ps");
        send_line(sock, "pwd");
        send_line(sock, "rm");
        send_line(sock, "sh");
        send_line(sock, "uname");
        send_line(sock, "wget");
        return;
    }

    split_command_word(args, &applet, &applet_args);

    if (strcmp(applet, "wget") == 0) {
        handle_wget(applet_args, sock);
    } else if (strcmp(applet, "echo") == 0) {
        handle_echo(applet_args, sock);
    } else if (strcmp(applet, "curl") == 0) {
        handle_curl(applet_args, sock);
    } else if (strcmp(applet, "sh") == 0 || strcmp(applet, "ash") == 0) {
        return;
    } else {
        send_line(sock, "BusyBox v1.20.2 (2015-04-01 10:23:44 CST) multi-call binary.");
    }
}

static void handle_ps(int sock) {
    send_line(sock, "  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND");
    send_line(sock, "    1     0 root     S     1234   1%  0% /sbin/init");
    send_line(sock, "   12     1 root     S     567  0%  0% /bin/busybox udhcpc");
    send_line(sock, "   23     1 root     S     890  0%  0% /bin/busybox telnetd");
    send_line(sock, "   45     1 root     S     456  0%  0% /bin/sh");
}

static void handle_free(int sock) {
    send_line(sock, "             total         used         free       shared      buffers");
    send_line(sock, "Mem:        123456      45678      77778            0        1234");
    send_line(sock, "-/+ buffers:            44444      79012");
    send_line(sock, "Swap:            0            0            0");
}

static void handle_df(int sock, char *args) {
    send_line(sock, "Filesystem           1K-blocks      Used Available Use% Mounted on");
    send_line(sock, "/dev/mtdblock3        123456   45678    77778  37% /");
}

static void handle_unknown(const char *cmd, int sock) {
    char error[128];
    snprintf(error, sizeof(error), "sh: %s: not found", cmd);
    send_line(sock, error);
}

// ============================================================
// Main Command Processor
// ============================================================

static bool is_redirection_only(const char *cmd) {
    cmd = skip_shell_spaces((char *)cmd);

    if (*cmd == '>') {
        return true;
    }

    return cmd[0] == '2' && cmd[1] == '>';
}

static void handle_simple_command(char *line, telnet_session_t *session, int sock) {
    char *command;
    char *args;
    const char *applet;

    line = trim_whitespace(line);
    if (*line == '\0' || is_redirection_only(line)) {
        return;
    }

    session->authenticated = true;
    split_command_word(line, &command, &args);
    applet = shell_basename(command);

    if (strcmp(applet, "busybox") == 0) handle_busybox(args, sock);
    else if (strcmp(applet, "echo") == 0) handle_echo(args, sock);
    else if (strcmp(applet, "wget") == 0) handle_wget(args, sock);
    else if (strcmp(applet, "curl") == 0) handle_curl(args, sock);
    else if (strcmp(applet, "ls") == 0) handle_ls(args, sock);
    else if (strcmp(applet, "cd") == 0) handle_cd(args, sock);
    else if (strcmp(applet, "cat") == 0) handle_cat(args, sock);
    else if (strcmp(applet, "uname") == 0) handle_uname(args, sock);
    else if (strcmp(applet, "id") == 0) handle_id(sock, args);
    else if (strcmp(applet, "df") == 0) handle_df(sock, args);
    else if (strcmp(applet, "pwd") == 0) handle_pwd(sock);
    else if (strcmp(applet, "whoami") == 0) handle_whoami(sock);
    else if (strcmp(applet, "hostname") == 0) handle_hostname(sock, args);
    else if (strcmp(applet, "ps") == 0) handle_ps(sock);
    else if (strcmp(applet, "free") == 0) handle_free(sock);
    else if (strcmp(applet, "help") == 0) handle_help(sock);
    else if (strcmp(applet, "sh") == 0 || strcmp(applet, "ash") == 0) return;
    else if (strcmp(applet, "chmod") == 0 || strcmp(applet, "cp") == 0 ||
             strcmp(applet, "rm") == 0 || strcmp(applet, "touch") == 0 ||
             strcmp(applet, "mkdir") == 0) return;
    else handle_unknown(command, sock);
}

static void process_command(char *cmd, telnet_session_t *session, int sock) {
    char *segment = cmd;
    char quote = '\0';

    log_command(cmd);
    session_record_command(session, cmd);

    for (char *p = cmd; ; p++) {
        if (*p == '\'' || *p == '"') {
            if (quote == '\0') {
                quote = *p;
            } else if (quote == *p) {
                quote = '\0';
            }
        }

        if (*p == '\0' || (quote == '\0' && (*p == ';' || *p == '|' || *p == '&'))) {
            char separator = *p;
            *p = '\0';
            handle_simple_command(segment, session, sock);

            if (separator == '\0') {
                break;
            }
            if ((separator == '&' || separator == '|') && p[1] == separator) {
                p++;
            }
            segment = p + 1;
        }
    }
}

// ============================================================
// Telnet Client Handler
// ============================================================

void handle_telnet_client(void *pvParameters) {
    telnet_session_t *session = (telnet_session_t *)pvParameters;
    int client_sock = session->sock;
    char buffer[BUFFER_SIZE];
    char cmd_buffer[CMD_BUFFER_SIZE];
    char line[MAX_CAPTURE_FIELD_LEN];
    int cmd_pos = 0;
    time_t wall_clock = time(NULL);
    
    // Set TCP keepalive to detect disconnected clients
    int keepalive = 1;
    setsockopt(client_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    session->started_us = esp_timer_get_time();
    session->started_ts = wall_clock > 946684800 ? (uint64_t)wall_clock : (uint64_t)(session->started_us / 1000ULL);
    session_register(session);
    
    // Send HiLinux NVR/DVR banner
    send_line(client_sock, "");
    send_line(client_sock, "Welcome to HiLinux (NVR Box)");
    send_line(client_sock, "");
    
    // Simulate login
    send_str(client_sock, "hilinux-nvrbox login: ");
    
    if (read_client_line(client_sock, line, sizeof(line), session) < 0) {
        goto cleanup;
    }
    strncpy(session->username, trim_whitespace(line), sizeof(session->username) - 1);
    session->username[sizeof(session->username) - 1] = '\0';
    session->auth_attempts = 1;
    send_line(client_sock, "");
    
    // Send password prompt
    send_str(client_sock, "Password: ");
    
    if (read_client_line(client_sock, line, sizeof(line), session) < 0) {
        goto cleanup;
    }
    strncpy(session->password, trim_whitespace(line), sizeof(session->password) - 1);
    session->password[sizeof(session->password) - 1] = '\0';
    session->authenticated = true;
    
    // Send shell banner
    send_line(client_sock, "");
    send_line(client_sock, "BusyBox v1.20.2 (2015-04-01 10:23:44 CST) built-in shell (ash)");
    send_line(client_sock, "Enter 'help' for a list of built-in commands.");
    send_line(client_sock, "");
    
    // Send prompt
    send_str(client_sock, "hilinux-nvrbox# ");
    
    // Reset cwd for this session
    strcpy(cwd, "/");
    
    while (1) {
        int len = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (len <= 0) {
            ESP_LOGI(TAG, "Client disconnected");
            break;
        }
        buffer[len] = '\0';
        
        // Handle telnet protocol options
        handle_telnet_options((unsigned char *)buffer, len, client_sock);
        
        // Process input characters. Treat CRLF/CRNUL as one line ending.
        for (int i = 0; i < len; i++) {
            unsigned char ch = (unsigned char)buffer[i];

            if (session->skip_next_lf) {
                session->skip_next_lf = false;
                if (ch == '\n' || ch == '\0') {
                    continue;
                }
            }

            // Ignore simple Telnet IAC negotiations that arrived in this recv buffer.
            if (ch == IAC) {
                if (i + 1 < len &&
                    ((unsigned char)buffer[i + 1] == WILL ||
                     (unsigned char)buffer[i + 1] == WONT ||
                     (unsigned char)buffer[i + 1] == DO ||
                     (unsigned char)buffer[i + 1] == DONT)) {
                    i += (i + 2 < len) ? 2 : 1;
                }
                continue;
            }

            if (ch == '\r' || ch == '\n') {
                if (ch == '\r') {
                    session->skip_next_lf = true;
                }
                session_record_event(session, 'i', "\r\n", 2);
                if (cmd_pos > 0) {
                    cmd_buffer[cmd_pos] = '\0';
                    // Remove trailing whitespace
                    while (cmd_pos > 0 && (cmd_buffer[cmd_pos - 1] == '\n' || 
                                           cmd_buffer[cmd_pos - 1] == '\r' ||
                                           cmd_buffer[cmd_pos - 1] == ' ' ||
                                           cmd_buffer[cmd_pos - 1] == '\t')) {
                        cmd_pos--;
                        cmd_buffer[cmd_pos] = '\0';
                    }
                    
                    if (cmd_pos > 0) {
                        // Make a copy for processing (strtok will modify it)
                        char cmd_copy[CMD_BUFFER_SIZE];
                        strncpy(cmd_copy, cmd_buffer, sizeof(cmd_copy) - 1);
                        cmd_copy[sizeof(cmd_copy) - 1] = '\0';
                        
                        process_command(cmd_copy, session, client_sock);
                    }
                    cmd_pos = 0;
                }
                send_str(client_sock, "hilinux-nvrbox# ");
            } else if (ch >= 32 && ch <= 126) {
                // Printable character
                if (cmd_pos < sizeof(cmd_buffer) - 1) {
                    cmd_buffer[cmd_pos++] = (char)ch;
                }
                session_record_input_char(session, (char)ch);
            } else if (ch == 127 || ch == 8) {
                // Backspace
                if (cmd_pos > 0) {
                    cmd_pos--;
                }
                session_record_input_char(session, '\b');
            } else if (ch == 4) {
                // Ctrl+D - end of transmission
                session_record_input_char(session, 4);
                send_line(client_sock, "");
                send_str(client_sock, "hilinux-nvrbox# ");
            }
        }
    }
    
cleanup:
    session->duration_ms = (uint32_t)((esp_timer_get_time() - session->started_us) / 1000ULL);
    close(client_sock);
    session_unregister(session);

    attack_info_t info = {0};
    strncpy(info.ip, session->source_ip, sizeof(info.ip) - 1);
    info.port = session->source_port;
    strncpy(info.user, session->username, sizeof(info.user) - 1);
    strncpy(info.protocol, "telnet", sizeof(info.protocol) - 1);
    info.authenticated = session->authenticated;

    ensure_runtime_state();
    if (s_network_report_mutex == NULL ||
        xSemaphoreTake(s_network_report_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        if (hub_reporting_enabled()) {
            submit_attack_report(session);
        }
        intel_report_otx(&info);
        if (s_network_report_mutex != NULL) {
            xSemaphoreGive(s_network_report_mutex);
        }
    } else {
        ESP_LOGW(TAG, "Skipping network reports for %s:%d because reporter is busy",
                 session->source_ip, session->source_port);
    }

    free_session(session);
    vTaskDelete(NULL);
}

// ============================================================
// Telnet Server Startup
// ============================================================

void start_telnet_server(void) {
    ensure_runtime_state();
    int server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket");
        return;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
#ifdef SO_REUSEPORT
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    
    // Bind to port 23
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(TELNET_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Bind failed");
        close(server_sock);
        return;
    }
    
    if (listen(server_sock, MAX_CONNECTIONS) < 0) {
        ESP_LOGE(TAG, "Listen failed");
        close(server_sock);
        return;
    }
    
    ESP_LOGI(TAG, "Telnet server started on port %d (HiLinux NVR/DVR Honeypot)", TELNET_PORT);
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_sock >= 0) {
            telnet_session_t *session = calloc(1, sizeof(*session));
            if (session == NULL) {
                ESP_LOGE(TAG, "Failed to allocate telnet session");
                close(client_sock);
                continue;
            }

            session->sock = client_sock;
            session->source_port = ntohs(client_addr.sin_port);
            inet_ntoa_r(client_addr.sin_addr, session->source_ip, sizeof(session->source_ip));

            int64_t cooldown_remaining_us = 0;
            if (!ip_cooldown_allow(session->source_ip, esp_timer_get_time(), &cooldown_remaining_us)) {
                ESP_LOGI(TAG, "Dropping telnet connection from %s:%d due to %ds IP cooldown (%llds remaining)",
                         session->source_ip, session->source_port, IP_COOLDOWN_SECONDS,
                         (long long)((cooldown_remaining_us + 999999LL) / 1000000LL));
                free_session(session);
                close(client_sock);
                continue;
            }

            ESP_LOGI(TAG, "New telnet connection from %s:%d",
                    session->source_ip, session->source_port);
            
            // Show attack icon on screen
            display_show_attack();
            
            // Create task to handle client
            if (xTaskCreate(handle_telnet_client, "telnet_client", 8192,
                            session, 5, NULL) != pdPASS) {
                ESP_LOGE(TAG, "Failed to create telnet client task");
                free_session(session);
                close(client_sock);
            }
        } else {
            vTaskDelay(100 / portTICK_PERIOD_MS);
        }
    }
}
