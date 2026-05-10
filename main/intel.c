#include <stdio.h>
#include <string.h>
#include "intel.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "intel";

bool intel_ip_is_private(const char *ip) {
    if (!ip || ip[0] == '\0') return true;
    if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0) return true;
    if (strncmp(ip, "10.", 3) == 0) return true;
    if (strncmp(ip, "192.168.", 8) == 0) return true;
    if (strncmp(ip, "169.254.", 8) == 0) return true;
    if (strncmp(ip, "172.", 4) == 0) {
        int second;
        if (sscanf(ip + 4, "%d", &second) == 1) {
            if (second >= 16 && second <= 31) return true;
        }
    }
    return false;
}

static char cached_pulse_id[64] = {0};
static char cached_pulse_name[128] = {0};
static SemaphoreHandle_t otx_mutex;
static int64_t otx_create_backoff_until_us;
#define OTX_CREATE_BACKOFF_US (5LL * 60LL * 1000000LL)
#define OTX_COOLDOWN_ENTRIES 64

#ifndef CONFIG_OTX_PULSE_ID
#define CONFIG_OTX_PULSE_ID ""
#endif

#ifndef CONFIG_OTX_REPORT_COOLDOWN_SECONDS
#define CONFIG_OTX_REPORT_COOLDOWN_SECONDS 900
#endif

typedef struct {
    char ip[64];
    int64_t last_report_us;
} otx_cooldown_entry_t;

static otx_cooldown_entry_t otx_cooldown[OTX_COOLDOWN_ENTRIES];

static char* create_pulse(const attack_info_t *seed);

static bool otx_cooldown_allow(const char *ip, int64_t now_us, int64_t *remaining_us) {
    int empty_slot = -1;
    int oldest_slot = 0;
    int64_t oldest_seen_us = INT64_MAX;
    int64_t cooldown_us = (int64_t)CONFIG_OTX_REPORT_COOLDOWN_SECONDS * 1000000LL;

    if (remaining_us != NULL) {
        *remaining_us = 0;
    }

    if (cooldown_us <= 0 || ip == NULL || ip[0] == '\0') {
        return true;
    }

    for (int i = 0; i < OTX_COOLDOWN_ENTRIES; i++) {
        if (otx_cooldown[i].ip[0] == '\0') {
            if (empty_slot < 0) {
                empty_slot = i;
            }
            continue;
        }

        if (strcmp(otx_cooldown[i].ip, ip) == 0) {
            int64_t elapsed = now_us - otx_cooldown[i].last_report_us;
            if (elapsed >= 0 && elapsed < cooldown_us) {
                if (remaining_us != NULL) {
                    *remaining_us = cooldown_us - elapsed;
                }
                return false;
            }
            return true;
        }

        if (otx_cooldown[i].last_report_us < oldest_seen_us) {
            oldest_seen_us = otx_cooldown[i].last_report_us;
            oldest_slot = i;
        }
    }

    (void)empty_slot;
    (void)oldest_slot;
    return true;
}

static void otx_cooldown_commit(const char *ip, int64_t now_us) {
    int empty_slot = -1;
    int oldest_slot = 0;
    int64_t oldest_seen_us = INT64_MAX;

    if (ip == NULL || ip[0] == '\0' || CONFIG_OTX_REPORT_COOLDOWN_SECONDS <= 0) {
        return;
    }

    for (int i = 0; i < OTX_COOLDOWN_ENTRIES; i++) {
        if (otx_cooldown[i].ip[0] == '\0') {
            if (empty_slot < 0) {
                empty_slot = i;
            }
            continue;
        }

        if (strcmp(otx_cooldown[i].ip, ip) == 0) {
            otx_cooldown[i].last_report_us = now_us;
            return;
        }

        if (otx_cooldown[i].last_report_us < oldest_seen_us) {
            oldest_seen_us = otx_cooldown[i].last_report_us;
            oldest_slot = i;
        }
    }

    int slot = empty_slot >= 0 ? empty_slot : oldest_slot;
    snprintf(otx_cooldown[slot].ip, sizeof(otx_cooldown[slot].ip), "%s", ip);
    otx_cooldown[slot].last_report_us = now_us;
}

static void load_pulse_id() {
    nvs_handle_t handle;
    if (nvs_open("otx_cache", NVS_READONLY, &handle) == ESP_OK) {
        size_t size = sizeof(cached_pulse_id);
        nvs_get_str(handle, "pulse_id", cached_pulse_id, &size);
        size = sizeof(cached_pulse_name);
        nvs_get_str(handle, "pulse_name", cached_pulse_name, &size);
        nvs_close(handle);
    }
}

static void save_pulse_id(const char *id, const char *name) {
    nvs_handle_t handle;
    if (nvs_open("otx_cache", NVS_READWRITE, &handle) == ESP_OK) {
        nvs_set_str(handle, "pulse_id", id);
        nvs_set_str(handle, "pulse_name", name != NULL ? name : "");
        nvs_commit(handle);
        nvs_close(handle);
    }

    snprintf(cached_pulse_id, sizeof(cached_pulse_id), "%s", id != NULL ? id : "");
    snprintf(cached_pulse_name, sizeof(cached_pulse_name), "%s", name != NULL ? name : "");
}

static const char *ensure_pulse_id(const attack_info_t *attack) {
    int64_t now_us;
    char *created_id;

    if (CONFIG_OTX_PULSE_ID[0] != '\0') {
        return CONFIG_OTX_PULSE_ID;
    }

    if (cached_pulse_id[0] == '\0') {
        load_pulse_id();
    }

    if (cached_pulse_id[0] != '\0' &&
        (cached_pulse_name[0] == '\0' || strcmp(cached_pulse_name, CONFIG_OTX_PULSE_NAME) == 0)) {
        return cached_pulse_id;
    }

    now_us = esp_timer_get_time();
    if (now_us < otx_create_backoff_until_us) {
        ESP_LOGW(TAG, "Skipping OTX pulse creation during backoff (%llds remaining)",
                 (long long)((otx_create_backoff_until_us - now_us + 999999LL) / 1000000LL));
        return NULL;
    }

    created_id = create_pulse(attack);
    if (created_id == NULL) {
        otx_create_backoff_until_us = now_us + OTX_CREATE_BACKOFF_US;
        return NULL;
    }

    save_pulse_id(created_id, CONFIG_OTX_PULSE_NAME);
    free(created_id);
    return cached_pulse_id;
}

static char* create_pulse(const attack_info_t *seed) {
    esp_http_client_config_t config = {
        .url = "https://otx.alienvault.com/api/v1/pulses/create",
        .method = HTTP_METHOD_POST,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 10000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) return NULL;

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "name", CONFIG_OTX_PULSE_NAME);
    cJSON_AddStringToObject(root, "description", "Live capture of brute-force login attempts against an ESP32-C3 honeypot (HoneyMistNano).");
    cJSON_AddBoolToObject(root, "public", false);
    
    cJSON *tags = cJSON_AddArrayToObject(root, "tags");
    cJSON_AddItemToArray(tags, cJSON_CreateString("honeypot"));
    cJSON_AddItemToArray(tags, cJSON_CreateString("brute-force"));
    cJSON_AddItemToArray(tags, cJSON_CreateString("telnet"));

    cJSON *inds = cJSON_AddArrayToObject(root, "indicators");
    cJSON *i0 = cJSON_CreateObject();
    cJSON_AddStringToObject(i0, "type", "IPv4");
    cJSON_AddStringToObject(i0, "indicator", seed->ip);
    cJSON_AddStringToObject(i0, "role", "bruteforce");
    char title[64];
    snprintf(title, sizeof(title), "%s login attempt", seed->protocol);
    cJSON_AddStringToObject(i0, "title", title);
    cJSON_AddItemToArray(inds, i0);

    char *post_data = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    esp_http_client_set_header(client, "X-OTX-API-KEY", CONFIG_OTX_API_KEY);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, post_data, strlen(post_data));

    esp_err_t err = esp_http_client_perform(client);
    char *new_id = NULL;

    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        if (status >= 200 && status < 300) {
            char buffer[1024];
            int len = esp_http_client_read_response(client, buffer, sizeof(buffer) - 1);
            if (len > 0) {
                buffer[len] = '\0';
                cJSON *resp = cJSON_Parse(buffer);
                if (resp) {
                    cJSON *id_node = cJSON_GetObjectItem(resp, "id");
                    if (cJSON_IsString(id_node)) {
                        new_id = strdup(id_node->valuestring);
                    }
                    cJSON_Delete(resp);
                }
            }
        } else {
            ESP_LOGE(TAG, "Pulse creation failed with status %d", status);
        }
    } else {
        ESP_LOGE(TAG, "Pulse creation request failed: %s", esp_err_to_name(err));
    }

    free(post_data);
    esp_http_client_cleanup(client);
    return new_id;
}

void intel_report_otx(const attack_info_t *attack) {
#ifndef CONFIG_OTX_ENABLED
    return;
#else
    const char *pulse_id;
    int64_t now_us;
    int64_t cooldown_remaining_us = 0;
    if (!CONFIG_OTX_ENABLED || strlen(CONFIG_OTX_API_KEY) == 0) return;
    if (intel_ip_is_private(attack->ip)) return;

    if (otx_mutex == NULL) {
        otx_mutex = xSemaphoreCreateMutex();
    }
    if (otx_mutex != NULL) {
        xSemaphoreTake(otx_mutex, portMAX_DELAY);
    }

    now_us = esp_timer_get_time();
    if (!otx_cooldown_allow(attack->ip, now_us, &cooldown_remaining_us)) {
        ESP_LOGI(TAG, "Skipping OTX report for %s during cooldown (%llds remaining)",
                 attack->ip, (long long)((cooldown_remaining_us + 999999LL) / 1000000LL));
        if (otx_mutex != NULL) {
            xSemaphoreGive(otx_mutex);
        }
        return;
    }

    pulse_id = ensure_pulse_id(attack);
    if (pulse_id == NULL || pulse_id[0] == '\0') {
        if (otx_mutex != NULL) {
            xSemaphoreGive(otx_mutex);
        }
        return;
    }

    char url[128];
    snprintf(url, sizeof(url), "https://otx.alienvault.com/api/v1/pulses/%s", pulse_id);

    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_PATCH,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 10000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        if (otx_mutex != NULL) {
            xSemaphoreGive(otx_mutex);
        }
        return;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *indicators = cJSON_AddObjectToObject(root, "indicators");
    cJSON *add = cJSON_AddArrayToObject(indicators, "add");
    cJSON *i = cJSON_CreateObject();
    cJSON_AddStringToObject(i, "type", "IPv4");
    cJSON_AddStringToObject(i, "indicator", attack->ip);
    cJSON_AddStringToObject(i, "role", "bruteforce");
    char title[64];
    snprintf(title, sizeof(title), "%s login attempt", attack->protocol);
    cJSON_AddStringToObject(i, "title", title);
    
    char desc[256];
    snprintf(desc, sizeof(desc), "Brute-force capture. user='%s' proto=%s", attack->user, attack->protocol);
    cJSON_AddStringToObject(i, "description", desc);
    cJSON_AddItemToArray(add, i);

    char *patch_data = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    esp_http_client_set_header(client, "X-OTX-API-KEY", CONFIG_OTX_API_KEY);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, patch_data, strlen(patch_data));

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        if (status >= 200 && status < 300) {
            otx_cooldown_commit(attack->ip, now_us);
            ESP_LOGI(TAG, "Successfully reported %s to OTX pulse %s", attack->ip, pulse_id);
        } else if (status == 404) {
            ESP_LOGW(TAG, "OTX pulse %s not found (404)%s", pulse_id,
                     CONFIG_OTX_PULSE_ID[0] != '\0' ? "" : ", clearing cache");
            if (CONFIG_OTX_PULSE_ID[0] == '\0') {
                save_pulse_id("", "");
            }
        } else {
            ESP_LOGE(TAG, "OTX report failed with status %d", status);
        }
    } else {
        ESP_LOGE(TAG, "OTX report request failed: %s", esp_err_to_name(err));
    }

    free(patch_data);
    esp_http_client_cleanup(client);
    if (otx_mutex != NULL) {
        xSemaphoreGive(otx_mutex);
    }
#endif
}
