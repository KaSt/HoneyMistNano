#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/gpio.h"
#include "esp_timer.h"
#include "esp_err.h"
#include "ssd1306.h"
#include "icons.h"
#include "display_task.h"

#define DISPLAY_ON_TIME_MS 30000
#define ATTACK_ICON_TIME_MS 30000

typedef enum {
    DISPLAY_CMD_BOOT,
    DISPLAY_CMD_ATTACK,
    DISPLAY_CMD_WAKE,
} display_cmd_t;

static QueueHandle_t display_queue;
static int64_t off_time_us = 0;
static bool is_on = false;

#if CONFIG_ATTACK_LED_ENABLED
static int64_t led_blink_until_us = 0;
static int64_t led_next_toggle_us = 0;
static bool led_on = false;

static void attack_led_set(bool on) {
    led_on = on;
    gpio_set_level(CONFIG_ATTACK_LED_GPIO,
                   on ? (CONFIG_ATTACK_LED_ACTIVE_LOW ? 0 : 1)
                      : (CONFIG_ATTACK_LED_ACTIVE_LOW ? 1 : 0));
}

static void attack_led_init(void) {
    gpio_config_t io_conf = {
        .pin_bit_mask = 1ULL << CONFIG_ATTACK_LED_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&io_conf));
    attack_led_set(false);
}

static void attack_led_start(void) {
    int64_t now = esp_timer_get_time();

    led_blink_until_us = now + (int64_t)CONFIG_ATTACK_LED_BLINK_MS * 1000;
    led_next_toggle_us = now + (int64_t)CONFIG_ATTACK_LED_INTERVAL_MS * 1000;
    attack_led_set(true);
}

static void attack_led_update(int64_t now) {
    if (led_blink_until_us == 0) {
        return;
    }

    if (now >= led_blink_until_us) {
        led_blink_until_us = 0;
        led_next_toggle_us = 0;
        attack_led_set(false);
        return;
    }

    if (now >= led_next_toggle_us) {
        attack_led_set(!led_on);
        led_next_toggle_us = now + (int64_t)CONFIG_ATTACK_LED_INTERVAL_MS * 1000;
    }
}

static int64_t attack_led_wait_ms(int64_t now, int64_t current_wait_ms) {
    if (led_blink_until_us == 0) {
        return current_wait_ms;
    }

    int64_t led_wait_ms = (led_next_toggle_us - now) / 1000;
    if (led_wait_ms < 1) {
        led_wait_ms = 1;
    }

    if (current_wait_ms == portMAX_DELAY || led_wait_ms < current_wait_ms) {
        return led_wait_ms;
    }

    return current_wait_ms;
}
#else
static void attack_led_init(void) {}
static void attack_led_start(void) {}
static void attack_led_update(int64_t now) { (void)now; }
static int64_t attack_led_wait_ms(int64_t now, int64_t current_wait_ms) {
    (void)now;
    return current_wait_ms;
}
#endif

void display_show_boot_logo() {
    display_cmd_t cmd = DISPLAY_CMD_BOOT;
    xQueueSend(display_queue, &cmd, 0);
}

void display_show_attack() {
    display_cmd_t cmd = DISPLAY_CMD_ATTACK;
    xQueueSend(display_queue, &cmd, 0);
}

void display_wake() {
    display_cmd_t cmd = DISPLAY_CMD_WAKE;
    xQueueSend(display_queue, &cmd, 0);
}

static void display_task(void *pvParameters) {
    display_cmd_t cmd;
    ssd1306_init(5, 6); // SDA: 5, SCL: 6
    attack_led_init();
    
    while (1) {
        int64_t now = esp_timer_get_time();
        int64_t wait_ms = 1000;
        attack_led_update(now);
        
        if (is_on) {
            int64_t remaining_ms = (off_time_us - now) / 1000;
            if (remaining_ms <= 0) {
                ssd1306_display_off();
                is_on = false;
                wait_ms = portMAX_DELAY;
            } else {
                wait_ms = remaining_ms;
            }
        } else {
            wait_ms = portMAX_DELAY;
        }
        wait_ms = attack_led_wait_ms(now, wait_ms);

        TickType_t wait_ticks = (wait_ms == portMAX_DELAY) ? portMAX_DELAY : pdMS_TO_TICKS(wait_ms);
        if (xQueueReceive(display_queue, &cmd, wait_ticks) == pdTRUE) {
            switch (cmd) {
                case DISPLAY_CMD_BOOT:
                    ssd1306_display_on();
                    ssd1306_clear();
                    ssd1306_draw_xbm((SSD1306_WIDTH - BOOT_LOGO_W) / 2, 
                                     (SSD1306_HEIGHT - BOOT_LOGO_H) / 2, 
                                     BOOT_LOGO_W, BOOT_LOGO_H, BOOT_LOGO);
                    ssd1306_refresh();
                    off_time_us = esp_timer_get_time() + (int64_t)DISPLAY_ON_TIME_MS * 1000;
                    is_on = true;
                    break;
                case DISPLAY_CMD_ATTACK:
                    ssd1306_display_on();
                    ssd1306_clear();
                    ssd1306_draw_xbm((SSD1306_WIDTH - TELNET_ICON_W) / 2, 
                                     (SSD1306_HEIGHT - TELNET_ICON_H) / 2, 
                                     TELNET_ICON_W, TELNET_ICON_H, TELNET_ICON);
                    ssd1306_refresh();
                    off_time_us = esp_timer_get_time() + (int64_t)ATTACK_ICON_TIME_MS * 1000;
                    is_on = true;
                    attack_led_start();
                    break;
                case DISPLAY_CMD_WAKE:
                    if (!is_on) {
                        ssd1306_display_on();
                        is_on = true;
                    }
                    off_time_us = esp_timer_get_time() + (int64_t)DISPLAY_ON_TIME_MS * 1000;
                    break;
            }
        }
    }
}

void display_task_start() {
    display_queue = xQueueCreate(10, sizeof(display_cmd_t));
    xTaskCreate(display_task, "display_task", 4096, NULL, 5, NULL);
}
