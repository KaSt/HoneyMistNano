#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <stdbool.h>
#include <stdint.h>

void config_init();
void config_get_string(const char *key, char *out, size_t max_len, const char *fallback);
int config_get_int(const char *key, int fallback);
bool config_get_bool(const char *key, bool fallback);

#endif
