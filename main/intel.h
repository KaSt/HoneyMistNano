#ifndef INTEL_H
#define INTEL_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    char ip[64];
    uint16_t port;
    char user[128];
    char protocol[16];
    bool authenticated;
} attack_info_t;

bool intel_report_otx(const attack_info_t *attack);
bool intel_ip_is_private(const char *ip);

#endif
