# HoneyMistNano

A lightweight, visually interactive Telnet honeypot for the **ESP32-C3 SuperMini**. 

## A word from the human 

This repository was vibe coded with the idea to see if another AI could do a minimal ESP32-C3 client for my own honeypot hub here https://honeyopus.ka.st (see the ESP32 code here: https://github.com/kast/honeyopus). This development was first assigned to Mistral (mistral-medium-3.5) using "vibe", as requirements it received the hub protocol paper, instructions to develop on an ESP32-C3. It provided the whole code, but it didn't compile and was out of tokens (free tier). I then switched to Codex with GPT 5.4 (don't know why I switched from 5.5 to this one) to fix the code and make it build. Then it fixed a few more bugs in the CR/LF handling, protocol handling. Finally, I got Gemini (gemini-3-flash-preview) to work on Oled support, reporting to Alienvault OTX, configurable attack cooldown and probably a couple things more. That's it, for the explanation. Rest is AI.

## What is this?

HoneyMistNano simulates a **generic embedded IoT appliance** environment, specifically targeting the common administrative interfaces of networked surveillance equipment and video recorders. It captures credentials, commands, and full session transcripts (asciinema-compatible) and reports them to a **HoneyOpus Hub** instance.

## ✨ Features

- **Embedded Environment Simulation:** Mimics a BusyBox-based shell typical of many networked appliances, complete with common IoT vulnerabilities.
- **Visual Feedback:** 
  - **OLED Support:** Custom driver optimized for the **72x40 SSD1306** (EastRising style) with correct column offsets.
  - **Boot Logo:** Stylish startup splash screen.
  - **Attack Icons:** Displays a CRT terminal icon when an attacker connects.
  - **Attack LED:** Blinks a configurable GPIO LED on attacker connection; defaults to GPIO 8 active-low for common ESP32-C3 SuperMini boards.
  - **Power Save:** Automatically dims the screen after 30 seconds of inactivity.
- **Forensic Capture:**
  - Full input/output transcripts.
  - Command history extraction.
  - Metadata: IP, port, credentials, and session duration.
- **Smart Throttling:** Configurable IP cooldown (3 minutes default) prevents flooding from single-source automated scanners.
- **Threat Intelligence:** Optional reporting to **AlienVault OTX**; supports automatic Pulse creation and IP deduplication.
- **Cloud Integration:** Reports in real-time to HoneyOpus Hub using the `v1` ingest protocol.

## 🛠 Hardware Requirements

- **MCU:** ESP32-C3 SuperMini.
- **Display:** 0.42" OLED (SSD1306, 72x40) connected via I2C.
  - **SDA:** GPIO 5
  - **SCL:** GPIO 6
  - **Driver Note:** Includes hardcoded column offsets for proper 72x40 centering.
- **Optional Button:** GPIO 9 for waking the screen.
- **Optional/Onboard LED:** GPIO 8 active-low by default, configurable in menuconfig.

## 🚀 Getting Started

1. **Configure via Menuconfig:**
   Use `idf.py menuconfig` to set your configuration under the **HoneyMist Nano** menu:
   - **WiFi:** SSID and Password.
   - **Hub:** URL and Bearer Token.
   - **Cooldown:** Set the IP throttling window (default 180s).
   - **OTX:** Enable reporting, set your AlienVault API key, optionally set an existing Pulse ID, and tune the per-IP report cooldown. If no Pulse ID is configured, the first report creates one and caches it in NVS.

2. **Build & Flash:**
   ```bash
   idf.py build
   idf.py flash monitor
   ```

## 📜 License

MIT License. See `LICENSE` for details.

---
*Captured by HoneyMistNano — Securing the IoT, one honey-drip at a time.*
