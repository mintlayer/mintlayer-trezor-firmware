#include "common.h"

__attribute__((noreturn)) void error_shutdown_rust(const char* title,
                                                   const char* msg,
                                                   const char* footer);

uint32_t mintlayer_screen_fatal_error_rust(const char* title, const char* msg,
                                           const char* footer);

typedef struct {
  const uint8_t* data;
  uint32_t len;
} ByteArray;

ByteArray mintlayer_encode_utxo_input(const unsigned char* hex,
                                      uint32_t hex_len, uint32_t index);

void screen_boot_stage_2(void);

void display_image(int16_t x, int16_t y, const uint8_t* data, uint32_t datalen);
void display_icon(int16_t x, int16_t y, const uint8_t* data, uint32_t datalen,
                  uint16_t fg_color, uint16_t bg_color);
