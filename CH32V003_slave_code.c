/*
  DUCO Miner Slave for CH32V003 (RISC-V)
  I2C slave address: 0x08
  Compile with: riscv-none-embed-gcc
  WATCHDOG ENABLED - Resets if mining loop freezes 😅
*/

#include "ch32v003fun.h"
#include <stdint.h>
#include <string.h>

// I2C slave address
#define I2C_SLAVE_ADDR 0x08 //make sure its unique or else it will be mixed up

// Watchdog timeout (seconds)
#define WDT_TIMEOUT_MS 1000

// SHA-1 constants
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))

const uint32_t sha1_k[4] = {
    0x5A827999, 0x6ED9EBA1,
    0x8F1BBCDC, 0xCA62C1D6
};

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA1_CTX;

// Mining globals
char last_hash[41];
char target_hash[41];
uint8_t target_bytes[20];
uint16_t difficulty = 10;
uint8_t has_job = 0;
uint32_t total_hashes = 0;
uint32_t accepted = 0;
uint32_t current_nonce = 0;
uint32_t max_nonce = 0;
uint8_t result[20];
uint32_t found_nonce = 0;

// I2C buffer
uint8_t i2c_rx_buffer[64];
uint8_t i2c_rx_len = 0;
uint8_t i2c_state = 0;

// Watchdog counter
uint32_t last_wdt_feed = 0;

// ==================== WATCHDOG FUNCTIONS ====================

void IWDG_Feed(void) {
    IWDG->KR = 0xAAAA;
}

void IWDG_Init(uint16_t timeout_ms) {
    // Enable write access to IWDG registers
    IWDG->KR = 0x5555;
    
    // Set prescaler to 64 (approx 1 tick per 1ms at 128kHz LSI)
    IWDG->PR = 0x04;  // Prescaler = 64
    
    // Calculate reload value
    // LSI = 128kHz, prescaler 64 = 2000 Hz (0.5ms per tick)
    // For timeout_ms, reload = timeout_ms * 2
    uint16_t reload = timeout_ms * 2;
    IWDG->RLR = reload;
    
    // Enable write protection
    IWDG->KR = 0xCCCC;
    
    // Start watchdog
    IWDG->KR = 0xCCCC;
}

// ==================== SHA-1 IMPLEMENTATION ====================

void sha1_transform(SHA1_CTX *ctx) {
    uint32_t w[80];
    uint32_t a, b, c, d, e, temp;
    uint8_t i;
    
    for (i = 0; i < 16; i++) {
        w[i] = (ctx->buffer[i*4] << 24) | (ctx->buffer[i*4+1] << 16) |
               (ctx->buffer[i*4+2] << 8) | ctx->buffer[i*4+3];
    }
    for (i = 16; i < 80; i++) {
        w[i] = ROTLEFT(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    
    for (i = 0; i < 20; i++) {
        temp = ROTLEFT(a,5) + ((b&c)|(~b&d)) + e + w[i] + sha1_k[0];
        e = d; d = c; c = ROTLEFT(b,30); b = a; a = temp;
    }
    for (i = 20; i < 40; i++) {
        temp = ROTLEFT(a,5) + (b^c^d) + e + w[i] + sha1_k[1];
        e = d; d = c; c = ROTLEFT(b,30); b = a; a = temp;
    }
    for (i = 40; i < 60; i++) {
        temp = ROTLEFT(a,5) + ((b&c)|(b&d)|(c&d)) + e + w[i] + sha1_k[2];
        e = d; d = c; c = ROTLEFT(b,30); b = a; a = temp;
    }
    for (i = 60; i < 80; i++) {
        temp = ROTLEFT(a,5) + (b^c^d) + e + w[i] + sha1_k[3];
        e = d; d = c; c = ROTLEFT(b,30); b = a; a = temp;
    }
    
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_init(SHA1_CTX *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count[0] = ctx->count[1] = 0;
}

void sha1_update(SHA1_CTX *ctx, const uint8_t *data, uint8_t len) {
    uint8_t i, index, partLen;
    
    index = (ctx->count[0] >> 3) & 63;
    ctx->count[0] += (len << 3);
    if (ctx->count[0] < (len << 3)) ctx->count[1]++;
    ctx->count[1] += (len >> 29);
    
    partLen = 64 - index;
    
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        sha1_transform(ctx);
        for (i = partLen; i + 63 < len; i += 64) {
            memcpy(ctx->buffer, &data[i], 64);
            sha1_transform(ctx);
        }
        index = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

void sha1_final(SHA1_CTX *ctx, uint8_t *digest) {
    uint8_t bits[8];
    uint8_t i, index, padLen;
    uint8_t padding[64];
    
    for (i = 0; i < 8; i++) {
        bits[i] = (ctx->count[i >> 2] >> ((3 - (i & 3)) * 8)) & 0xFF;
    }
    
    index = (ctx->count[0] >> 3) & 63;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    
    padding[0] = 0x80;
    for (i = 1; i < padLen; i++) padding[i] = 0;
    
    sha1_update(ctx, padding, padLen);
    sha1_update(ctx, bits, 8);
    
    for (i = 0; i < 20; i++) {
        digest[i] = (ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 0xFF;
    }
}

void sha1_string(const char* input, uint8_t* output) {
    SHA1_CTX ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t*)input, strlen(input));
    sha1_final(&ctx, output);
}

// ==================== HELPER FUNCTIONS ====================

uint8_t hex_char_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

void hex_to_bytes(const char* hex, uint8_t* bytes, uint8_t len) {
    uint8_t i;
    for (i = 0; i < len; i++) {
        bytes[i] = (hex_char_to_byte(hex[i*2]) << 4) | hex_char_to_byte(hex[i*2+1]);
    }
}

void uint32_to_str(uint32_t num, char* out) {
    char temp[12];
    uint8_t i = 0;
    
    if (num == 0) {
        out[0] = '0';
        out[1] = '\0';
        return;
    }
    
    while (num > 0) {
        temp[i++] = '0' + (num % 10);
        num /= 10;
    }
    
    for (uint8_t j = 0; j < i; j++) {
        out[j] = temp[i - 1 - j];
    }
    out[i] = '\0';
}

// ==================== MINING LOOP WITH WATCHDOG ====================

void mine(void) {
    char input_str[52];
    char nonce_str[12];
    uint32_t nonce;
    
    if (!has_job) return;
    
    max_nonce = difficulty * 100;
    if (max_nonce < 1000) max_nonce = 1000;
    if (max_nonce > 30000) max_nonce = 30000;
    
    strcpy(input_str, last_hash);
    uint8_t hash_len = strlen(last_hash);
    
    for (nonce = 0; nonce < max_nonce && has_job; nonce++) {
        uint32_to_str(nonce, nonce_str);
        strcpy(input_str + hash_len, nonce_str);
        sha1_string(input_str, result);
        total_hashes++;
        
        if (memcmp(result, target_bytes, 20) == 0) {
            found_nonce = nonce;
            has_job = 0;
            accepted++;
            return;
        }
        
        // Feed watchdog every 256 nonces
        if ((nonce & 0xFF) == 0) {
            IWDG_Feed();
        }
    }
    
    if (has_job) {
        has_job = 0;
    }
}

// ==================== I2C SLAVE HANDLER ====================

void I2C_Slave_Handler(void) __attribute__((interrupt));
void I2C_Slave_Handler(void) {
    uint8_t data;
    uint8_t status = I2C0->STAR1;
    
    if (status & (1 << 6)) {  // ADDRF
        I2C0->STAR1 &= ~(1 << 6);
    }
    else if (status & (1 << 5)) {  // STOPF
        I2C0->STAR1 &= ~(1 << 5);
        i2c_state = 0;
        i2c_rx_len = 0;
        
        if (i2c_rx_len > 4 && i2c_rx_buffer[0] == 'J') {
            // Parse JOB command
            int i;
            for (i = 0; i < 40 && (i+1) < i2c_rx_len; i++) {
                last_hash[i] = i2c_rx_buffer[i+1];
            }
            last_hash[i] = '\0';
            
            // Also parse target hash
            int j;
            for (j = 0; j < 40 && (i+j+2) < i2c_rx_len; j++) {
                target_hash[j] = i2c_rx_buffer[i+j+2];
            }
            target_hash[j] = '\0';
            
            hex_to_bytes(target_hash, target_bytes, 20);
            has_job = 1;
            found_nonce = 0;
        }
    }
    else if (status & (1 << 7)) {  // RXNE
        data = I2C0->DATAR;
        if (i2c_state == 0 && i2c_rx_len < 64) {
            i2c_rx_buffer[i2c_rx_len++] = data;
        }
    }
    else if (status & (1 << 4)) {  // TXE
        if (found_nonce != 0) {
            I2C0->DATAR = (found_nonce >> 24) & 0xFF;
            IWDG_Feed();  // Feed watchdog during I2C
        } else {
            I2C0->DATAR = 0;
        }
    }
    
    IWDG_Feed();  // Feed watchdog on every interrupt
    I2C0->STAR1 = 0;
}

void I2C_Slave_Init(void) {
    RCC->APB1PCENR |= RCC_APB1ENR_I2C0EN;
    
    // Configure PB6 as SCL, PB7 as SDA
    GPIOB->CFGLR &= ~(0xF << (6*4));
    GPIOB->CFGLR |= (GPIO_Speed_10MHz | GPIO_CNF_OUT_OD) << (6*4);
    GPIOB->CFGLR &= ~(0xF << (7*4));
    GPIOB->CFGLR |= (GPIO_Speed_10MHz | GPIO_CNF_OUT_OD) << (7*4);
    
    I2C0->CTLR1 = 0;
    I2C0->CTLR2 = (1 << 10) | (1 << 9);  // ACK enable, DMA disable
    I2C0->OADDR1 = I2C_SLAVE_ADDR << 1;
    I2C0->CTLR1 = (1 << 0) | (1 << 2);   // PE, ENGC
    I2C0->CTLR2 |= (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7);  // Interrupt enable
    
    NVIC_EnableIRQ(I2C0_IRQn);
}

// ==================== MAIN ====================

int main(void) {
    SystemInit();
    
    // Configure PB1 as LED
    GPIOB->CFGLR &= ~(0xF << (1*4));
    GPIOB->CFGLR |= (GPIO_Speed_10MHz | GPIO_CNF_OUT_PP) << (1*4);
    
    // Initialize watchdog (1 second timeout)
    IWDG_Init(WDT_TIMEOUT_MS);
    last_wdt_feed = 0;
    
    I2C_Slave_Init();
    
    // Blink LED to show alive
    GPIOB->BSHR = (1 << 1);
    Delay_Ms(200);
    GPIOB->BSHR = (1 << (1 + 16));
    Delay_Ms(200);
    GPIOB->BSHR = (1 << 1);
    Delay_Ms(200);
    GPIOB->BSHR = (1 << (1 + 16));
    
    // Feed watchdog after boot
    IWDG_Feed();
    
    while (1) {
        if (has_job) {
            mine();
        }
        
        // Feed watchdog every main loop iteration, so no more hanging yay
        IWDG_Feed();
        
        Delay_Ms(1);
    }
}