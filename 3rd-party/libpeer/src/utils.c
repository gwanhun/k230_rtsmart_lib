#include "utils.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if CONFIG_USE_HWRNG
#include "drv_pufs.h"
#include <pthread.h>
#elif CONFIG_USE_LWIP
#include "mbedtls/entropy.h"
#else
#include <sys/random.h>
#endif
#include "mbedtls/md.h"

#if CONFIG_USE_HWRNG
static pthread_mutex_t hardware_rng_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

int utils_random_bytes(uint8_t* output, size_t len) {
  if (output == NULL && len != 0) {
    return -1;
  }
  if (len == 0) {
    return 0;
  }

#if CONFIG_USE_HWRNG
  drv_pufs_inst dev;
  int ret;

  /* RT-Smart's getrandom() uses a deterministic PRNG, not the hardware RNG. */
  if (len > UINT32_MAX || pthread_mutex_lock(&hardware_rng_mutex) != 0) {
    return -1;
  }

  /* Concurrent handshakes must not overlap the /dev/pufs file lifecycle. */
  if (drv_pufs_open(&dev) != 0) {
    pthread_mutex_unlock(&hardware_rng_mutex);
    return -1;
  }

  ret = drv_pufs_rng_read(&dev, output, (uint32_t)len);
  drv_pufs_close(&dev);
  pthread_mutex_unlock(&hardware_rng_mutex);
  return ret == 0 ? 0 : -1;
#elif CONFIG_USE_LWIP
  mbedtls_entropy_context entropy;
  int ret;

  mbedtls_entropy_init(&entropy);
  ret = mbedtls_entropy_func(&entropy, output, len);
  mbedtls_entropy_free(&entropy);
  return ret == 0 ? 0 : -1;
#else
  size_t offset = 0;

  while (offset < len) {
    ssize_t ret = getrandom(output + offset, len - offset, 0);
    if (ret > 0) {
      offset += (size_t)ret;
      continue;
    }
    if (ret < 0 && errno == EINTR) {
      continue;
    }
    return -1;
  }
  return 0;
#endif
}

int utils_random_string(char* s, const int len) {
  int offset = 0;
  uint8_t random_bytes[32];

  static const char alphanum[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";

  if (s == NULL || len < 0) {
    return -1;
  }

  while (offset < len) {
    if (utils_random_bytes(random_bytes, sizeof(random_bytes)) != 0) {
      s[0] = '\0';
      return -1;
    }
    for (size_t i = 0; i < sizeof(random_bytes) && offset < len; i++) {
      /* Ignore the top eight values to avoid modulo bias (248 is 4 * 62). */
      if (random_bytes[i] < 248) {
        s[offset++] = alphanum[random_bytes[i] % (sizeof(alphanum) - 1)];
      }
    }
  }

  s[len] = '\0';
  return 0;
}

int utils_get_hmac_sha1(const char* input, size_t input_len, const char* key, size_t key_len, unsigned char* output) {
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  int ret;

  if (!md_info) {
    return -1;
  }

  mbedtls_md_init(&ctx);
  ret = mbedtls_md_setup(&ctx, md_info, 1);
  if (ret == 0) {
    ret = mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key, key_len);
  }
  if (ret == 0) {
    ret = mbedtls_md_hmac_update(&ctx, (const unsigned char*)input, input_len);
  }
  if (ret == 0) {
    ret = mbedtls_md_hmac_finish(&ctx, output);
  }
  mbedtls_md_free(&ctx);
  return ret;
}

void utils_get_md5(const char* input, size_t input_len, unsigned char* output) {
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_MD5;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char*)input, input_len);
  mbedtls_md_finish(&ctx, output);
  mbedtls_md_free(&ctx);
}


#if LOG_REDIRECT
/* libpeer 로그를 링버퍼에 모아 MicroPython(webrtc.log_read)이 꺼내 찍게 한다.
 * 기본 fprintf(stdout) 는 K230 에서 USB 콘솔이 아닌 디버그 UART 로 나가 보이지 않았다(2026-10-21). */
#include <stdarg.h>
#include <pthread.h>
#define PEER_LOG_BUF 16384
static char s_log_buf[PEER_LOG_BUF];
static int s_log_len = 0;
static int s_log_dropped = 0;
static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;

void peer_log(char* level_tag, const char* file_name, int line_number, const char* fmt, ...) {
  char line[256];
  const char* base = strrchr(file_name, '/');
  int n, m, total;
  va_list ap;
  base = base ? base + 1 : file_name;
  n = snprintf(line, sizeof(line), "%s %s:%d ", level_tag, base, line_number);
  if (n < 0) n = 0;
  if (n > (int)sizeof(line) - 2) n = (int)sizeof(line) - 2;
  va_start(ap, fmt);
  m = vsnprintf(line + n, sizeof(line) - n - 1, fmt, ap);
  va_end(ap);
  if (m < 0) m = 0;
  total = n + m;
  if (total > (int)sizeof(line) - 2) total = (int)sizeof(line) - 2;
  line[total++] = '\n';
  pthread_mutex_lock(&s_log_mutex);
  if (s_log_len + total <= PEER_LOG_BUF) {
    memcpy(s_log_buf + s_log_len, line, total);
    s_log_len += total;
  } else {
    s_log_dropped++;
  }
  pthread_mutex_unlock(&s_log_mutex);
}

int peer_log_read(char* out, int max, int* dropped) {
  int n;
  pthread_mutex_lock(&s_log_mutex);
  n = s_log_len < max ? s_log_len : max;
  if (n > 0) {
    memcpy(out, s_log_buf, n);
    memmove(s_log_buf, s_log_buf + n, s_log_len - n);
    s_log_len -= n;
  }
  if (dropped) {
    *dropped = s_log_dropped;
    s_log_dropped = 0;
  }
  pthread_mutex_unlock(&s_log_mutex);
  return n;
}
#endif
