#ifndef SDP_H_
#define SDP_H_

#include <stdint.h>
#include <string.h>
#include "config.h"

#define SDP_ATTR_LENGTH 128

#ifndef ICE_LITE
#define ICE_LITE 0
#endif

void sdp_append_h264(char* sdp);
/* answerer 용: offer 가 제시한 payload type / mid 를 그대로 쓰고 방향을 sendonly 로 둘 수 있다 */
void sdp_append_h264_pt(char* sdp, int pt, const char* mid, int sendonly);

void sdp_append_h265(char* sdp);

void sdp_append_pcma(char* sdp);

void sdp_append_pcmu(char* sdp);

void sdp_append_opus(char* sdp, uint32_t audio_sample_rate);

void sdp_append_datachannel(char* sdp);

void sdp_create(char* sdp, int b_video, int b_audio, int b_datachannel);
void sdp_create_mid(char* sdp, int b_video, int b_audio, int b_datachannel, const char* video_mid);

int sdp_append(char* sdp, const char* format, ...);

void sdp_reset(char* sdp);

#endif  // SDP_H_
