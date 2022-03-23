#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

struct GDPClient;

using GdpName = uint8_t[32];

extern "C" {

int8_t new_ffi(GDPClient *out, uint16_t lib_port, uint16_t sidecar_port);

int8_t send_packet_ffi(const GDPClient *self,
                       const GdpName *dest,
                       const uint8_t *payload,
                       uintptr_t payload_len);

} // extern "C"
