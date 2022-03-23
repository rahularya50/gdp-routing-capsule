from libc.stdint cimport int8_t, int16_t, int32_t, int64_t, intptr_t
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, uintptr_t
cdef extern from *:
  ctypedef bint bool
  ctypedef struct va_list

cdef extern from *:

  cdef struct GDPClient:
    pass

  ctypedef uint8_t GdpName[32];

  int8_t send_packet_ffi(const GDPClient *self,
                         const GdpName *dest,
                         const uint8_t *payload,
                         uintptr_t payload_len);
