// idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Write the frames a case saw as a libpcap capture, so a failing exchange opens in Wireshark.
//
// The framing is ProtoCore's, src/shared/pcap/pcap.h and pcap.c: the classic 24-octet global
// header and 16-octet per-record header, every field little-endian, magic 0xa1b2c3d4 for
// microsecond timestamps. That renderer declares DLT_RAW and synthesizes an IP and a UDP header
// around a logged datagram, because its records start at the IP header. This one has whole
// Ethernet II frames as they went on the wire, so it declares DLT_EN10MB and synthesizes nothing.
//
// Two layers: the two header writers put their octets in the caller's buffer and are what a case
// asserts the layout on, and the file writer puts a capture on disk through them.
//
// test/ is exempt from the src/ style rules, so this reads as plain host C.

#ifndef IDEMIP_TEST_PCAP_H
#define IDEMIP_TEST_PCAP_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/** libpcap header sizes. */
#define IDEMIP_PCAP_GLOBAL_HDR_LEN 24u
#define IDEMIP_PCAP_REC_HDR_LEN 16u

/** libpcap DLT link-layer types. */
#define IDEMIP_DLT_EN10MB 1u ///< IEEE 802.3 Ethernet, the record starts at the destination address
#define IDEMIP_DLT_RAW 101u  ///< the record starts at the IP header, with no link layer

/** The magic a little-endian file with microsecond timestamps opens with. */
#define IDEMIP_PCAP_MAGIC_USEC 0xA1B2C3D4u

/** Version 2.4, which every libpcap reader takes. */
#define IDEMIP_PCAP_VERSION_MAJOR 2u
#define IDEMIP_PCAP_VERSION_MINOR 4u

/** The longest record the file declares it stores. */
#define IDEMIP_PCAP_SNAPLEN 65535u

static inline void idemip_pcap_wr32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static inline void idemip_pcap_wr16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

// The 24-octet file header. Returns the octets written, or 0 when @p cap is short of it.
static inline size_t idemip_pcap_global_header(uint8_t *out, size_t cap, uint32_t linktype)
{
    if (out == NULL || cap < IDEMIP_PCAP_GLOBAL_HDR_LEN)
    {
        return 0u;
    }
    idemip_pcap_wr32le(out + 0, IDEMIP_PCAP_MAGIC_USEC);
    idemip_pcap_wr16le(out + 4, (uint16_t)IDEMIP_PCAP_VERSION_MAJOR);
    idemip_pcap_wr16le(out + 6, (uint16_t)IDEMIP_PCAP_VERSION_MINOR);
    idemip_pcap_wr32le(out + 8, 0u);  // thiszone, GMT
    idemip_pcap_wr32le(out + 12, 0u); // sigfigs
    idemip_pcap_wr32le(out + 16, IDEMIP_PCAP_SNAPLEN);
    idemip_pcap_wr32le(out + 20, linktype);
    return IDEMIP_PCAP_GLOBAL_HDR_LEN;
}

// The 16-octet per-frame header. Returns the octets written, or 0 when @p cap is short of it.
static inline size_t idemip_pcap_record_header(uint8_t *out, size_t cap, uint32_t ts_sec, uint32_t ts_usec, uint32_t caplen,
                                        uint32_t origlen)
{
    if (out == NULL || cap < IDEMIP_PCAP_REC_HDR_LEN)
    {
        return 0u;
    }
    idemip_pcap_wr32le(out + 0, ts_sec);
    idemip_pcap_wr32le(out + 4, ts_usec);
    idemip_pcap_wr32le(out + 8, caplen);
    idemip_pcap_wr32le(out + 12, origlen);
    return IDEMIP_PCAP_REC_HDR_LEN;
}

/** An open capture file, and what has gone into it. */
typedef struct
{
    FILE *fp;
    uint32_t frames;
    uint32_t octets; ///< frame octets, the record headers excluded
} IdemIpPcap;

// Open @p path and write the DLT_EN10MB global header.
static inline int idemip_pcap_open(IdemIpPcap *p, const char *path)
{
    uint8_t hdr[IDEMIP_PCAP_GLOBAL_HDR_LEN];

    memset(p, 0, sizeof *p);
    p->fp = fopen(path, "wb");
    if (p->fp == NULL)
    {
        return 0;
    }
    if (idemip_pcap_global_header(hdr, sizeof hdr, IDEMIP_DLT_EN10MB) != sizeof hdr ||
        fwrite(hdr, 1, sizeof hdr, p->fp) != sizeof hdr)
    {
        fclose(p->fp);
        p->fp = NULL;
        return 0;
    }
    return 1;
}

// Append one whole Ethernet II frame, stamped at @p ms milliseconds from the start of the capture.
static inline int idemip_pcap_frame(IdemIpPcap *p, const uint8_t *frame, size_t len, uint32_t ms)
{
    uint8_t hdr[IDEMIP_PCAP_REC_HDR_LEN];

    if (p == NULL || p->fp == NULL || frame == NULL || len == 0u)
    {
        return 0;
    }
    if (idemip_pcap_record_header(hdr, sizeof hdr, ms / 1000u, (ms % 1000u) * 1000u, (uint32_t)len,
                                  (uint32_t)len) != sizeof hdr)
    {
        return 0;
    }
    if (fwrite(hdr, 1, sizeof hdr, p->fp) != sizeof hdr || fwrite(frame, 1, len, p->fp) != len)
    {
        return 0;
    }
    p->frames++;
    p->octets += (uint32_t)len;
    return 1;
}

// Octets the file holds once @p p's frames are all in it.
static inline size_t idemip_pcap_expected_size(const IdemIpPcap *p)
{
    return (size_t)IDEMIP_PCAP_GLOBAL_HDR_LEN + ((size_t)p->frames * IDEMIP_PCAP_REC_HDR_LEN) + (size_t)p->octets;
}

static inline void idemip_pcap_close(IdemIpPcap *p)
{
    if (p != NULL && p->fp != NULL)
    {
        fclose(p->fp);
        p->fp = NULL;
    }
}

#endif // IDEMIP_TEST_PCAP_H
