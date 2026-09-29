#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace specter {
constexpr size_t SNAPLEN = 1600;
enum class Kind { Ignore, Beacon, Eapol };
struct Parsed { Kind kind = Kind::Ignore; uint8_t message = 0; };

// Input is a complete 802.11 MPDU with FCS already removed. No unaligned reads.
inline Parsed parse(const uint8_t* p, size_t n, const uint8_t target[6]) {
    if (n < 24 || (p[0] & 3) != 0) return {};
    const uint8_t type = (p[0] >> 2) & 3, subtype = p[0] >> 4;
    if (type == 0) {
        if ((subtype == 8 || subtype == 5) && n >= 36 &&
            std::memcmp(p + 16, target, 6) == 0) return {Kind::Beacon, 0};
        return {};
    }
    // Exclude encrypted, fragmented, WDS, null-data and A-MSDU frames.
    const unsigned ds = p[1] & 3;
    if (type != 2 || ds == 0 || ds == 3 || (p[1] & 0x44) ||
        (p[22] & 0x0f) || (subtype & 4)) return {};
    const uint8_t* bssid = ds == 1 ? p + 4 : p + 10;
    if (std::memcmp(bssid, target, 6)) return {};
    size_t h = 24;
    if (subtype & 8) {
        if (n < h + 2 || (p[h] & 0x80)) return {};
        h += 2;
        if (p[1] & 0x80) h += 4;  // HT control
    }
    static constexpr uint8_t llc[] = {0xaa,0xaa,0x03,0,0,0,0x88,0x8e};
    if (n < h + 12 || std::memcmp(p + h, llc, 8)) return {};
    const uint8_t* e = p + h + 8;
    size_t length = (size_t(e[2]) << 8) | e[3];
    if (length > n - h - 12) return {};
    Parsed result{Kind::Eapol, 0};
    // RSN/WPA EAPOL-Key. Counts describe observed message shapes, not validity.
    if (e[1] != 3 || length < 95 || (e[4] != 2 && e[4] != 254)) return result;
    const uint16_t info = (uint16_t(e[5]) << 8) | e[6];
    const size_t keyData = (size_t(e[97]) << 8) | e[98];
    if (keyData > length - 95 || !(info & 8) || (info & 0x0c00)) return result;
    const bool ack = info & 0x80, mic = info & 0x100, secure = info & 0x200;
    if (ack && ds == 2) result.message = mic ? 3 : 1;
    if (!ack && mic && ds == 1) result.message = secure ? 4 : 2;
    return result;
}

inline void le16(uint8_t* p, uint16_t n) { p[0] = n; p[1] = n >> 8; }
inline void le32(uint8_t* p, uint32_t n) {
    for (unsigned i = 0; i < 4; ++i) p[i] = n >> (8 * i);
}
inline void pcapHeader(uint8_t out[24]) {
    std::memset(out, 0, 24);
    le32(out, 0xa1b2c3d4); le16(out + 4, 2); le16(out + 6, 4);
    le32(out + 16, SNAPLEN); le32(out + 20, 105); // LINKTYPE_IEEE802_11, no FCS
}
inline void recordHeader(uint8_t out[16], uint64_t us, uint32_t length) {
    le32(out, us / 1000000); le32(out + 4, us % 1000000);
    le32(out + 8, length); le32(out + 12, length);
}
} // namespace specter
