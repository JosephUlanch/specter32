"""Independent PCAP framing check using Python's struct, not firmware helpers."""
import struct
import sys
from pathlib import Path
b = Path(sys.argv[1]).read_bytes()
assert struct.unpack('<IHHIIII', b[:24]) == (0xa1b2c3d4, 2, 4, 0, 0, 1600, 105)
pos, count = 24, 0
while pos < len(b):
    sec, usec, size, original = struct.unpack('<IIII', b[pos:pos+16])
    assert sec == 1 and usec < 1000000 and size == original
    pos += 16
    frame = b[pos:pos+size]
    assert len(frame) == size and frame[30:32] == b'\x88\x8e'
    pos += size
    count += 1
assert count == 4 and pos == len(b)
print('PCAP: valid little-endian header and four complete 802.11 EAPOL records.')
