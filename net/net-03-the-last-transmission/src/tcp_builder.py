"""TCP conversation builder for NET-03 — The Last Transmission.

Builds complete, Wireshark-reconstructable TCP conversations offline with Scapy.

Sequence numbers are tracked per direction, so every segment's ``seq``/``ack``
matches what the peer expects. Payloads are split at ``MSS`` bytes and each
segment is acknowledged, which is what makes Follow TCP Stream work for the
binary ZIP payload in the FTP data connection.
"""

import os
import tempfile

from scapy.all import Ether, IP, Raw, TCP, wrpcap

MSS = 1200


class Capture:
    """Collects frames with controlled timestamps and writes the PCAP."""

    def __init__(self, base_time):
        self.base_time = base_time
        self.frames = []

    def add(self, packet, at):
        packet.time = self.base_time + at
        self.frames.append(packet)
        return packet

    def ordered(self):
        return sorted(self.frames, key=lambda frame: frame.time)

    def write(self, path):
        """Serialise to a temporary file and publish atomically."""
        frames = self.ordered()
        directory = os.path.dirname(os.path.abspath(path)) or "."
        os.makedirs(directory, exist_ok=True)

        handle, temporary = tempfile.mkstemp(suffix=".pcap.tmp", dir=directory)
        os.close(handle)

        try:
            wrpcap(temporary, frames)
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)
            os.chmod(path, 0o644)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

        return len(frames)


class TCPFlow:
    """One client/server TCP conversation with correct sequence tracking."""

    def __init__(
        self,
        capture,
        *,
        client_ip,
        client_mac,
        server_ip,
        server_mac,
        client_port,
        server_port,
        client_isn,
        server_isn,
        start,
        mss=MSS,
        client_window=64240,
        server_window=65160,
        segment_gap=0.002,
        ack_gap=0.001,
    ):
        self.capture = capture
        self.client_ip = client_ip
        self.client_mac = client_mac
        self.server_ip = server_ip
        self.server_mac = server_mac
        self.client_port = client_port
        self.server_port = server_port
        self.client_isn = client_isn & 0xFFFFFFFF
        self.server_isn = server_isn & 0xFFFFFFFF
        self.client_next = (self.client_isn + 1) & 0xFFFFFFFF
        self.server_next = (self.server_isn + 1) & 0xFFFFFFFF
        self.mss = mss
        self.client_window = client_window
        self.server_window = server_window
        self.segment_gap = segment_gap
        self.ack_gap = ack_gap
        self.clock = start
        self.bytes_from_client = 0
        self.bytes_from_server = 0

    # --- plumbing --------------------------------------------------------

    @property
    def end(self):
        return self.clock

    def _advance(self, delta):
        current = self.clock
        self.clock += delta
        return current

    def _frame(self, direction, flags, seq, ack, payload=b"", window=None, delta=None):
        if direction == "c2s":
            src_ip, dst_ip = self.client_ip, self.server_ip
            src_mac, dst_mac = self.client_mac, self.server_mac
            sport, dport = self.client_port, self.server_port
            default_window = self.client_window
        elif direction == "s2c":
            src_ip, dst_ip = self.server_ip, self.client_ip
            src_mac, dst_mac = self.server_mac, self.client_mac
            sport, dport = self.server_port, self.client_port
            default_window = self.server_window
        else:  # pragma: no cover - internal misuse
            raise ValueError(f"unknown direction {direction!r}")

        packet = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, ttl=128 if direction == "c2s" else 64)
            / TCP(
                sport=sport,
                dport=dport,
                flags=flags,
                seq=seq & 0xFFFFFFFF,
                ack=ack & 0xFFFFFFFF,
                window=window or default_window,
            )
        )

        if payload:
            packet = packet / Raw(load=payload)

        self.capture.add(packet, self._advance(self.ack_gap if delta is None else delta))
        return packet

    # --- conversation stages ---------------------------------------------

    def handshake(self, gap=0.011):
        self._frame("c2s", "S", self.client_isn, 0, delta=0.0)
        self._frame("s2c", "SA", self.server_isn, self.client_next, delta=gap)
        self._frame("c2s", "A", self.client_next, self.server_next)
        return self

    def send(self, payload, gap=None):
        """Client -> server application data, segmented and acknowledged."""
        return self._transfer("c2s", payload, gap)

    def receive(self, payload, gap=None):
        """Server -> client application data, segmented and acknowledged."""
        return self._transfer("s2c", payload, gap)

    def _transfer(self, direction, payload, gap=None):
        data = payload.encode() if isinstance(payload, str) else bytes(payload)

        if not data:
            return 0

        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + self.mss]
            offset += len(chunk)

            if direction == "c2s":
                self._frame("c2s", "PA", self.client_next, self.server_next, chunk,
                            delta=self.segment_gap if gap is None else gap)
                self.client_next = (self.client_next + len(chunk)) & 0xFFFFFFFF
                self.bytes_from_client += len(chunk)
                self._frame("s2c", "A", self.server_next, self.client_next)
            else:
                self._frame("s2c", "PA", self.server_next, self.client_next, chunk,
                            delta=self.segment_gap if gap is None else gap)
                self.server_next = (self.server_next + len(chunk)) & 0xFFFFFFFF
                self.bytes_from_server += len(chunk)
                self._frame("c2s", "A", self.client_next, self.server_next)

        return len(data)

    def close(self):
        self._frame("c2s", "FA", self.client_next, self.server_next)
        self.client_next = (self.client_next + 1) & 0xFFFFFFFF
        self._frame("s2c", "FA", self.server_next, self.client_next)
        self.server_next = (self.server_next + 1) & 0xFFFFFFFF
        self._frame("c2s", "A", self.client_next, self.server_next)
        return self

    def idle(self, seconds):
        """Advance the conversation clock without emitting a packet."""
        self.clock += seconds
        return self


def reassemble(packets, *, src_ip, dst_ip, sport, dport):
    """Rebuild one direction of a conversation from sequence numbers.

    This is the same operation Wireshark's Follow TCP Stream performs, so it
    doubles as a check that the capture is reconstructable.
    """
    segments = {}

    for packet in packets:
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            continue
        if packet[IP].src != src_ip or packet[IP].dst != dst_ip:
            continue
        if packet[TCP].sport != sport or packet[TCP].dport != dport:
            continue
        segments[packet[TCP].seq] = bytes(packet[Raw].load)

    return b"".join(segments[seq] for seq in sorted(segments))
