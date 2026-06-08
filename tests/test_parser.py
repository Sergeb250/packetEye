"""Tests for PCAP parser."""

import struct
import tempfile
from datetime import datetime

import dpkt
import pytest

from app.services.pcap_parser import PCAPParser, is_external_ip, is_private_ip, validate_pcap_magic


def _make_minimal_pcap():
    """Create a minimal valid PCAP with one TCP packet."""
    buf = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    writer = dpkt.pcap.Writer(buf)
    eth = dpkt.ethernet.Ethernet()
    eth.src = b"\x00" * 6
    eth.dst = b"\xff" * 6
    ip = dpkt.ip.IP(src=b"\xc0\xa8\x01\x01", dst=b"\xc0\xa8\x01\x02")
    tcp = dpkt.tcp.TCP(sport=12345, dport=80)
    tcp.data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ip.data = tcp
    eth.data = ip
    writer.writepkt(bytes(eth), ts=datetime.now().timestamp())
    buf.close()
    return buf.name


def test_validate_pcap_magic():
    path = _make_minimal_pcap()
    assert validate_pcap_magic(path) is True


def test_parse_minimal_pcap():
    path = _make_minimal_pcap()
    parser = PCAPParser(path)
    result = parser.parse()
    assert len(result["flows"]) >= 1
    assert len(result["observables"]) >= 2


def test_ip_classification():
    assert is_private_ip("192.168.1.1") is True
    assert is_external_ip("8.8.8.8") is True
