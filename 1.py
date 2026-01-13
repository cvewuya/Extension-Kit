import json
import struct
import sys
from typing import Any, Dict

from malduck import enhex, int32, procmempe, rc4


class ConfigParser:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def unpack32(self) -> int:
        value = struct.unpack("<I", self.data[self.offset : self.offset + 4])[0]
        self.offset += 4
        return value

    def unpack16(self) -> int:
        """Unpack a 16-bit unsigned integer (little-endian)."""
        value = struct.unpack("<H", self.data[self.offset : self.offset + 2])[0]
        self.offset += 2
        return value

    def unpack8(self) -> int:
        """Unpack an 8-bit unsigned integer."""
        value = self.data[self.offset]
        self.offset += 1
        return value

    def unpack_string(self) -> str:
        """Unpack a length-prefixed string."""
        length = self.unpack32()
        string_data = self.data[self.offset : self.offset + length]
        self.offset += length
        if string_data and string_data[-1] == 0:
            string_data = string_data[:-1]
        return string_data.decode("utf-8", errors="replace")

    def unpack_bytes(self, length: int) -> bytes:
        """Unpack a fixed number of bytes."""
        data = self.data[self.offset : self.offset + length]
        self.offset += length
        return data


def parse_beacon_http_config(data: bytes) -> Dict[str, Any]:
    """Parse BEACON_HTTP configuration from raw bytes."""
    parser = ConfigParser(data)
    config: Dict[str, Any] = {}

    try:
        # Agent type
        config["agent_type"] = parser.unpack32()

        # HTTP profile
        config["use_ssl"] = bool(parser.unpack8())
        config["servers_count"] = parser.unpack32()

        # Servers and ports
        config["servers"] = []
        config["ports"] = []
        for _ in range(config["servers_count"]):
            server = parser.unpack_string()
            port = parser.unpack32()
            config["servers"].append(server)
            config["ports"].append(port)

        # HTTP settings
        config["http_method"] = parser.unpack_string()
        config["uri"] = parser.unpack_string()
        config["parameter"] = parser.unpack_string()
        config["user_agent"] = parser.unpack_string()
        config["http_headers"] = parser.unpack_string()

        # Answer sizes
        config["ans_pre_size"] = parser.unpack32()
        ans_size_raw = parser.unpack32()
        config["ans_size"] = ans_size_raw + config["ans_pre_size"]

        # Timing settings
        config["kill_date"] = parser.unpack32()
        config["working_time"] = parser.unpack32()
        config["sleep_delay"] = parser.unpack32()
        config["jitter_delay"] = parser.unpack32()

        # Defaults
        config["listener_type"] = 0
        config["download_chunk_size"] = 0x19000

        return config

    except Exception as e:
        print(f"Failed to parse configuration: {e}")
        raise


def parse_config(data: bytes, beacon_type: str = "BEACON_HTTP") -> Dict[str, Any]:
    """Main entry point for parsing beacon configurations."""
    if beacon_type == "BEACON_HTTP":
        return parse_beacon_http_config(data)
    raise NotImplementedError(f"Parser for {beacon_type} not implemented")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extractor.py <path_to_config_file|hex_bytes>")
        sys.exit(1)

    passed_arg = sys.argv[1]

    try:
        # Try treating the argument as a PE file path first
        sample = procmempe.from_file(passed_arg)
        rdata_section = sample.pe.section(".rdata")
        config_structure = sample.readp(
            rdata_section.PointerToRawData, rdata_section.SizeOfRawData
        )
        config_size = int32(config_structure)
        encrypted_config = config_structure[4 : config_size + 4]
        rc4_key = config_structure[config_size + 4 : config_size + 4 + 16]
    except Exception as e:
        print(f"Error reading file or extracting configuration: {e}")
        print("Falling back to treating the argument as hex bytes.")
        try:
            config_structure = bytes.fromhex(passed_arg)
            config_size = int32(config_structure)
            encrypted_config = config_structure[4 : config_size + 4]
            rc4_key = config_structure[config_size + 4 : config_size + 4 + 16]
        except Exception as e2:
            print(f"Failed to process provided argument as configuration bytes: {e2}")
            sys.exit(1)

    try:
        decrypted_config = rc4(rc4_key, encrypted_config)
        print(f"Decrypted configuration size: {len(decrypted_config)} bytes")
        print(f"Decrypted configuration content: {decrypted_config!r}")
        print(f"Decrypted configuration (hex): {enhex(decrypted_config)}")

        config = parse_config(decrypted_config)
        print("Parsed configuration:")
        print(json.dumps(config, indent=2))
    except Exception as e:
        print(f"Error parsing configuration: {e}")