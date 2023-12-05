#!/usr/bin/env python3
import struct
from argparse import ArgumentParser

import crcmod

# fmt: off

# (addr, orig, new (optional) )
PATCHES = {
    "2501": [
        (0x0005E7A8, b"1K0909144E \x002501", b"1K0909144E \x002502"),  # Software number and version
        (0x0005E221, b"\x64", b"\x00"),  # Disengage countdown
        (0x0005E283, b"\x32", b"\x00"),  # Min speed
        (0x0005FFFC, b"Ende", b"\xff\xff\xff\xff"),  # End of FW marker
    ],
    "3501": [
        (0x0005D828, b"1K0909144R \x003501", b"1K0909144R \x003502"),  # Software number and version
        (0x0005D289, b"\x64", b"\x00"),  # Disengage countdown
        (0x0005D2FA, b"\x14", b"\x00"),  # Min speed
        (0x0005FFFC, b"Ende", b"\xff\xff\xff\xff"),  # End of FW marker
    ]
}

# fmt: on

# (checksum addr, start, end)
CHECKSUMS = {
    "2501": [
        (0x05EFFC, 0x5E000, 0x5EFFC),
    ],
    "3501": [
        # ASW: A000 - 5C000
        (0x05FEF8, 0x0A000, 0x0AFFF),
        (0x05FEFA, 0x0AFFF, 0x0BFFE),
        (0x05FEFC, 0x0BFFE, 0x0CFFD),
        (0x05FEFE, 0x0CFFD, 0x0DFFC),
        (0x05FF00, 0x0DFFC, 0x0EFFB),
        (0x05FF02, 0x0EFFB, 0x0FFFA),
        (0x05FF04, 0x0FFFA, 0x10FF9),
        (0x05FF06, 0x10FF9, 0x11FF8),
        (0x05FF08, 0x11FF8, 0x12FF7),
        (0x05FF0A, 0x12FF7, 0x13FF6),
        (0x05FF0C, 0x13FF6, 0x14FF5),
        (0x05FF0E, 0x14FF5, 0x15FF4),
        (0x05FF10, 0x15FF4, 0x16FF3),
        (0x05FF12, 0x16FF3, 0x17FF2),
        (0x05FF14, 0x17FF2, 0x18FF1),
        (0x05FF16, 0x18FF1, 0x19FF0),
        (0x05FF18, 0x19FF0, 0x1AFEF),
        (0x05FF1A, 0x1AFEF, 0x1BFEE),
        (0x05FF1C, 0x1BFEE, 0x1CFED),
        (0x05FF1E, 0x1CFED, 0x1DFEC),
        (0x05FF20, 0x1DFEC, 0x1EFEB),
        (0x05FF22, 0x1EFEB, 0x1FFEA),
        (0x05FF24, 0x1FFEA, 0x20FE9),
        (0x05FF26, 0x20FE9, 0x21FE8),
        (0x05FF28, 0x21FE8, 0x22FE7),
        (0x05FF2A, 0x22FE7, 0x23FE6),
        (0x05FF2C, 0x23FE6, 0x24FE5),
        (0x05FF2E, 0x24FE5, 0x25FE4),
        (0x05FF30, 0x25FE4, 0x26FE3),
        (0x05FF32, 0x26FE3, 0x27FE2),
        (0x05FF34, 0x27FE2, 0x28FE1),
        (0x05FF36, 0x28FE1, 0x29FE0),
        (0x05FF38, 0x29FE0, 0x2AFDF),
        (0x05FF3A, 0x2AFDF, 0x2BFDE),
        (0x05FF3C, 0x2BFDE, 0x2CFDD),
        (0x05FF3E, 0x2CFDD, 0x2DFDC),
        (0x05FF40, 0x2DFDC, 0x2EFDB),
        (0x05FF42, 0x2EFDB, 0x2FFDA),
        (0x05FF44, 0x2FFDA, 0x30FD9),
        (0x05FF46, 0x30FD9, 0x31FD8),
        (0x05FF48, 0x31FD8, 0x32FD7),
        (0x05FF4A, 0x32FD7, 0x33FD6),
        (0x05FF4C, 0x33FD6, 0x34FD5),
        (0x05FF4E, 0x34FD5, 0x35FD4),
        (0x05FF50, 0x35FD4, 0x36FD3),
        (0x05FF52, 0x36FD3, 0x37FD2),
        (0x05FF54, 0x37FD2, 0x38FD1),
        (0x05FF56, 0x38FD1, 0x39FD0),
        (0x05FF58, 0x39FD0, 0x3AFCF),
        (0x05FF5A, 0x3AFCF, 0x3BFCE),
        (0x05FF5C, 0x3BFCE, 0x3CFCD),
        (0x05FF5E, 0x3CFCD, 0x3DFCC),
        (0x05FF60, 0x3DFCC, 0x3EFCB),
        (0x05FF62, 0x3EFCB, 0x3FFCA),
        (0x05FF64, 0x3FFCA, 0x40FC9),
        (0x05FF66, 0x40FC9, 0x41FC8),
        (0x05FF68, 0x41FC8, 0x42FC7),
        (0x05FF6A, 0x42FC7, 0x43FC6),
        (0x05FF6C, 0x43FC6, 0x44FC5),
        (0x05FF6E, 0x44FC5, 0x45FC4),
        (0x05FF70, 0x45FC4, 0x46FC3),
        (0x05FF72, 0x46FC3, 0x47FC2),
        (0x05FF74, 0x47FC2, 0x48FC1),
        (0x05FF76, 0x48FC1, 0x49FC0),
        (0x05FF78, 0x49FC0, 0x4AFBF),
        (0x05FF7A, 0x4AFBF, 0x4BFBE),
        (0x05FF7C, 0x4BFBE, 0x4CFBD),
        (0x05FF7E, 0x4CFBD, 0x4DFBC),
        (0x05FF80, 0x4DFBC, 0x4EFBB),
        (0x05FF82, 0x4EFBB, 0x4FFBA),
        (0x05FF84, 0x4FFBA, 0x50FB9),
        (0x05FF86, 0x50FB9, 0x51FB8),
        (0x05FF88, 0x51FB8, 0x52FB7),
        (0x05FF8A, 0x52FB7, 0x53FB6),
        (0x05FF8C, 0x53FB6, 0x54FB5),
        (0x05FF8E, 0x54FB5, 0x55FB4),
        (0x05FF90, 0x55FB4, 0x56FB3),
        (0x05FF92, 0x56FB3, 0x57FB2),
        (0x05FF94, 0x57FB2, 0x58FB1),
        (0x05FF96, 0x58FB1, 0x59FB0),
        (0x05FF98, 0x59FB0, 0x5AFAF),
        (0x05FF9A, 0x5AFAF, 0x5BFAE),
        (0x05FF9C, 0x5BFAE, 0x5C000),
        # Calibration: 5C000 - 5EFFE
        (0x05DFFC, 0x5C000, 0x5CFFF),
        (0x05DFFE, 0x5CFFF, 0x5DFFC),
        (0x05EFFE, 0x5E000, 0x5EFFE),
    ],
}


def _crc16(dat):
    xmodem_crc_func = crcmod.mkCrcFun(0x11021, rev=False, initCrc=0x0000, xorOut=0x0000)
    crc = xmodem_crc_func(dat)
    return struct.pack(">H", crc)


def _verify_checksums(fw_in, config):
    for expected, start, end in config:
        if fw_in[expected : expected + 2] != _crc16(fw_in[start:end]):
            return False

    return True


def _update_checksums(fw_in, config):
    fw_out = fw_in
    for expected, start, end in config:
        fw_out = fw_out[:expected] + _crc16(fw_in[start:end]) + fw_out[expected + 2 :]
    return fw_out


def patcher(input_filename: str, output_filename: str, version: int) -> None:
    with open(input_filename, "rb") as fp_input:
        input_fw = fp_input.read()

    output_fw = input_fw

    assert _verify_checksums(output_fw, CHECKSUMS[version])

    for addr, orig, new in PATCHES[version]:
        length = len(orig)
        cur = input_fw[addr : addr + length]

        assert (
            cur == orig
        ), f"Unexpected values in input FW {cur.hex()} expected {orig.hex()}"

        if new is not None:
            assert len(new) == length
            output_fw = output_fw[:addr] + new + output_fw[addr + length :]
            assert output_fw[addr : addr + length] == new

    output_fw = _update_checksums(output_fw, CHECKSUMS[version])

    assert _verify_checksums(output_fw, CHECKSUMS[version])
    assert len(output_fw) == len(input_fw)

    with open(output_filename, "wb") as output_fw:
        output_fw.write(output_fw)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--input", required=True, help="input file to patch")
    parser.add_argument("--output", required=True, help="output file")
    parser.add_argument(
        "--version", default="2501", const="2501", nargs="?", choices=["2501", "3501"]
    )

    args = parser.parse_args()

    patcher(args.input, args.output, args.version)
