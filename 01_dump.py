#!/usr/bin/env python3
from argparse import ArgumentParser

import tqdm
from panda import Panda

from kwp2000 import ECU_IDENTIFICATION_TYPE, KWP2000Client
from tp20 import TP20Transport

try:
    from panda.ccp import BYTE_ORDER, CcpClient
except ImportError:
    from panda.python.ccp import BYTE_ORDER, CcpClient

LOGICAL_ID = 0x9
CHUNK_SIZE = 4


def dump(bus: int, filename: str, start_address: int, end_address: int) -> None:
    p = Panda()
    p.can_clear(0xFFFF)
    p.set_safety_mode(Panda.SAFETY_ALLOUTPUT)

    print("Connecting using KWP2000...")
    tp20 = TP20Transport(p, LOGICAL_ID, bus=bus)
    kwp_client = KWP2000Client(tp20)

    print("Reading ecu identification & flash status")
    ident = kwp_client.read_ecu_identifcation(ECU_IDENTIFICATION_TYPE.ECU_IDENT)
    print("ECU identification", ident)

    status = kwp_client.read_ecu_identifcation(ECU_IDENTIFICATION_TYPE.STATUS_FLASH)
    print("Flash status", status)

    print("\nConnecting using CCP...")
    client = CcpClient(p, 1746, 1747, byte_order=BYTE_ORDER.LITTLE_ENDIAN, bus=bus)
    client.connect(0x0)

    progress = tqdm.tqdm(total=end_address - start_address)

    addr = start_address
    client.set_memory_transfer_address(0, 0, addr)

    dump_data = b""
    for _ in range(0, end_address, CHUNK_SIZE):
        dump_data += client.upload(CHUNK_SIZE)[:CHUNK_SIZE]
        progress.update(CHUNK_SIZE)

    with open(filename, "wb") as f:
        f.write(dump_data)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--bus", default=0, type=int, help="CAN bus number to use")
    parser.add_argument("--start-address", default=0, type=int, help="start address")
    parser.add_argument(
        "--end-address", default=0x5FFFF, type=int, help="end address (inclusive)"
    )
    parser.add_argument("--output", required=True, help="output file")

    args = parser.parse_args()

    dump(args.bus, args.output, args.start_address, args.end_address)
