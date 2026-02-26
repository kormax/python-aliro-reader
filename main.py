import json
import logging
import signal
import sys
import time

from aliro.protocol import AliroFlow, AliroTransactionType, ProtocolError, read_aliro
from repository import Repository
from util.afclf import AnnotationFrameContactlessFrontend, ISODEPTag, RemoteTarget, activate
from util.ecp import ECP
from util.iso7816 import ISO7816Tag
from util.tlv.ber import BerTLV, BerTLVMessage

# By default, this file is located in the same folder as the project
CONFIGURATION_FILE_PATH = "configuration.json"


def load_configuration(path=CONFIGURATION_FILE_PATH) -> dict:
    with open(path) as f:
        return json.load(f)


def configure_logging(config: dict):
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)8s] %(module)-18s:%(lineno)-4d %(message)s")
    hdlr = logging.StreamHandler(sys.stdout)
    logging.getLogger().setLevel(config.get("level", logging.INFO))
    hdlr.setFormatter(formatter)
    logging.getLogger().addHandler(hdlr)
    return logging.getLogger()


def configure_nfc_device(config: dict):
    clf = AnnotationFrameContactlessFrontend(
        path=config.get("path", None) or f"tty:{config.get('port')}:{config.get('driver')}",
        annotation_enabled=True,
    )
    return clf


def configure_repository(config: dict, repository=None):
    repository = repository or Repository(config["persist"])
    reader_private_key_hex = config.get("reader_private_key")
    reader_group_identifier_hex = config.get("reader_group_identifier")
    reader_group_sub_identifier_hex = config.get("reader_group_sub_identifier")

    if reader_private_key_hex:
        repository.set_reader_private_key(bytes.fromhex(reader_private_key_hex))

    reader_group_identifier = (
        bytes.fromhex(reader_group_identifier_hex) if reader_group_identifier_hex else bytes.fromhex("00" * 8)
    )
    repository.set_reader_group_identifier(reader_group_identifier)

    reader_group_sub_identifier = (
        bytes.fromhex(reader_group_sub_identifier_hex)
        if reader_group_sub_identifier_hex
        else bytes.fromhex("00" * len(reader_group_identifier))
    )
    repository.set_reader_group_sub_identifier(reader_group_sub_identifier)
    return repository


def resolve_flow(flow: str) -> AliroFlow:
    try:
        return AliroFlow[str(flow).upper()]
    except KeyError:
        fallback_flow = AliroFlow.FAST
        logging.warning(f"Digital Key flow {flow} is not supported. Falling back to {fallback_flow}")
        return fallback_flow


def read_aliro_once(  # noqa: C901
    nfc_device,
    repository: Repository,
    *,
    express: bool,
    flow: AliroFlow,
    throttle_polling: float,
    should_run,
):
    start = time.monotonic()

    remote_target = nfc_device.sense(
        RemoteTarget("106A"),
        annotation=ECP.aliro(
            identifier=repository.get_reader_group_identifier(),
            flag_2=express,
        ).to_bytes(),
    )

    if remote_target is None:
        # Throttle polling attempts to prevent overheating & RF performance degradation
        time.sleep(max(0, throttle_polling - time.monotonic() + start))
        return

    target = activate(nfc_device, remote_target)
    if target is None:
        return

    if not isinstance(target, ISODEPTag):
        logging.info(f"Found non-ISODEP Tag with UID: {target.identifier.hex().upper()}")
        nfc_device.close()
        nfc_device.open(nfc_device.path)
        while nfc_device.sense(RemoteTarget("106A")) is not None:
            if not should_run():
                return
            logging.info("Waiting for target to leave the field...")
            time.sleep(0.5)
        return

    logging.info(f"Got NFC tag {target}")

    tag = ISO7816Tag(target)

    command = BerTLV(
        0xBA,
        BerTLVMessage(
            [
                # Session indicator
                BerTLV(0x8C, [0x00]),
                # Read request, offset 0, length 16
                BerTLV(0x87, [0x00, 0x00, 0x00, 0x0F]),
            ]
        ),
    )

    try:
        result_flow, endpoint = read_aliro(
            tag,
            endpoints=repository.get_all_endpoints(),
            preferred_versions=[b"\x00\x09"],  # b"\x01\x00",
            flow=flow,
            transaction_code=AliroTransactionType.UNLOCK,
            reader_group_identifier=repository.get_reader_group_identifier(),
            reader_group_sub_identifier=repository.get_reader_group_sub_identifier(),
            reader_private_key=repository.get_reader_private_key(),
            key_size=16,
            mailbox_data=command,
        )

        if endpoint is not None:
            repository.upsert_endpoint(endpoint)

        logging.info(f"Authenticated endpoint via {result_flow!r}: {endpoint}")
        logging.info(f"Transaction took {(time.monotonic() - start) * 1000} ms")
    except ProtocolError as e:
        logging.info(f'Could not authenticate device due to protocol error "{e}"')

    # Let device cool down, wait for ISODEP to drop to consider comms finished
    while target.is_present:
        if not should_run():
            return
        logging.info("Waiting for device to leave the field...")
        time.sleep(0.5)
    logging.info("Device left the field. Continuing in 2 seconds...")
    time.sleep(2)
    logging.info("Waiting for next device...")


def run_aliro(
    nfc_device,
    repository: Repository,
    *,
    express: bool,
    flow: AliroFlow,
    throttle_polling: float,
    should_run,
):
    if repository.get_reader_private_key() in (None, b""):
        raise Exception("Device is not configured via HAP. NFC inactive")

    logging.info("Connecting to the NFC reader...")
    nfc_device.device = None
    nfc_device.open(nfc_device.path)
    if nfc_device.device is None:
        raise Exception(f"Could not connect to NFC device {nfc_device} at {nfc_device.path}")

    while should_run():
        read_aliro_once(
            nfc_device,
            repository,
            express=express,
            flow=flow,
            throttle_polling=throttle_polling,
            should_run=should_run,
        )


def main():
    config = load_configuration()
    configure_logging(config["logging"])

    nfc_device = configure_nfc_device(config["nfc"])
    repository = configure_repository(config["aliro"])
    express = bool(config["aliro"].get("express", True))
    flow = resolve_flow(config["aliro"].get("flow", "fast"))
    throttle_polling = float(config["nfc"].get("throttle_polling") or 0.15)

    running = True

    def should_run():
        return running

    def handle_signal(sig, *_):
        nonlocal running
        logging.info(f"SIGNAL {signal.Signals(sig).name}")
        running = False

    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, handle_signal)

    try:
        run_aliro(
            nfc_device,
            repository,
            express=express,
            flow=flow,
            throttle_polling=throttle_polling,
            should_run=should_run,
        )
    finally:
        nfc_device.close()


if __name__ == "__main__":
    main()
