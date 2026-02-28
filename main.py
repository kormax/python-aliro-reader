import json
import logging
import signal
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ec

from aliro.authentication_policy import AuthenticationPolicy
from aliro.certificate import Profile0000Certificate
from aliro.flow import AliroFlow
from aliro.protocol import ProtocolError, read_aliro
from repository import Repository
from util.afclf import AnnotationFrameContactlessFrontend, ISODEPTag, RemoteTarget, activate
from util.ecp import ECP
from util.general import hex_or_base64_to_bytes
from util.iso7816 import ISO7816Tag

# By default, this file is located in the same folder as the project
CONFIGURATION_FILE_PATH = "configuration.json"
DEFAULT_STEP_UP_DATA_ELEMENT = "matter1"


def load_configuration(path=CONFIGURATION_FILE_PATH) -> dict:
    with open(path) as f:
        return json.load(f)


def resolve_reader_certificate(
    reader_certificate,
    reader_private_key: bytes | None,
) -> tuple[bytes | None, bytes | None]:
    if reader_certificate in (None, False):
        return None, None

    if reader_certificate is True:
        if reader_private_key in (None, b""):
            raise ValueError("aliro.reader_certificate=true requires aliro.reader_private_key")
        issuer_private = ec.derive_private_key(int.from_bytes(reader_private_key, "big"), ec.SECP256R1())
        intermediate_private = ec.generate_private_key(ec.SECP256R1())
        cert = Profile0000Certificate.generate(
            issuer_private_key=issuer_private,
            subject_public_key=intermediate_private.public_key(),
        ).to_bytes()
        intermediate_private_bytes = intermediate_private.private_numbers().private_value.to_bytes(32, "big")
        logging.info(f"Generated intermediate reader private key bytes: {intermediate_private_bytes.hex()}")
        logging.info(f"Generated reader_certificate bytes: {cert.hex()}")
        logging.info(
            f"Generated reader_certificate from reader_private_key on startup ({len(cert)} bytes); "
            "replacing active reader_private_key with generated intermediate key",
        )
        return cert, intermediate_private_bytes

    if isinstance(reader_certificate, str):
        try:
            cert = hex_or_base64_to_bytes(reader_certificate)
        except ValueError as exc:
            raise ValueError("aliro.reader_certificate must be hex or base64 when provided as string") from exc
        profile = Profile0000Certificate.from_bytes(cert)
        if reader_private_key not in (None, b""):
            reader_public = ec.derive_private_key(
                int.from_bytes(reader_private_key, "big"),
                ec.SECP256R1(),
            ).public_key()
            if profile.subject_public_key.public_numbers() != reader_public.public_numbers():
                raise ValueError("Configured reader_certificate subject key does not match reader_private_key")
        logging.info(f"Loaded reader_certificate from configuration ({len(cert)} bytes)")
        return cert, None

    raise ValueError("aliro.reader_certificate must be true, false/null, hex string, or base64 string")


def resolve_auth0_command_vendor_extension(value) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            resolved = hex_or_base64_to_bytes(value)
        except ValueError as exc:
            raise ValueError(
                "aliro.auth0_command_vendor_extension must be hex or base64 when provided as string"
            ) from exc
        logging.info(f"Loaded auth0_command_vendor_extension from configuration ({len(resolved)} bytes)")
        return resolved
    raise ValueError("aliro.auth0_command_vendor_extension must be null, hex string, or base64 string")


def _normalize_step_up_data_element_identifiers(value, value_path: str) -> list[str]:
    if value is None:
        scopes = [DEFAULT_STEP_UP_DATA_ELEMENT]
    elif isinstance(value, str):
        scopes = [value]
    elif isinstance(value, list):
        scopes = value
    else:
        raise ValueError(f"{value_path} must be a string, array of strings, or null")

    normalized_scopes = []
    for index, raw_scope in enumerate(scopes):
        if not isinstance(raw_scope, str):
            raise ValueError(f"{value_path}[{index}] must be a string")
        scope = raw_scope.strip()
        if scope == "":
            raise ValueError(f"{value_path}[{index}] must not be empty")
        if len(scope) > 128:
            raise ValueError(f"{value_path}[{index}] exceeds 128 characters")
        if scope not in normalized_scopes:
            normalized_scopes.append(scope)

    if not normalized_scopes:
        raise ValueError(f"{value_path} must not be empty")

    return normalized_scopes


def resolve_step_up_scopes(value) -> dict[str, bool]:
    if isinstance(value, dict):
        normalized_scopes: dict[str, bool] = {}
        for raw_scope, raw_keep_marker in value.items():
            scope = _normalize_step_up_data_element_identifiers([raw_scope], "aliro.step_up_scopes keys")[0]
            if isinstance(raw_keep_marker, bool):
                keep = raw_keep_marker
            elif isinstance(raw_keep_marker, str):
                marker = raw_keep_marker.strip().lower().replace("-", "").replace("_", "")
                if marker in ("keep", "true", "yes", "1"):
                    keep = True
                elif marker in ("nokeep", "false", "no", "0"):
                    keep = False
                else:
                    raise ValueError(f"aliro.step_up_scopes[{scope}] must be boolean or marker string keep/nokeep")
            else:
                raise ValueError(f"aliro.step_up_scopes[{scope}] must be boolean or marker string keep/nokeep")
            normalized_scopes[scope] = keep

        if not normalized_scopes:
            raise ValueError("aliro.step_up_scopes must not be empty")

        logging.info(f"Configured Step-up scope request map: {normalized_scopes}")
        return normalized_scopes

    scopes = _normalize_step_up_data_element_identifiers(value, "aliro.step_up_scopes")
    scope_map = dict.fromkeys(scopes, True)
    logging.info(f"Configured Step-up scope request map: {scope_map}")
    return scope_map


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

    reader_group_identifier = bytes.fromhex(reader_group_identifier_hex) if reader_group_identifier_hex else bytes(16)
    if len(reader_group_identifier) != 16:
        raise ValueError(
            f"aliro.reader_group_identifier must be 16 bytes (32 hex chars), got {len(reader_group_identifier)} bytes"
        )
    repository.set_reader_group_identifier(reader_group_identifier)

    reader_group_sub_identifier = (
        bytes.fromhex(reader_group_sub_identifier_hex) if reader_group_sub_identifier_hex else bytes(16)
    )
    if len(reader_group_sub_identifier) != 16:
        raise ValueError(
            "aliro.reader_group_sub_identifier must be 16 bytes"
            f" (32 hex chars), got {len(reader_group_sub_identifier)} bytes"
        )
    repository.set_reader_group_sub_identifier(reader_group_sub_identifier)
    return repository


def read_aliro_once(  # noqa: C901
    nfc_device,
    repository: Repository,
    *,
    express: bool,
    flow: AliroFlow,
    authentication_policy: AuthenticationPolicy,
    reader_certificate: bytes | None,
    auth0_command_vendor_extension: bytes | None,
    step_up_scopes: dict[str, bool],
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

    try:
        result_flow, endpoint = read_aliro(
            tag,
            endpoints=repository.get_all_endpoints(),
            preferred_versions=[b"\x00\x09"],  # b"\x01\x00",
            flow=flow,
            authentication_policy=authentication_policy,
            reader_certificate=reader_certificate,
            auth0_command_vendor_extension=auth0_command_vendor_extension,
            step_up_scopes=step_up_scopes,
            reader_group_identifier=repository.get_reader_group_identifier(),
            reader_group_sub_identifier=repository.get_reader_group_sub_identifier(),
            reader_private_key=repository.get_reader_private_key(),
            key_size=16,
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
    authentication_policy: AuthenticationPolicy,
    reader_certificate: bytes | None,
    auth0_command_vendor_extension: bytes | None,
    step_up_scopes: dict[str, bool],
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
            authentication_policy=authentication_policy,
            reader_certificate=reader_certificate,
            auth0_command_vendor_extension=auth0_command_vendor_extension,
            step_up_scopes=step_up_scopes,
            throttle_polling=throttle_polling,
            should_run=should_run,
        )


def main():
    config = load_configuration()
    configure_logging(config["logging"])

    nfc_device = configure_nfc_device(config["nfc"])
    repository = configure_repository(config["aliro"])
    express = bool(config["aliro"].get("express", True))
    configured_flow = config["aliro"].get("flow", "fast")
    try:
        flow = AliroFlow.parse(configured_flow)
    except (KeyError, ValueError):
        flow = AliroFlow.FAST
        logging.warning(f"Digital Key flow {configured_flow} is not supported. Falling back to {flow}")
    authentication_policy = AuthenticationPolicy.parse(config["aliro"].get("authentication_policy", "user"))
    reader_certificate_config = config["aliro"].get("reader_certificate", None)
    reader_certificate, replacement_reader_private_key = resolve_reader_certificate(
        reader_certificate_config,
        repository.get_reader_private_key(),
    )
    if replacement_reader_private_key is not None:
        repository.set_reader_private_key(replacement_reader_private_key)
    auth0_command_vendor_extension = resolve_auth0_command_vendor_extension(
        config["aliro"].get("auth0_command_vendor_extension")
    )
    step_up_scopes = resolve_step_up_scopes(config["aliro"].get("step_up_scopes"))
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
            authentication_policy=authentication_policy,
            reader_certificate=reader_certificate,
            auth0_command_vendor_extension=auth0_command_vendor_extension,
            step_up_scopes=step_up_scopes,
            throttle_polling=throttle_polling,
            should_run=should_run,
        )
    finally:
        nfc_device.close()


if __name__ == "__main__":
    main()
