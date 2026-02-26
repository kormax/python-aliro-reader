import copy
import json
import logging
from threading import Lock
from typing import List

from entity import Endpoint

log = logging.getLogger()


class Repository:
    """Serves as a way of emulating a storage/database"""

    _endpoints: List[Endpoint]

    def __init__(self, storage_file_path):
        self.storage_file_path = storage_file_path
        self._reader_private_key = bytes(32)
        self._reader_group_sub_identifier = bytes(16)
        self._reader_group_identifier = bytes(16)
        self._endpoints = []
        self._transaction_lock = Lock()
        self._state_lock = Lock()
        self._load_state_from_file()

    def _load_state_from_file(self):
        try:
            with self._state_lock:
                configuration = json.load(open(self.storage_file_path, "r+"))
                self._reader_group_sub_identifier = bytes.fromhex(
                    configuration.get("reader_group_sub_identifier")
                    or configuration.get("reader_identifier")
                    or ("00" * 16)
                )
                self._endpoints = [Endpoint.from_dict(endpoint) for endpoint in configuration.get("endpoints", [])]
        except Exception:
            logging.exception("Could not load configuration. Assuming that device is not yet configured...")
            pass

    def _save_state_to_file(self):
        with self._state_lock:
            json.dump(
                {
                    "reader_group_sub_identifier": self._reader_group_sub_identifier.hex(),
                    "endpoints": [endpoint.to_dict() for endpoint in self._endpoints],
                },
                open(self.storage_file_path, "w"),
                indent=2,
            )

    def _refresh_state(self):
        self._save_state_to_file()
        self._load_state_from_file()

    def get_reader_private_key(self):
        return self._reader_private_key

    def set_reader_private_key(self, reader_private_key):
        with self._transaction_lock:
            self._reader_private_key = reader_private_key

    def get_reader_group_sub_identifier(self):
        return self._reader_group_sub_identifier

    def set_reader_group_sub_identifier(self, reader_group_sub_identifier):
        with self._transaction_lock:
            self._reader_group_sub_identifier = reader_group_sub_identifier

    def get_reader_group_identifier(self):
        return self._reader_group_identifier

    def set_reader_group_identifier(self, reader_group_identifier):
        with self._transaction_lock:
            self._reader_group_identifier = reader_group_identifier

    def get_all_endpoints(self):
        return copy.deepcopy(list(self._endpoints))

    def upsert_endpoint(self, endpoint: Endpoint):
        with self._transaction_lock:
            self._endpoints = [(e if e.public_key != endpoint.public_key else endpoint) for e in self._endpoints]
            if not any(e.public_key == endpoint.public_key for e in self._endpoints):
                self._endpoints.append(endpoint)
            self._refresh_state()
