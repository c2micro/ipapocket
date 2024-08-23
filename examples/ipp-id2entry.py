#!/usr/bin/env python

from ipapocket.utils import logger
import logging
import argparse
import sys
from pyparsing import Suppress, Word, nums, Group, alphas, OneOrMore, printables, Dict
import base64
from ipapocket.krb5.crypto.crypto import decrypt
from ipapocket.krb5.types import KrbKeySet, KrbMKey
from ipapocket.krb5.crypto.backend import Key
from ipapocket.krb5.constants import KeyUsageType
from binascii import hexlify


class Secret:
    _blob = None

    def __init__(self, blob):
        self.blob = blob

    @property
    def blob(self):
        return self._blob

    @blob.setter
    def blob(self, value) -> None:
        self._blob = KrbKeySet.load(value)


class Id2Entry:
    _dump_path: str = None
    _dump_raw: str = None
    _dump_parsed = None
    _pattern = None
    _mkey: KrbMKey = None
    _mkey_key: Key = None
    _secrets: dict[str, Secret] = dict()

    def __init__(self, dump_path):
        self._dump_path = dump_path
        self.read_raw()
        self.pattern()
        self.parse()

    def read_raw(self):
        """
        Read raw file
        """
        with open(self._dump_path, "r") as f:
            self._dump_raw = f.read()

    def pattern(self):
        """
        Create pattern for parsing
        """
        id_num = Suppress("id ") + Word(nums).suppress()
        line = Dict(
            Group(
                Word(alphas + nums + ";-_", exclude_chars=":")
                + OneOrMore(":").suppress()
                + Word(printables + " ")
            )
        )
        block = OneOrMore(line)
        self._pattern = OneOrMore(Group(id_num + block))

    def prepare(self):
        """
        Remove LDIF RFC \n\t symbols
        """
        self._dump_raw = self._dump_raw.replace("\n\t ", "").replace("\t\n", "")

    def parse(self):
        """
        Parse LDIF dump and create list of values
        """
        self.prepare()
        self._dump_parsed = self._pattern.parse_string(self._dump_raw, parseAll=True)

    def create_mkey(self):
        # self._mkey_key = string_to_key(self._mkey.key.keytype, self._mkey.key.keyvalue, b"ZE.LOC")
        self._mkey_key = Key(self._mkey.key.keytype, self._mkey.key.keyvalue)

    def dump(self):
        """
        Process parsed LDIF dump:
        1. Extract MKey (master key) and krbPrincipalKey (blobs with principals secrets)
        2. Decrypt principal secrets using master key
        3. Output this
        """
        for block in self._dump_parsed:
            # process block
            if "krbMKey" in block:
                self._mkey = KrbMKey.load(base64.b64decode(block.krbMKey))
            if "krbPrincipalKey" in block:
                if "krbPrincipalName" in block:
                    # remove domain part after @
                    principal_name = (block.krbPrincipalName).split("@")[0]
                    self._secrets[principal_name] = Secret(
                        base64.b64decode(block.krbPrincipalKey)
                    )
                else:
                    logging.debug("krbPrincipalKey exists, but no krbPrincipalName")
        if self._mkey is None or self._mkey == "":
            # exit if no master key found
            logging.error("master key (krbMKey) not found in LDIF dump")
            sys.exit(1)
        logging.debug(
            "Found 1 MK:\n%s:%s"
            % (
                self._mkey.key.keytype.name.lower(),
                hexlify(self._mkey.key.keyvalue).decode(),
            )
        )
        if len(self._secrets) == 0:
            # exit if no printipal keys found
            logging.error("principal keys (krbPrincipalKey) not found in LDIF dump")
            sys.exit(1)
        logging.debug("Found %d principals with keys:" % len(self._secrets))
        self.create_mkey()
        for k in self._secrets.keys():
            for i in self._secrets[k].blob.keys.keys:
                try:
                    principal = k
                    etype = i.key.keytype.name.lower()
                    if i.salt is not None:
                        stype = i.salt.type.name.lower()
                        salt = base64.b64encode(i.salt.salt).decode()
                    else:
                        stype = ""
                        salt = ""
                    # first 2 bytes - length of plain key
                    # https://github.com/krb5/krb5/blob/5495454583261ab5567b9916cbcfd41a3d5bd75d/src/lib/kdb/decrypt_key.c#L77
                    key = hexlify(
                        decrypt(
                            self._mkey_key, KeyUsageType.MASTER_KEY, i.key.keyvalue[2:]
                        )
                    ).decode()
                    print("%s:%s:%s:%s:%s" % (principal, etype, stype, salt, key))
                except:
                    logging.error(
                        "unable decrypt secret for {} with etype {}", k, i.key.keytype
                    )


if __name__ == "__main__":
    """
    As berkeley db in python is fucking nightmare, we need prepared data for processing.
    This file can be created by dbscan -f path/to/id2entry.db, e.g.:

    dbscan -f /var/lib/dirsrv/slapd-IPA-TEST/db/userRoot/id2entry.db

    Output format:
    [principal]:[encryption type]:[salt type (if exists)]:[salt in b64 (if exists)]:[key in hex]
    """
    logger.init()
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Dump hashes from id2entry (like NTDS dump, but its LDIF dump =) )",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        required=False,
        action="store_true",
        help="Verbose mode",
    )
    parser.add_argument(
        "-d",
        "--dump",
        required=True,
        action="store",
        help="Path to dump, produced by dbscan -f <path/id2entry.db>",
    )

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    Id2Entry(options.dump).dump()
