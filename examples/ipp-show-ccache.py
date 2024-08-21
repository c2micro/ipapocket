#!/usr/bin/env python

from ipapocket.utils import logger
from ipapocket.krb5.ccache import Ccache
import argparse
import os
import logging
from datetime import datetime, UTC
import base64
from ipapocket.krb5.constants import EncryptionTypes, TicketFlagsTypes, KeyUsageTypes
from ipapocket.krb5.types.ticket import Ticket
from ipapocket.krb5.types.enc_ticket_part import EncTicketPart
from ipapocket.krb5.crypto.backend import Key
from ipapocket.krb5.crypto.crypto import decrypt
from binascii import unhexlify, hexlify


class ShowCcache:
    _content: bytes = None
    _ccache: Ccache = None
    _raw_key: str = None

    def _read_file(self, path) -> bytes:
        with open(path, "rb") as f:
            self._content = f.read()

    def __init__(self, path, key):
        """
        Read CCACHE file in such order:
        1. KRB5CCNAME
        2. Supplied path
        """
        env_path = os.getenv("KRB5CCNAME")
        if (env_path is not None and env_path != "") and (path is None or path == ""):
            logging.debug(
                "Attempt to read file from path in KRB5CCNAME env ({})".format(env_path)
            )
            self._read_file(env_path)
        elif path is not None and path != "":
            logging.debug("Attempt to reaf file from supplied path ({})".format(path))
            self._read_file(path)
        else:
            raise AttributeError("Specify KRB5CCNAME or directly path")

        # attempt to parse ccache
        self._ccache = Ccache.from_bytes(self._content)
        self._raw_key = key

    def show(self):
        logging.info(
            "%-30s: 0x%04x" % ("CCACHE version", self._ccache.file_format_version)
        )
        logging.info(
            "%-30s: %d"
            % ("Credentials number", len(self._ccache.credentials.credentials))
        )
        for i in range(len(self._ccache.credentials.credentials)):
            cred = self._ccache.credentials.credentials[i]
            # format user principal
            user_name = ""
            for j in range(cred.client.num_components):
                if j == cred.client.num_components - 1:
                    user_name += cred.client.components[j].data.decode("utf-8")
                else:
                    user_name += cred.client.components[j].data.decode("utf-8") + "/"
            user_realm = cred.client.realm.data.decode("utf-8")
            # format service principal
            service_name = ""
            for j in range(cred.server.num_components):
                if j == cred.server.num_components - 1:
                    service_name += cred.server.components[j].data.decode("utf-8")
                else:
                    service_name += cred.server.components[j].data.decode("utf-8") + "/"
            service_realm = cred.server.realm.data.decode("utf-8")
            # format authtime
            auth_time = datetime.fromtimestamp(cred.time.authtime).strftime(
                "%d/%m/%Y %H:%M:%S %p"
            )
            # format starttime
            start_time = datetime.fromtimestamp(cred.time.starttime).strftime(
                "%d/%m/%Y %H:%M:%S %p"
            )
            # format endtime
            end_time = datetime.fromtimestamp(cred.time.endtime).strftime(
                "%d/%m/%Y %H:%M:%S %p"
            )
            if datetime.fromtimestamp(cred.time.endtime) < datetime.now():
                end_time += " [expired]"
            # format renew till
            renew_till = datetime.fromtimestamp(cred.time.renew_till).strftime(
                "%d/%m/%Y %H:%M:%S %p"
            )
            if datetime.fromtimestamp(cred.time.renew_till) < datetime.now():
                renew_till += " [expired]"
            # format ticket flags
            tkt_flags = ""
            for j in TicketFlagsTypes:
                if (cred.tktflags >> (31 - j.value)) & 1 == 1:
                    tkt_flags += j.name + ","
            tkt_flags = tkt_flags.strip(",")
            # format key_type
            key_type = EncryptionTypes(cred.key.keytype).name
            # format key_value
            key_value = base64.b64encode(cred.key.keyvalue).decode("utf-8")
            tkt = Ticket.load(cred.ticket.data)
            # format tkt_kvno
            tkt_kvno = tkt.tkt_vno.value
            # format tkt_sname
            tkt_sname = ""
            for j in range(len(tkt.sname.name_value.value)):
                if j == len(tkt.sname.name_value.value) - 1:
                    tkt_sname += str(tkt.sname.name_value.value[j])
                else:
                    tkt_sname += str(tkt.sname.name_value.value[j]) + "/"
            # format tkt_realm
            tkt_realm = tkt.realm.realm
            # format tkt_etype
            tkt_etype = tkt.enc_part.etype.name
            # format service principal
            service_name = ""
            for j in range(cred.server.num_components):
                if j == cred.server.num_components - 1:
                    service_name += cred.server.components[j].data.decode("utf-8")
                else:
                    service_name += cred.server.components[j].data.decode("utf-8") + "/"
            service_realm = cred.server.realm.data.decode("utf-8")
            logging.info("[#%d] %-25s: %s" % (i, "Client name", user_name))
            logging.info("[#%d] %-25s: %s" % (i, "Client realm", user_realm))
            logging.info("[#%d] %-25s: %s" % (i, "Service name", service_name))
            logging.info("[#%d] %-25s: %s" % (i, "Service realm", service_realm))
            logging.info("[#%d] %-25s: %s" % (i, "Auth time", auth_time))
            logging.info("[#%d] %-25s: %s" % (i, "Start time", start_time))
            logging.info("[#%d] %-25s: %s" % (i, "End time", end_time))
            logging.info("[#%d] %-25s: %s" % (i, "Renew till time", renew_till))
            logging.info("[#%d] %-25s: %s" % (i, "Flags", tkt_flags))
            logging.info("[#%d] %-25s: %s" % (i, "Key type", key_type))
            logging.info("[#%d] %-25s: %s" % (i, "Key value", key_value))
            logging.info("[#%d] %s:" % (i, "Info from ticket"))
            logging.info("[#%d]  %-24s: %d" % (i, "Service kvno", tkt_kvno))
            logging.info("[#%d]  %-24s: %s" % (i, "Serivce name", tkt_sname))
            logging.info("[#%d]  %-24s: %s" % (i, "Service realm", tkt_realm))
            logging.info("[#%d]  %-24s: %s" % (i, "Service etype", tkt_etype))

            # process encrypted part
            if self._raw_key is not None and self._raw_key != "":
                # attempt of decryption
                try:
                    # create key
                    key = Key(tkt.enc_part.etype, unhexlify(self._raw_key))
                    enc_tkt_part = EncTicketPart.load(
                        decrypt(key, KeyUsageTypes.KDC_REP_TICKET, tkt.enc_part.cipher)
                    )
                    # format ticket flags
                    enc_tkt_flags = ""
                    for j in enc_tkt_part.flags.flags:
                        enc_tkt_flags += j.name + ","
                    enc_tkt_flags = enc_tkt_flags.strip(",")
                    # format enc_tkt_key_type
                    enc_tkt_key_type = EncryptionTypes(enc_tkt_part.key.keytype).name
                    # format enc_tkt_key_value
                    enc_tkt_key_value = base64.b64encode(
                        enc_tkt_part.key.keyvalue
                    ).decode("utf-8")
                    # format enc_tkt_crealm
                    enc_tkt_crealm = enc_tkt_part.crealm.realm
                    # format enc_tkt_cname
                    enc_tkt_cname = str(enc_tkt_part.cname.name_value)
                    # format authtime
                    enc_tkt_auth_time = ""
                    if enc_tkt_part.authtime is not None:
                        enc_tkt_auth_time = enc_tkt_part.authtime.time.strftime(
                            "%d/%m/%Y %H:%M:%S %p"
                        )
                    else:
                        enc_tkt_auth_time = datetime.fromtimestamp(0).strftime(
                            "%d/%m/%Y %H:%M:%S %p"
                        )
                    enc_tkt_start_time = ""
                    if enc_tkt_part.starttime is not None:
                        enc_tkt_start_time = enc_tkt_part.starttime.time.strftime(
                            "%d/%m/%Y %H:%M:%S %p"
                        )
                    else:
                        enc_tkt_start_time = datetime.fromtimestamp(0).strftime(
                            "%d/%m/%Y %H:%M:%S %p"
                        )
                    enc_tkt_end_time = ""
                    if enc_tkt_part.endtime is not None:
                        enc_tkt_end_time = enc_tkt_part.endtime.time.strftime(
                            "%d/%m/%Y %H:%M:%S %p"
                        )
                        if enc_tkt_part.endtime.time < datetime.now(UTC):
                            enc_tkt_end_time += " [expired]"
                    else:
                        enc_tkt_end_time = datetime.fromtimestamp(0).strftime(
                            "%d/%m/%Y %H:%M:%S %p"
                        )
                    enc_tkt_renew_till = ""
                    if enc_tkt_part.renew_till is not None:
                        enc_tkt_renew_till = enc_tkt_part.renew_till.time.strftime(
                            "%d/%m/%Y %H:%M:%S %p"
                        )
                        if enc_tkt_part.renew_till.time < datetime.now(UTC):
                            enc_tkt_renew_till += " [expired]"
                    else:
                        enc_tkt_renew_till = datetime.fromtimestamp(0).strftime(
                            "%d/%m/%Y %H:%M:%S %p"
                        )
                    logging.info(
                        "[#%d]  %s" % (i, "Info from decrypted ticket:")
                    )
                    logging.info(
                        "[#%d]   %-23s: %s" % (i, "Flags", enc_tkt_flags)
                    )
                    logging.info(
                        "[#%d]   %-23s: %s" % (i, "Key etype", enc_tkt_key_type)
                    )
                    logging.info(
                        "[#%d]   %-23s: %s"
                        % (i, "Key value", enc_tkt_key_value)
                    )
                    logging.info(
                        "[#%d]   %-23s: %s"
                        % (i, "Client realm", enc_tkt_crealm)
                    )
                    logging.info(
                        "[#%d]   %-23s: %s" % (i, "Client name", enc_tkt_cname)
                    )
                    # TODO - print transition
                    logging.info(
                        "[#%d]   %-23s: %s"
                        % (i, "Auth time", enc_tkt_auth_time)
                    )
                    logging.info(
                        "[#%d]   %-23s: %s"
                        % (i, "Start time", enc_tkt_start_time)
                    )
                    logging.info(
                        "[#%d]   %-23s: %s" % (i, "End time", enc_tkt_end_time)
                    )
                    logging.info(
                        "[#%d]   %-23s: %s"
                        % (i, "Renew till time", enc_tkt_renew_till)
                    )
                    # TODO - parse PAC
                except Exception as e:
                    logging.debug("Error on attempt to decrypt ticket: {}".format(e))
                    tkt_enc = (
                        base64.b64encode(tkt.enc_part.cipher).decode("utf-8")
                        + " [DECRYPTION FAILED]"
                    )
                    logging.info(
                        "[#%d]  %-24s: %s" % (i, "Encrypted part", tkt_enc)
                    )
            else:
                tkt_enc = base64.b64encode(tkt.enc_part.cipher).decode("utf-8")
                logging.info(
                    "[#%d]  %-24s: %s" % (i, "Encrypted part", tkt_enc)
                )


if __name__ == "__main__":
    logger.init()
    parser = argparse.ArgumentParser(
        add_help=True, description="Show details from CCACHE file"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        required=False,
        action="store_true",
        help="Verbose mode",
    )
    parser.add_argument(
        "--ccache",
        required=False,
        action="store",
        help="Path for CCACHE file to store TGT (will try KRB5CCNAME before)",
    )
    parser.add_argument(
        "-k",
        "--key",
        required=False,
        action="store",
        help="Key for ticket decryption attempt (in hex)",
    )

    options = parser.parse_args()

    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sc = ShowCcache(options.ccache, options.key)
    sc.show()
