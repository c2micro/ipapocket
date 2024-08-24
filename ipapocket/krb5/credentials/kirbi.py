import base64
from ipapocket.krb5.types import (
    KrbCred,
    Tgs,
    Tgt,
    KrbCredInfo,
    KrbCredInfos,
    EncKrbCredPart,
    EncryptedData,
    Tickets,
)
from ipapocket.krb5.constants import EncryptionType, MessageType


class Kirbi:
    _krb_cred: KrbCred = None

    @property
    def krb_cred(self) -> KrbCred:
        return self._krb_cred

    @krb_cred.setter
    def krb_cred(self, value) -> None:
        self._krb_cred = value

    @classmethod
    def from_tgt(cls, tgt: Tgt):
        # fill krb cred info
        krb_cred_info = KrbCredInfo()
        krb_cred_info.key = tgt.session_key
        krb_cred_info.prealm = tgt.kdc_rep.crealm
        krb_cred_info.pname = tgt.kdc_rep.cname
        krb_cred_info.flags = tgt.epart.flags
        krb_cred_info.authtime = tgt.epart.authtime
        krb_cred_info.starttime = tgt.epart.starttime
        krb_cred_info.endtime = tgt.epart.endtime
        krb_cred_info.renew_till = tgt.epart.renew_till
        krb_cred_info.srealm = tgt.epart.srealm
        krb_cred_info.sname = tgt.epart.sname
        # fill krb cred infos
        krb_cred_infos = KrbCredInfos()
        krb_cred_infos.add(krb_cred_info)
        # fill enc krb cred part
        enc_krb_cred_part = EncKrbCredPart()
        enc_krb_cred_part.ticket_info = krb_cred_infos
        # fill encrypted data
        edata = EncryptedData()
        edata.etype = EncryptionType.UNKNOWN
        edata.cipher = enc_krb_cred_part.dump()
        # fill tickets
        tickets = Tickets()
        tickets.add(tgt.kdc_rep.ticket)
        # fill krb cred
        krb_cred = KrbCred()
        krb_cred.msg_type = MessageType.KRB_CRED
        krb_cred.enc_part = edata
        krb_cred.tickets = tickets
        # return object
        tmp = cls()
        tmp.krb_cred = krb_cred
        return tmp

    @classmethod
    def from_tgs(cls, tgs: Tgs):
        # fill krb cred info
        krb_cred_info = KrbCredInfo()
        krb_cred_info.key = tgs.session_key
        krb_cred_info.prealm = tgs.kdc_rep.crealm
        krb_cred_info.pname = tgs.kdc_rep.cname
        krb_cred_info.flags = tgs.epart.flags
        krb_cred_info.authtime = tgs.epart.authtime
        krb_cred_info.starttime = tgs.epart.starttime
        krb_cred_info.endtime = tgs.epart.endtime
        krb_cred_info.renew_till = tgs.epart.renew_till
        krb_cred_info.srealm = tgs.epart.srealm
        krb_cred_info.sname = tgs.epart.sname
        # fill krb cred infos
        krb_cred_infos = KrbCredInfos()
        krb_cred_infos.add(krb_cred_info)
        # fill enc krb cred part
        enc_krb_cred_part = EncKrbCredPart()
        enc_krb_cred_part.ticket_info = krb_cred_infos
        # fill encrypted data
        edata = EncryptedData()
        edata.etype = EncryptionType.UNKNOWN
        edata.cipher = enc_krb_cred_part.dump()
        # fill tickets
        tickets = Tickets()
        tickets.add(tgs.kdc_rep.ticket)
        # fill krb cred
        krb_cred = KrbCred()
        krb_cred.msg_type = MessageType.KRB_CRED
        krb_cred.enc_part = edata
        krb_cred.tickets = tickets
        # return object
        tmp = cls()
        tmp.krb_cred = krb_cred
        return tmp

    def to_file(self, path) -> None:
        """
        Write object's bytes to file
        """
        with open(path, "wb") as f:
            f.write(self.krb_cred.dump())

    def to_b64(self) -> str:
        return base64.b64encode(self.krb_cred.dump()).decode()
