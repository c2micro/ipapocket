from datetime import datetime, timezone, timedelta
import secrets
from ipapocket.krb5.objects import *
from ipapocket.krb5.constants import *
from ipapocket.krb5.crypto import *

def as_req_wihtout_pa(domain: str, username: str) -> AsReq:
    """
        Create AS-REQ packet without Preauthentication data
    """
    # we need uppercase domain
    domain = domain.upper()
    # create UPN
    username = PrincipalName(PrincipalType.NT_PRINCIPAL.value, [username])
    # create realm
    realm = Realm(domain)
    # create sname
    server_name = PrincipalName(PrincipalType.NT_PRINCIPAL.value, ['krbtgt', domain])

    current_timestamp = datetime.now(timezone.utc)

    # create KDC request body
    kdc_req_body = KdcReqBody()

    # create KDC options
    kdc_options = KdcOptions()
    kdc_options.add(KdcOptionsTypes.FORWARDABLE)
    kdc_options.add(KdcOptionsTypes.CANONICALIZE)
    kdc_options.add(KdcOptionsTypes.RENEWABLE_OK)

    # generate timestamps for validatity of TGT
    till = KerberosTime((current_timestamp + timedelta(days=1)).replace(microsecond=0))
    rtime = KerberosTime((current_timestamp + timedelta(days=1)).replace(microsecond=0))

    # generate nonce
    nonce = UInt32(secrets.randbits(31))

    # set options in request
    kdc_req_body.set_kdc_options(kdc_options)
    # set cname in request
    kdc_req_body.set_cname(username)
    # set realm in request
    kdc_req_body.set_realm(realm)
    # set sname in request
    kdc_req_body.set_sname(server_name)
    # set till in request
    kdc_req_body.set_till(till)
    # set rtime in request
    kdc_req_body.set_rtime(rtime)
    # set nonce in request
    kdc_req_body.set_nonce(nonce)

    # create object with supported encryption types
    etypes = EncTypes(supported_enctypes())
    # set etype in request
    kdc_req_body.set_etypes(etypes)
    
    # create KDC request
    kdc_req = KdcReq()

    # add version of kerberos
    kdc_req.set_pvno(Int32(5))
    # add KDC requst body
    kdc_req.set_req_body(kdc_req_body)
    # add message type
    kdc_req.set_msg_type(Int32(MessageTypes.KRB_AS_REQ.value))

    # create AS-REQ
    return AsReq(kdc_req)
