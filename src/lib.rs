pub mod error;
use crate::error::CCacheError;
use picky_krb::messages::AsRep;
use compact_jwt::crypto::MsOapxbcSessionKey;

struct Header {
    tag: u16,
    tagdata: Vec<u8>,
}

struct CountedOctetString {
    data: Vec<u8>,
}

struct Principal {
    name_type: u32,
    realm: CountedOctetString,
    components: Vec<CountedOctetString>,
}

struct Keyblock {
    keytype: u16,
    etype: u16,
    keyvalue: Vec<u8>,
}

struct Times {
    authtime: u32,
    starttime: u32,
    endtime: u32,
    renew_till: u32,
}

struct Address {
    addrtype: u16,
    addrdata: CountedOctetString,
}

struct Authdata {
    authtype: u16,
    authdata: CountedOctetString,
}

struct Credentials {
    client: Principal,
    server: Principal,
    key: Keyblock,
    time: Times,
    is_skey: u8,
    tktflags: u32,
    addrs: Vec<Address>,
    authdata: Vec<Authdata>,
    ticket: CountedOctetString,
    second_ticket: CountedOctetString,
}

struct CCache {
    file_format_version: u16,
    headers: Vec<Header>,
    primary_principal: Principal,
    credentials: Vec<Credentials>,
}

impl CCache {
    pub fn from_tgt(tgt: AsRep, session_key: MsOapxbcSessionKey) -> Result<CCache, CCacheError> {
        Err(CCacheError::NotImplemented)
    }
}
