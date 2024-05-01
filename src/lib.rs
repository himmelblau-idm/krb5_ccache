pub mod error;
use crate::error::CCacheError;
use compact_jwt::crypto::MsOapxbcSessionKey;
use picky_asn1::wrapper::{Asn1SequenceOf, GeneralStringAsn1};
use picky_krb::messages::AsRep;
use std::convert::Into;

struct Header {
    tag: u16,
    tagdata: Vec<u8>,
}

struct CountedOctetString {
    data: Vec<u8>,
}

impl Into<CountedOctetString> for GeneralStringAsn1 {
    fn into(self) -> CountedOctetString {
        CountedOctetString {
            data: self.as_bytes().to_vec(),
        }
    }
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

/// Based on the file format defined in:
/// https://www.gnu.org/software/shishi/manual/html_node/The-Credential-Cache-Binary-File-Format.html
struct CCache {
    file_format_version: u16,
    headers: Vec<Header>,
    primary_principal: Principal,
    credentials: Vec<Credentials>,
}

impl CCache {
    pub fn from_tgt(tgt: &[u8], session_key: MsOapxbcSessionKey) -> Result<CCache, CCacheError> {
        let tgt: AsRep = picky_asn1_der::from_bytes(tgt)
            .map_err(|e| {
                CCacheError::CryptoFail(format!("AsRep decode fail: {:?}", e))
            })?;
        let header = Header {
            tag: 1,
            tagdata: vec![0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
        };

        let principal = Principal {
            name_type: u32::from_be_bytes(
                tgt.0.cname.name_type.0.as_unsigned_bytes_be()[0..4]
                    .try_into()
                    .map_err(|e| CCacheError::FormatError(format!("{:?}", e)))?,
            ),
            realm: tgt.0.crealm.0.into(),
            components: tgt
                .0
                .cname
                .0
                .name_string
                .0
                .to_vec()
                .iter()
                .map(|i| (*i).clone().into())
                .collect(),
        };

        Err(CCacheError::NotImplemented)
    }
}
