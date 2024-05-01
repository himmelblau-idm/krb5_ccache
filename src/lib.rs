pub mod error;
use crate::error::CCacheError;
use compact_jwt::crypto::MsOapxbcSessionKey;
use compact_jwt::jwe::Jwe;
use compact_jwt::JweCompact;
use kanidm_hsm_crypto::{BoxedDynTpm, MsOapxbcRsaKey};
use picky_asn1::wrapper::GeneralStringAsn1;
use picky_krb::messages::AsRep;
use std::convert::Into;
use std::str::FromStr;

struct SessionKey {
    session_key_jwe: JweCompact,
}

impl SessionKey {
    fn new(session_key_jwe: &str) -> Result<Self, CCacheError> {
        Ok(SessionKey {
            session_key_jwe: JweCompact::from_str(session_key_jwe)
                .map_err(|e| CCacheError::InvalidParse(format!("Failed parsing jwe: {}", e)))?,
        })
    }

    fn decipher(
        &self,
        tpm: &mut BoxedDynTpm,
        transport_key: &MsOapxbcRsaKey,
        data: &[u8],
    ) -> Result<Jwe, CCacheError> {
        let session_key = MsOapxbcSessionKey::complete_tpm_rsa_oaep_key_agreement(
            tpm,
            transport_key,
            &self.session_key_jwe,
        )
        .map_err(|e| {
            CCacheError::CryptoFail(format!("Unable to decipher session_key_jwe: {}", e))
        })?;
        // TODO: There is no decipher function for plain bytes yet on MsOapxbcSessionKey!
        Err(CCacheError::NotImplemented)
    }
}

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
    pub fn from_tgt(tgt: &[u8], session_key: SessionKey) -> Result<CCache, CCacheError> {
        let tgt: AsRep = picky_asn1_der::from_bytes(tgt)
            .map_err(|e| CCacheError::CryptoFail(format!("AsRep decode fail: {:?}", e)))?;
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
