pub mod error;
use crate::error::CCacheError;
use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use compact_jwt::crypto::MsOapxbcSessionKey;
use compact_jwt::JweCompact;
use kanidm_hsm_crypto::{BoxedDynTpm, MsOapxbcRsaKey};
use picky_asn1::wrapper::{GeneralStringAsn1, GeneralizedTimeAsn1, IntegerAsn1};
use picky_krb::data_types::TicketInner;
use picky_krb::messages::{AsRep, EncAsRepPart};
use std::convert::{From, Into, TryFrom};
use std::str::FromStr;

struct Asn1Int<'a>(&'a IntegerAsn1);
impl<'a> TryFrom<Asn1Int<'a>> for u16 {
    type Error = CCacheError;

    fn try_from(i: Asn1Int) -> Result<Self, Self::Error> {
        Ok(u16::from_be_bytes(
            i.0.as_unsigned_bytes_be()[0..2]
                .try_into()
                .map_err(|e| CCacheError::FormatError(format!("{:?}", e)))?,
        ))
    }
}
impl<'a> TryFrom<Asn1Int<'a>> for u32 {
    type Error = CCacheError;

    fn try_from(i: Asn1Int) -> Result<Self, Self::Error> {
        Ok(u32::from_be_bytes(
            i.0.as_unsigned_bytes_be()[0..4]
                .try_into()
                .map_err(|e| CCacheError::FormatError(format!("{:?}", e)))?,
        ))
    }
}

struct SessionKey {
    session_key: MsOapxbcSessionKey,
}

impl SessionKey {
    pub fn new(
        session_key_jwe: &str,
        tpm: &mut BoxedDynTpm,
        transport_key: &MsOapxbcRsaKey,
    ) -> Result<Self, CCacheError> {
        let session_key_jwe = JweCompact::from_str(session_key_jwe)
            .map_err(|e| CCacheError::InvalidParse(format!("Failed parsing jwe: {}", e)))?;
        let session_key = MsOapxbcSessionKey::complete_tpm_rsa_oaep_key_agreement(
            tpm,
            transport_key,
            &session_key_jwe,
        )
        .map_err(|e| {
            CCacheError::CryptoFail(format!("Unable to decipher session_key_jwe: {}", e))
        })?;
        Ok(SessionKey { session_key })
    }

    fn decipher(&mut self, data: &[u8]) -> Result<Vec<u8>, CCacheError> {
        // TODO: There is no decipher function for plain bytes yet on MsOapxbcSessionKey!
        Err(CCacheError::NotImplemented)
    }
}

struct Header {
    tag: u16,
    tagdata: Vec<u8>,
}

#[derive(Clone)]
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

impl TryInto<CountedOctetString> for TicketInner {
    type Error = CCacheError;

    fn try_into(self) -> Result<CountedOctetString, Self::Error> {
        Ok(CountedOctetString {
            data: picky_asn1_der::to_vec(&self)
                .map_err(|e| CCacheError::CryptoFail(format!("{:?}", e)))?,
        })
    }
}

struct Asn1StrList(Vec<GeneralStringAsn1>);
impl From<Asn1StrList> for Vec<CountedOctetString> {
    fn from(i: Asn1StrList) -> Vec<CountedOctetString> {
        i.0.iter().map(|i| (*i).clone().into()).collect()
    }
}

#[derive(Clone)]
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

struct Asn1Time(GeneralizedTimeAsn1);
impl TryFrom<Asn1Time> for u32 {
    type Error = CCacheError;

    fn try_from(i: Asn1Time) -> Result<u32, Self::Error> {
        let date = NaiveDate::from_ymd_opt(i.0.year().into(), i.0.month().into(), i.0.day().into())
            .ok_or(CCacheError::DateTime("Invalid date specified".to_string()))?;
        let time =
            NaiveTime::from_hms_opt(i.0.hour().into(), i.0.minute().into(), i.0.second().into())
                .ok_or(CCacheError::DateTime("Invalid time specified".to_string()))?;
        let instant = NaiveDateTime::new(date, time);
        // WARNING: This is susceptible to the year 2038 time problem!
        Ok(instant.and_utc().timestamp() as u32)
    }
}

struct Address {
    addrtype: u16,
    addrdata: CountedOctetString,
}

struct Authdata {
    authtype: u16,
    authdata: CountedOctetString,
}

struct Credential {
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
    credentials: Vec<Credential>,
}

impl CCache {
    pub fn from_tgt(tgt: &[u8], mut session_key: SessionKey) -> Result<CCache, CCacheError> {
        let tgt: AsRep = picky_asn1_der::from_bytes(tgt)
            .map_err(|e| CCacheError::CryptoFail(format!("AsRep decode fail: {:?}", e)))?;
        let header = Header {
            tag: 1,
            tagdata: vec![0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
        };

        let principal = Principal {
            name_type: Asn1Int(&tgt.0.cname.name_type.0).try_into()?,
            realm: tgt.0.crealm.0.into(),
            components: Asn1StrList(tgt.0.cname.0.name_string.0.to_vec()).into(),
        };

        let cipher_text = tgt.0.enc_part.0.cipher.to_vec();
        let plain_text = session_key.decipher(&cipher_text)?;
        let enc_part: EncAsRepPart = picky_asn1_der::from_bytes(&plain_text)
            .map_err(|e| CCacheError::CryptoFail(format!("EncAsRepPart decode fail: {:?}", e)))?;

        let tktflags = enc_part.0.flags.0.as_bytes();
        let credential = Credential {
            client: principal.clone(),
            server: Principal {
                name_type: Asn1Int(&enc_part.0.sname.name_type.0).try_into()?,
                realm: enc_part.0.srealm.0.into(),
                components: Asn1StrList(enc_part.0.sname.0.name_string.0.to_vec()).into(),
            },
            key: Keyblock {
                keytype: Asn1Int(&enc_part.0.key.key_type.0).try_into()?,
                etype: 0,
                keyvalue: enc_part.0.key.0.key_value.to_vec(),
            },
            time: Times {
                authtime: Asn1Time(enc_part.0.auth_time.0).try_into()?,
                starttime: match enc_part.0.start_time.0 {
                    Some(start_time) => Asn1Time(start_time.0).try_into()?,
                    None => 0,
                },
                endtime: Asn1Time(enc_part.0.end_time.0).try_into()?,
                renew_till: match enc_part.0.renew_till.0 {
                    Some(renew_till) => Asn1Time(renew_till.0).try_into()?,
                    None => 0,
                },
            },
            is_skey: 0,
            tktflags: u32::from_be_bytes([tktflags[3], tktflags[2], tktflags[1], tktflags[0]]),
            addrs: vec![],
            authdata: vec![],
            ticket: tgt.0.ticket.0 .0.try_into()?,
            second_ticket: CountedOctetString { data: vec![] },
        };

        Ok(CCache {
            file_format_version: 0x0504,
            headers: vec![header],
            primary_principal: principal,
            credentials: vec![credential],
        })
    }
}
