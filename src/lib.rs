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
use std::fs::OpenOptions;
use std::io::Write;
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

pub struct SessionKey {
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

impl Into<Vec<u8>> for Header {
    fn into(mut self) -> Vec<u8> {
        let mut b = self.tag.to_be_bytes().to_vec();
        let tagdata_len = self.tagdata.len() as u16;
        b.append(&mut tagdata_len.to_be_bytes().to_vec());
        b.append(&mut self.tagdata);
        return b;
    }
}

#[derive(Clone)]
struct CountedOctetString {
    data: Vec<u8>,
}

impl Into<Vec<u8>> for CountedOctetString {
    fn into(mut self) -> Vec<u8> {
        let len = self.data.len() as u32;
        let mut b = len.to_be_bytes().to_vec();
        b.append(&mut self.data);
        return b;
    }
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

impl Into<Vec<u8>> for Principal {
    fn into(self) -> Vec<u8> {
        let mut b = self.name_type.to_be_bytes().to_vec();
        let components_len = self.components.len() as u32;
        b.append(&mut components_len.to_be_bytes().to_vec());
        b.append(&mut self.realm.into());
        for component in self.components.into_iter() {
            b.append(&mut component.into())
        }
        return b;
    }
}

struct Keyblock {
    keytype: u16,
    etype: u16,
    keyvalue: Vec<u8>,
}

impl Into<Vec<u8>> for Keyblock {
    fn into(self) -> Vec<u8> {
        let mut b = self.keytype.to_be_bytes().to_vec();
        b.append(&mut self.etype.to_be_bytes().to_vec());
        let keylen: u16 = self.keyvalue.len() as u16;
        b.append(&mut keylen.to_be_bytes().to_vec());
        b.append(&mut self.keyvalue.clone());
        return b;
    }
}

struct Times {
    authtime: u32,
    starttime: u32,
    endtime: u32,
    renew_till: u32,
}

impl Into<Vec<u8>> for Times {
    fn into(self) -> Vec<u8> {
        let mut b = self.authtime.to_be_bytes().to_vec();
        b.append(&mut self.starttime.to_be_bytes().to_vec());
        b.append(&mut self.endtime.to_be_bytes().to_vec());
        b.append(&mut self.renew_till.to_be_bytes().to_vec());
        return b;
    }
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

impl Into<Vec<u8>> for Address {
    fn into(self) -> Vec<u8> {
        let mut b = self.addrtype.to_be_bytes().to_vec();
        b.append(&mut self.addrdata.into());
        return b;
    }
}

struct Authdata {
    authtype: u16,
    authdata: CountedOctetString,
}

impl Into<Vec<u8>> for Authdata {
    fn into(self) -> Vec<u8> {
        let mut b = self.authtype.to_be_bytes().to_vec();
        b.append(&mut self.authdata.into());
        return b;
    }
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

impl Into<Vec<u8>> for Credential {
    fn into(self) -> Vec<u8> {
        let mut b: Vec<u8> = self.client.into();
        b.append(&mut self.server.into());
        b.append(&mut self.key.into());
        b.append(&mut self.time.into());
        b.push(self.is_skey);
        b.append(&mut self.tktflags.to_be_bytes().to_vec());
        let addrs_len = self.addrs.len() as u32;
        b.append(&mut addrs_len.to_be_bytes().to_vec());
        for addr in self.addrs.into_iter() {
            b.append(&mut addr.into());
        }
        let authdata_len = self.authdata.len() as u32;
        b.append(&mut authdata_len.to_be_bytes().to_vec());
        for authdata in self.authdata.into_iter() {
            b.append(&mut authdata.into());
        }
        b.append(&mut self.ticket.into());
        b.append(&mut self.second_ticket.into());
        return b;
    }
}

/// Based on the file format defined in:
/// https://www.gnu.org/software/shishi/manual/html_node/The-Credential-Cache-Binary-File-Format.html
pub struct CCache {
    file_format_version: u16,
    headers: Vec<Header>,
    primary_principal: Principal,
    credentials: Vec<Credential>,
}

impl Into<Vec<u8>> for CCache {
    fn into(self) -> Vec<u8> {
        let mut b = self.file_format_version.to_be_bytes().to_vec();
        let headers_len = self.headers.len() as u16;
        b.append(&mut headers_len.to_be_bytes().to_vec());
        for header in self.headers.into_iter() {
            b.append(&mut header.into());
        }
        b.append(&mut self.primary_principal.into());
        for credential in self.credentials.into_iter() {
            b.append(&mut credential.into());
        }
        return b;
    }
}

impl CCache {
    pub fn save_keytab_file(self, filename: &str) -> Result<(), CCacheError> {
        let bytes: Vec<u8> = self.into();
        let mut keytab_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(filename)
            .map_err(|e| CCacheError::FileOperationFail(format!("{:?}", e)))?;
        keytab_file.write_all(&bytes)
            .map_err(|e| CCacheError::FileOperationFail(format!("{:?}", e)))?;
        keytab_file
            .sync_all()
            .map_err(|e| CCacheError::FileOperationFail(format!("{:?}", e)))?;
        return Ok(());
    }

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
