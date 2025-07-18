use std::{collections::HashMap, sync::Mutex};

use super::{
    db::{self, attr::CkRawAttrTemplate, Object},
    login::{self, LoginCtx},
    Error,
};
use crate::{
    backend::{self, db::object::ObjectKind, mechanism::Mechanism, ApiError, types::*},
    data::{DEVICE, KEY_ALIASES},
};
use base64ct::{Base64, Encoding};
use config_file::CertificateFormat;
use cryptoki_sys::{
    CKA_CLASS, CKA_DECRYPT, CKA_EC_PARAMS, CKA_ENCRYPT, CKA_ID, CKA_KEY_TYPE, CKA_LABEL,
    CKA_MODULUS_BITS, CKA_PRIME_1, CKA_PRIME_2, CKA_PUBLIC_EXPONENT, CKA_SIGN, CKA_VALUE,
    CKA_VALUE_LEN, CKK_EC, CKK_EC_EDWARDS, CKK_GENERIC_SECRET, CKK_RSA, CK_KEY_TYPE,
    CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_ULONG,
};
use der::{oid::ObjectIdentifier, Decode};
use log::{debug, error, trace, warn};
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct ParsedAttributes {
    pub id: Option<String>,
    pub key_type: Option<CK_KEY_TYPE>,
    pub sign: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub key_class: Option<ObjectKind>,
    pub ec_params: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
    pub public_exponent: Option<Vec<u8>>,
    pub prime_p: Option<Vec<u8>>,
    pub prime_q: Option<Vec<u8>>,
    pub value_len: Option<CK_ULONG>,
    pub modulus_bits: Option<CK_ULONG>,
    pub raw_id: Option<Vec<u8>>,
}

pub fn parse_attributes(template: &CkRawAttrTemplate) -> Result<ParsedAttributes, Error> {
    let mut parsed = ParsedAttributes::default();

    for attr in template.iter() {
        let t = attr.type_();

        match t {
            CKA_CLASS => match unsafe { attr.read_value::<CK_OBJECT_CLASS>() } {
                Some(val) => {
                    parsed.key_class = match ObjectKind::from(val) {
                        ObjectKind::Other => {
                            debug!("Class not supported: {val:?}");
                            None
                        }

                        k => Some(k),
                    }
                }
                None => return Err(Error::InvalidAttribute(CKA_CLASS)),
            },
            CKA_ID => {
                if let Some(bytes) = attr.val_bytes() {
                    let str_result = String::from_utf8(bytes.to_vec());
                    let mut output = None;
                    if let Ok(str) = str_result {
                        // check if the string contains only alphanumeric characters
                        if str.chars().all(|c| c.is_alphanumeric()) {
                            output = Some(str);
                        }
                    }

                    if output.is_none() {
                        // store as hex value string
                        output = Some(hex::encode(bytes));
                        parsed.raw_id = Some(bytes.to_vec());
                    }
                    parsed.id = output;
                }
            }
            CKA_LABEL => {
                let label = attr
                    .val_bytes()
                    .map(|val| String::from_utf8(val.to_vec()))
                    .transpose()
                    .map_err(Error::StringParse)?;
                trace!("label: {label:?}");
                if parsed.id.is_none() {
                    parsed.id = label;
                }
            }

            CKA_KEY_TYPE => {
                let ktype = match unsafe { attr.read_value::<CK_KEY_TYPE>() } {
                    Some(val) => val,
                    None => return Err(Error::InvalidAttribute(CKA_KEY_TYPE)),
                };
                parsed.key_type = Some(ktype);
            }
            CKA_EC_PARAMS => {
                parsed.ec_params = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_VALUE => {
                parsed.value = attr.val_bytes().map(|val| val.to_vec());
            }

            CKA_SIGN => {
                if let Some(val) = attr.val_bytes() {
                    if val[0] == 1 {
                        parsed.sign = true;
                    }
                }
            }
            CKA_ENCRYPT => {
                if let Some(val) = attr.val_bytes() {
                    if val[0] == 1 {
                        parsed.encrypt = true;
                    }
                }
            }
            CKA_DECRYPT => {
                if let Some(val) = attr.val_bytes() {
                    if val[0] == 1 {
                        parsed.decrypt = true;
                    }
                }
            }
            CKA_PUBLIC_EXPONENT => {
                parsed.public_exponent = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_PRIME_1 => {
                parsed.prime_p = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_PRIME_2 => {
                parsed.prime_q = attr.val_bytes().map(|val| val.to_vec());
            }
            CKA_VALUE_LEN => {
                parsed.value_len = unsafe { attr.read_value::<CK_ULONG>() };
            }
            CKA_MODULUS_BITS => {
                parsed.modulus_bits = unsafe { attr.read_value::<CK_ULONG>() };
            }

            _ => {
                debug!("Attribute not supported: {:?}", attr.type_());
            }
        }
    }

    Ok(parsed)
}

fn upload_certificate(
    parsed_template: &ParsedAttributes,
    login_ctx: &LoginCtx,
) -> Result<(String, ObjectKind, Option<Vec<u8>>), Error> {
    let _cert = parsed_template
        .value
        .as_ref()
        .ok_or(Error::MissingAttribute(CKA_VALUE))?;

    let id = match parsed_template.id {
        Some(ref id) => id.clone(),
        None => {
            error!("A key ID is required");
            return Err(Error::MissingAttribute(CKA_ID));
        }
    };

    let Some(_device) = DEVICE.load_full() else {
        error!("Initialization was not performed or failed");
        return Err(Error::LibraryNotInitialized);
    };

    // TODO: This should be implemented by the specific backend
    // For now, return an error to allow compilation
    return Err(Error::InvalidData);
}

pub fn create_key_from_template(
    template: CkRawAttrTemplate,
    login_ctx: &LoginCtx,
) -> Result<(String, ObjectKind, Option<Vec<u8>>), Error> {
    let parsed = parse_attributes(&template)?;

    debug!("key_class: {:?}", parsed.key_class);
    debug!("key_type: {:?}", parsed.key_type);

    let key_class = if let Some(ref key_class) = parsed.key_class {
        let key_class = *key_class;
        if key_class == ObjectKind::Other || key_class == ObjectKind::PublicKey {
            // Supported object types are Certificates, Private keys and keypairs
            warn!("Creating object of class {key_class:?} is not supported by the core");
            return Err(Error::ObjectClassNotSupported);
        }
        key_class
    } else {
        return Err(Error::ObjectClassNotSupported);
    };

    if key_class == ObjectKind::Certificate {
        return upload_certificate(&parsed, login_ctx);
    }

    // TODO: This should be implemented by the specific backend
    // For now, return an error to allow compilation
    return Err(Error::InvalidData);
}

const KEYTYPE_EC_P224: ObjectIdentifier = der::oid::db::rfc5912::SECP_224_R_1;
const KEYTYPE_EC_P256: ObjectIdentifier = der::oid::db::rfc5912::SECP_256_R_1;
const KEYTYPE_EC_P384: ObjectIdentifier = der::oid::db::rfc5912::SECP_384_R_1;
const KEYTYPE_EC_P521: ObjectIdentifier = der::oid::db::rfc5912::SECP_521_R_1;
const KEYTYPE_CURVE25519: ObjectIdentifier = der::oid::db::rfc8410::ID_ED_25519;

pub fn key_type_to_asn1(key_type: KeyType) -> Option<ObjectIdentifier> {
    Some(match key_type {
        KeyType::Rsa => return None,
        KeyType::EllipticCurve => KEYTYPE_EC_P256, // Default to P256
        KeyType::Aes => return None,
        KeyType::GenericSecret => return None,
        KeyType::Generic => return None,
        KeyType::EcP224 => KEYTYPE_EC_P224,
        KeyType::EcP256 => KEYTYPE_EC_P256,
        KeyType::EcP384 => KEYTYPE_EC_P384,
        KeyType::EcP521 => KEYTYPE_EC_P521,
        KeyType::Curve25519 => KEYTYPE_CURVE25519,
    })
}

// returns the key size in bytes
pub const fn key_size(t: &KeyType) -> Option<usize> {
    let size = match t {
        KeyType::Rsa => return None, // Variable size
        KeyType::EllipticCurve => 256, // Default to P256
        KeyType::Aes => return None, // Variable size
        KeyType::GenericSecret => return None, // Variable size
        KeyType::Generic => return None, // Variable size
        KeyType::EcP224 => 224,
        KeyType::EcP256 => 256,
        KeyType::EcP384 => 384,
        KeyType::EcP521 => 521,
        KeyType::Curve25519 => 256,
    };

    Some(size / 8)
}

fn key_type_from_params(params: &[u8]) -> Option<KeyType> {
    // decode der to ObjectIdentifier
    let oid: der::oid::ObjectIdentifier = der::oid::ObjectIdentifier::from_der(params).ok()?;

    // For core implementation, just return EllipticCurve for any EC curve
    if oid == KEYTYPE_CURVE25519 || oid == KEYTYPE_EC_P224 || oid == KEYTYPE_EC_P256 || oid == KEYTYPE_EC_P384 || oid == KEYTYPE_EC_P521 {
        Some(KeyType::EllipticCurve)
    } else {
        None
    }
}

pub fn generate_key_from_template(
    template: &CkRawAttrTemplate,
    public_template: Option<&CkRawAttrTemplate>,
    mechanism: &Mechanism,
    login_ctx: &LoginCtx,
    db: &Mutex<db::Db>,
) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
    let _parsed = parse_attributes(template)?;
    let _parsed_public = public_template.map(parse_attributes).transpose()?;

    // TODO: This should be implemented by the specific backend
    // For now, return an error to allow compilation
    return Err(Error::InvalidData);
}

fn fetch_one_key(
    key_id: &str,
    raw_id: Option<Vec<u8>>,
    login_ctx: &LoginCtx,
) -> Result<Vec<Object>, Error> {
    if !login_ctx.can_run_mode(super::login::UserMode::OperatorOrAdministrator) {
        return Err(Error::NotLoggedIn(
            super::login::UserMode::OperatorOrAdministrator,
        ));
    }

    // TODO: This should be implemented by the specific backend
    // For now, return an error to allow compilation
    return Err(Error::InvalidData);
}

// we need the raw id when the CKA_KEY_ID doesn't parse to an alphanumeric string
pub fn fetch_key(
    key_id: &str,
    raw_id: Option<Vec<u8>>,
    login_ctx: &LoginCtx,
    db: &Mutex<db::Db>,
) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
    let objects = fetch_one_key(key_id, raw_id, login_ctx)?;

    let mut db = db.lock()?;

    Ok(objects.into_iter().map(|o| db.add_object(o)).collect())
}

fn fetch_one_certificate(
    key_id: &str,
    raw_id: Option<Vec<u8>>,
    login_ctx: &LoginCtx,
) -> Result<Object, Error> {
    if !login_ctx.can_run_mode(super::login::UserMode::OperatorOrAdministrator) {
        return Err(Error::NotLoggedIn(
            super::login::UserMode::OperatorOrAdministrator,
        ));
    }

    // TODO: This should be implemented by the specific backend
    // For now, return an error to allow compilation
    return Err(Error::InvalidData);
}

pub fn fetch_certificate(
    key_id: &str,
    raw_id: Option<Vec<u8>>,
    login_ctx: &LoginCtx,
    db: &Mutex<db::Db>,
) -> Result<(CK_OBJECT_HANDLE, Object), Error> {
    let object = fetch_one_certificate(key_id, raw_id, login_ctx)?;
    let r = db.lock()?.add_object(object);

    Ok(r)
}

// get the id from the logation header value :
// location: /api/v1/keys/<id>?mechanisms=ECDSA_Signature
fn extract_key_id_location_header(headers: HashMap<String, String>) -> Result<String, Error> {
    let location_header = headers.get("location").ok_or(Error::InvalidData)?;
    let key_id = location_header
        .split('/')
        .next_back()
        .ok_or(Error::InvalidData)?
        .split('?')
        .next()
        .ok_or(Error::InvalidData)?
        .to_string();
    Ok(key_id)
}

pub fn fetch_one(
    key: &KeyItem,
    login_ctx: &LoginCtx,
    kind: Option<ObjectKind>,
) -> Result<Vec<Object>, Error> {
    let mut acc = Vec::new();

    if matches!(
        kind,
        None | Some(ObjectKind::Other)
            | Some(ObjectKind::PrivateKey)
            | Some(ObjectKind::PublicKey)
            | Some(ObjectKind::SecretKey)
    ) {
        acc = fetch_one_key(&key.handle.0.to_string(), None, login_ctx)?;
    }

    if matches!(kind, None | Some(ObjectKind::Certificate)) {
        match fetch_one_certificate(&key.handle.0.to_string(), None, login_ctx) {
            Ok(cert) => acc.push(cert),
            Err(err) => {
                debug!("Failed to fetch certificate: {err:?}");
            }
        }
    }
    Ok(acc)
}
