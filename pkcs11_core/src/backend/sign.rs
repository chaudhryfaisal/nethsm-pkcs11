use crate::backend::mechanism::MechDigest;

use super::{
    db::Object,
    login::{self, LoginCtx},
    mechanism::{MechMode, Mechanism},
    Error,
};
use base64ct::{Base64, Encoding};
use der::Decode;
use log::{debug, trace};
use sha2::Digest;

#[derive(Clone, Debug)]
pub struct SignCtx {
    pub mechanism: Mechanism,
    pub key: Object,
    pub data: Vec<u8>,
}

impl SignCtx {
    pub fn init(mechanism: Mechanism, key: Object, login_ctx: &LoginCtx) -> Result<Self, Error> {
        trace!("key_type: {:?}", key.kind);

        if !login_ctx.can_run_mode(crate::backend::login::UserMode::Operator) {
            return Err(Error::NotLoggedIn(login::UserMode::Operator));
        }

        // Provider-specific mechanism validation should be implemented by the backend
        trace!("Signing with mechanism: {mechanism:?}");
        trace!("key mechanisms: {:?}", key.mechanisms);

        Ok(Self {
            mechanism,
            key,
            data: Vec::new(),
        })
    }
    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn sign_final(&self, _login_ctx: &LoginCtx) -> Result<Vec<u8>, Error> {
        // Provider-specific signing logic should be implemented by the backend
        // This is a placeholder that returns an error indicating the operation is not supported
        Err(Error::InvalidMechanismMode(MechMode::Sign, self.mechanism.clone()))
    }

    pub fn get_theoretical_size(&self) -> usize {
        self.mechanism.get_signature_size(self.key.size)
    }
}
