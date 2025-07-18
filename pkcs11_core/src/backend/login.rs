use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_DEVICE_ERROR, CKR_OK, CKR_PIN_INCORRECT, CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID, CKS_RO_PUBLIC_SESSION, CKS_RW_SO_FUNCTIONS, CKS_RW_USER_FUNCTIONS,
    CKU_CONTEXT_SPECIFIC, CKU_SO, CKU_USER, CK_RV, CK_STATE, CK_USER_TYPE,
};
use log::{debug, error, trace, warn};
use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::Duration,
};

use crate::{
    config::{
        config_file::{RetryConfig, UserConfig},
        device::{InstanceAttempt, InstanceData, Slot},
    },
    data::THREADS_ALLOWED,
};

use super::Error;

/// Provider-agnostic login context
#[derive(Debug)]
pub struct LoginCtx {
    slot: Arc<Slot>,
    admin_allowed: bool,
    operator_allowed: bool,
    ck_state: CK_STATE,
}

#[derive(Debug, Clone)]
pub enum LoginError {
    InvalidUser,
    UserNotPresent,
    BadArgument,
    IncorrectPin,
}

impl From<LoginError> for CK_RV {
    fn from(val: LoginError) -> Self {
        match val {
            LoginError::InvalidUser => CKR_USER_TYPE_INVALID,
            LoginError::UserNotPresent => CKR_USER_TYPE_INVALID,
            LoginError::BadArgument => CKR_ARGUMENTS_BAD,
            LoginError::IncorrectPin => CKR_PIN_INCORRECT,
        }
    }
}

impl From<LoginError> for Error {
    fn from(val: LoginError) -> Self {
        Error::Login(val)
    }
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::InvalidUser => write!(f, "User type not supported"),
            LoginError::UserNotPresent => write!(f, "Username not cofigured for this user"),
            LoginError::BadArgument => write!(f, "Bad argument"),
            LoginError::IncorrectPin => write!(f, "Incorrect pin"),
        }
    }
}


impl LoginCtx {
    pub fn new(slot: Arc<Slot>, admin_allowed: bool, operator_allowed: bool) -> Self {
        let mut ck_state = CKS_RO_PUBLIC_SESSION;

        // CKS_RW_USER_FUNCTIONS has the priority, OpenDNSSEC checks for it
        if operator_allowed {
            ck_state = CKS_RW_USER_FUNCTIONS;
        } else if admin_allowed {
            ck_state = CKS_RW_SO_FUNCTIONS
        }

        Self {
            slot,
            operator_allowed,
            admin_allowed,
            ck_state,
        }
    }

    pub fn slot(&self) -> &Arc<Slot> {
        &self.slot
    }

    fn operator_config(&self) -> Option<&UserConfig> {
        if !self.operator_allowed {
            return None;
        }
        // In core library, we don't have direct access to user configs
        // This should be implemented by specific backend implementations
        None
    }

    fn admin_config(&self) -> Option<&UserConfig> {
        if !self.admin_allowed {
            return None;
        }
        // In core library, we don't have direct access to user configs
        // This should be implemented by specific backend implementations
        None
    }

    pub fn login(&mut self, user_type: CK_USER_TYPE, _pin: String) -> Result<(), LoginError> {
        trace!("Login as {user_type:?} with pin");

        match user_type {
            CKU_CONTEXT_SPECIFIC => return Err(LoginError::InvalidUser),
            CKU_SO => {
                trace!("administrator login attempt");
                if self.admin_config().is_none() {
                    return Err(LoginError::UserNotPresent);
                }
                self.admin_allowed = true;
                self.ck_state = CKS_RW_SO_FUNCTIONS;
            }
            CKU_USER => {
                if self.operator_config().is_none() {
                    return Err(LoginError::UserNotPresent);
                }
                self.operator_allowed = true;
                self.ck_state = CKS_RW_USER_FUNCTIONS;
            }
            _ => return Err(LoginError::BadArgument),
        };

        // Provider-specific login logic should be implemented by the backend
        Ok(())
    }

    pub fn can_run_mode(&self, mode: UserMode) -> bool {
        match mode {
            UserMode::Operator => self.operator_allowed && self.operator_config().is_some(),
            UserMode::Administrator => self.admin_allowed && self.admin_config().is_some(),
            UserMode::Guest => true,
            UserMode::OperatorOrAdministrator => {
                (self.operator_allowed && self.operator_config().is_some())
                || (self.admin_allowed && self.admin_config().is_some())
            }
        }
    }

    pub fn logout(&mut self) {
        self.ck_state = CKS_RO_PUBLIC_SESSION;
    }

    pub fn ck_state(&self) -> CK_STATE {
        self.ck_state
    }

    pub fn change_pin(&mut self, _pin: String) -> CK_RV {
        // Provider-specific PIN change logic should be implemented by the backend
        CKR_DEVICE_ERROR
    }

    /// Stub implementation of try_ method for backend API calls
    /// This should be implemented by specific backend implementations
    pub fn try_<F, T, E>(&self, _api_call: F, _user_mode: UserMode) -> Result<T, super::Error>
    where
        F: FnOnce(&str) -> Result<T, E>,
        E: std::fmt::Debug,
    {
        // This is a stub implementation for the core library
        // Specific backend implementations should override this
        Err(super::Error::NotImplemented("try_ method not implemented in core".to_string()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UserMode {
    Operator,
    Administrator,
    Guest,
    OperatorOrAdministrator,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UserStatus {
    Operator,
    Administrator,
    LoggedOut,
}

fn user_is_valid(user: Option<&UserConfig>) -> bool {
    let Some(user) = user else { return false };
    let Some(ref password) = user.password else {
        return false;
    };
    !user.username.is_empty() && !password.is_empty()
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_user_is_valid() {
        let user = UserConfig {
            username: "test".to_string(),
            password: Some("password".to_string()),
        };
        let empty_password_user = UserConfig {
            username: "test".to_string(),
            password: None,
        };

        assert!(user_is_valid(Some(&user)));
        assert!(!user_is_valid(None));
        assert!(!user_is_valid(Some(&empty_password_user)));
    }
}
