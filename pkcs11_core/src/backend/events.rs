use cryptoki_sys::CK_SLOT_ID;
use log::error;
use std::sync::Arc;
// NetHSM-specific imports moved to pkcs11_impl_nethsm_sdk

use crate::{
    config::device::Slot,
    data::{DEVICE, EVENTS_MANAGER, TOKENS_STATE},
};

use super::{login::LoginCtx, types::SystemState};

pub struct EventsManager {
    pub events: Vec<CK_SLOT_ID>, // list of slots that changed

    // Used when CKF_DONT_BLOCK is clear and C_Finalize is called, then every blocking call to C_WaitForSlotEvent should return CKR_CRYPTOKI_NOT_INITIALIZED
    pub finalized: bool,
}

impl EventsManager {
    pub const fn new() -> Self {
        EventsManager {
            events: Vec::new(),
            finalized: false,
        }
    }
}

pub fn update_slot_state(slot_id: CK_SLOT_ID, present: bool) {
    let mut tokens_state = TOKENS_STATE.lock().unwrap();
    if let Some(prev) = tokens_state.get(&slot_id) {
        if *prev == present {
            return;
        } else {
            // new event
            EVENTS_MANAGER.write().unwrap().events.push(slot_id);
        }
    }
    tokens_state.insert(slot_id, present);
}

pub fn fetch_slots_state() -> Result<(), cryptoki_sys::CK_RV> {
    let Some(device) = DEVICE.load_full() else {
        error!("Initialization was not performed or failed");
        return Err(cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED);
    };

    for (index, slot) in device.slots.iter().enumerate() {
        // Convert types::Slot to config::device::Slot
        let device_slot = Slot::new(slot.id.0, slot.info.slot_description.clone(), slot.available);
        let login_ctx = LoginCtx::new(Arc::new(device_slot), false, false);
        let status = login_ctx
            .try_(|_| Ok::<(), crate::backend::Error>(()), super::login::UserMode::Guest)
            .map(|_| true)
            .unwrap_or(false);

        update_slot_state(index as CK_SLOT_ID, status);
    }
    Ok(())
}
