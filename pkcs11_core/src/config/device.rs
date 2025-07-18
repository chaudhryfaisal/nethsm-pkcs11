use std::{
    collections::BTreeMap,
    sync::{
        atomic::AtomicUsize,
        mpsc::{self, RecvError, RecvTimeoutError},
        Arc, Condvar, Mutex, RwLock, Weak,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use config_file::CertificateFormat;
use crate::backend::db::Db;

use super::config_file::{RetryConfig, UserConfig};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum InstanceState {
    #[default]
    Working,
    Failed {
        retry_count: u8,
        last_retry_at: Instant,
    },
}

impl InstanceState {
    pub fn new_failed() -> InstanceState {
        InstanceState::Failed {
            retry_count: 0,
            last_retry_at: Instant::now(),
        }
    }
}

// Core InstanceData type for device management
#[derive(Debug, Clone)]
pub struct InstanceData {
    /// Instance identifier
    pub id: String,
    /// Instance state
    pub state: Arc<RwLock<InstanceState>>,
    /// User configuration
    pub user_config: UserConfig,
    /// Retry configuration
    pub retry_config: RetryConfig,
    /// Database reference
    pub db: Arc<RwLock<Db>>,
    /// Connection pool counter
    pub pool_counter: Arc<AtomicUsize>,
}

impl InstanceData {
    /// Create a new instance data
    pub fn new(
        id: String,
        user_config: UserConfig,
        retry_config: RetryConfig,
        db: Arc<RwLock<Db>>,
    ) -> Self {
        Self {
            id,
            state: Arc::new(RwLock::new(InstanceState::Working)),
            user_config,
            retry_config,
            db,
            pool_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Clear the connection pool
    pub fn clear_pool(&self) {
        self.pool_counter.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn should_try(&self) -> InstanceAttempt {
        let this = self.state.read().unwrap();
        match *this {
            InstanceState::Working => InstanceAttempt::Working,
            InstanceState::Failed {
                retry_count,
                last_retry_at,
            } => {
                if last_retry_at.elapsed() < retry_duration_from_count(retry_count) {
                    InstanceAttempt::Failed
                } else {
                    InstanceAttempt::Retry
                }
            }
        }
    }

    pub fn clear_failed(&self) {
        *self.state.write().unwrap() = InstanceState::Working;
    }

    pub fn bump_failed(&self) {
        let mut write = self.state.write().unwrap();
        let retry_count = match *write {
            InstanceState::Working => {
                *write = InstanceState::new_failed();
                0
            }
            InstanceState::Failed {
                retry_count: prev_retry_count,
                last_retry_at,
            } => {
                // We only bump if it's a "real" retry. This is to avoid race conditions where
                // the same instance stops working when multiple threads are simultaneously connecting
                // to it
                if last_retry_at.elapsed() >= retry_duration_from_count(prev_retry_count) {
                    let retry_count = prev_retry_count.saturating_add(1);
                    *write = InstanceState::Failed {
                        retry_count,
                        last_retry_at: Instant::now(),
                    };
                    retry_count
                } else {
                    prev_retry_count
                }
            }
        };
        drop(write);
        if let Some(t) = &*RETRY_THREAD.read().unwrap() {
            t.tx.send(RetryThreadMessage::FailedInstnace {
                retry_in: retry_duration_from_count(retry_count),
                instance: self.clone(),
            })
            .ok();
        }
    }
}

/// Weak reference to InstanceData
#[derive(Debug, Clone)]
pub struct WeakInstanceData {
    /// Weak reference to the instance
    pub inner: Weak<RwLock<InstanceData>>,
}

impl From<InstanceData> for WeakInstanceData {
    fn from(instance: InstanceData) -> Self {
        Self {
            inner: Arc::downgrade(&Arc::new(RwLock::new(instance))),
        }
    }
}

impl WeakInstanceData {
    /// Upgrade to a strong reference
    pub fn upgrade(&self) -> Option<InstanceData> {
        self.inner.upgrade().and_then(|arc| {
            arc.read().ok().map(|guard| guard.clone())
        })
    }
}

/// Slot representation for core
#[derive(Debug, Clone)]
pub struct Slot {
    /// Slot ID
    pub id: u32,
    /// Slot label
    pub label: String,
    /// Whether the slot has a token
    pub has_token: bool,
    /// Associated instance data
    pub instance: Option<InstanceData>,
}

impl Slot {
    /// Create a new slot
    pub fn new(id: u32, label: String, has_token: bool) -> Self {
        Self {
            id,
            label,
            has_token,
            instance: None,
        }
    }

    /// Set the instance for this slot
    pub fn set_instance(&mut self, instance: InstanceData) {
        self.instance = Some(instance);
    }
}

pub enum InstanceAttempt {
    /// The instance is in the failed state and should not be used
    Failed,
    /// The instance is in the failed  state but a connection should be attempted
    Retry,
    /// The instance is in the working state
    Working,
}

#[allow(clippy::large_enum_variant)]
pub enum RetryThreadMessage {
    FailedInstnace {
        retry_in: Duration,
        instance: InstanceData,
    },
}

pub struct RetryChannel {
    tx: mpsc::Sender<RetryThreadMessage>,
    background_thread: JoinHandle<()>,
    background_timer: JoinHandle<()>,
}
pub static RETRY_THREAD: RwLock<Option<RetryChannel>> = RwLock::new(None);

pub fn start_background_timer() {
    let (tx, rx) = mpsc::channel();
    let (tx_instance, rx_instance) = mpsc::channel();
    let background_thread = thread::spawn(background_thread(rx_instance));
    let background_timer = thread::spawn(background_timer(rx, tx_instance));
    *RETRY_THREAD.write().unwrap() = Some(RetryChannel {
        tx,
        background_thread,
        background_timer,
    });
}

pub fn stop_background_timer() {
    let res = RETRY_THREAD.write().unwrap().take();
    let Some(RetryChannel {
        tx,
        background_thread,
        background_timer,
    }) = res
    else {
        return;
    };
    drop(tx);
    background_thread
        .join()
        .inspect_err(|err| {
            if let Some(err) = err.downcast_ref::<&'static str>() {
                log::error!("Background thread panicked: {err}");
            } else if let Some(err) = err.downcast_ref::<String>() {
                log::error!("Background thread panicked: {err}");
            } else {
                log::error!("Background thread panicked: {err:?}");
            }
        })
        .ok();
    background_timer
        .join()
        .inspect_err(|err| {
            if let Some(err) = err.downcast_ref::<&'static str>() {
                log::error!("Background timer panicked: {err}");
            } else if let Some(err) = err.downcast_ref::<String>() {
                log::error!("Background timer panicked: {err}");
            } else {
                log::error!("Background timer panicked: {err:?}");
            }
        })
        .ok();
}

fn background_timer(
    rx: mpsc::Receiver<RetryThreadMessage>,
    tx_instance: mpsc::Sender<InstanceData>,
) -> impl FnOnce() {
    let mut jobs: BTreeMap<Instant, WeakInstanceData> = BTreeMap::new();
    move || loop {
        let next_job = jobs.pop_first();
        let Some((next_job_deadline, next_job_instance)) = next_job else {
            // No jobs in the queue, we can just run the next
            match rx.recv() {
                Err(RecvError) => break,
                Ok(RetryThreadMessage::FailedInstnace { retry_in, instance }) => {
                    jobs.insert(Instant::now() + retry_in, instance.into());
                    continue;
                }
            }
        };

        let now = Instant::now();

        if now >= next_job_deadline {
            if let Some(instance) = next_job_instance.upgrade() {
                tx_instance.send(instance).unwrap();
                continue;
            }
        } else {
            jobs.insert(next_job_deadline, next_job_instance);
        }

        let timeout = next_job_deadline.duration_since(now);
        match rx.recv_timeout(timeout) {
            Ok(RetryThreadMessage::FailedInstnace { retry_in, instance }) => {
                jobs.insert(now + retry_in, instance.into());
                continue;
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn background_thread(rx: mpsc::Receiver<InstanceData>) -> impl FnOnce() {
    move || {
        while let Ok(instance) = rx.recv() {
            instance.clear_pool();
            // Health check would be implemented by specific backend
            instance.clear_failed();
        }
    }
}

fn retry_duration_from_count(retry_count: u8) -> Duration {
    let secs = match retry_count {
        0 | 1 => 1,
        2 => 2,
        3 => 5,
        4 => 10,
        5 => 60,
        6.. => 60 * 5,
    };

    Duration::from_secs(secs)
}

// Device struct moved to pkcs11_impl_nethsm_sdk
// Core will use abstract device concepts

// NetHSM-specific connector functions moved to pkcs11_impl_nethsm_sdk

// Slot struct moved to pkcs11_impl_nethsm_sdk
// Core will use abstract slot concepts
