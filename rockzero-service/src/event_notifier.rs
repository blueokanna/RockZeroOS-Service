//! Event notifier module for broadcasting system events
//! This module is infrastructure code prepared for future real-time notification features.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, RwLock, Mutex};
use tracing::{info, warn};
use serde::{Serialize, Deserialize};

/// System event type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SystemEventType {
    FileSystemChange,
    DiskMount,
    DiskUnmount,
    NetworkChange,
    CpuUsageChange,
    MemoryUsageChange,
    ConfigChange,
    FileUpload,
    FileDownload,
    VideoAccess,
    SecurityAlert,
}

/// System event (with security verification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    pub event_type: SystemEventType,
    pub path: Option<String>,
    #[serde(skip, default = "Instant::now")]
    pub timestamp: Instant,
    pub unix_timestamp: u64,
    pub version_token: u64,
    pub metadata: HashMap<String, String>,
    pub event_hash: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
}

impl SystemEvent {
    pub fn new(
        event_type: SystemEventType,
        path: Option<PathBuf>,
        version_token: u64,
        user_id: Option<String>,
        session_id: Option<String>,
    ) -> Self {
        let timestamp = Instant::now();
        let unix_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let path_str = path.as_ref().map(|p| p.to_string_lossy().to_string());
        
        let mut event = Self {
            event_type,
            path: path_str,
            timestamp,
            unix_timestamp,
            version_token,
            metadata: HashMap::new(),
            event_hash: String::new(),
            user_id,
            session_id,
        };
        
        event.event_hash = event.compute_hash();
        event
    }
    
    fn compute_hash(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(format!("{:?}", self.event_type).as_bytes());
        if let Some(ref path) = self.path {
            hasher.update(path.as_bytes());
        }
        hasher.update(&self.unix_timestamp.to_le_bytes());
        hasher.update(&self.version_token.to_le_bytes());
        if let Some(ref user_id) = self.user_id {
            hasher.update(user_id.as_bytes());
        }
        hex::encode(hasher.finalize().as_bytes())
    }
    
    pub fn verify(&self) -> bool {
        let computed_hash = self.compute_hash();
        computed_hash == self.event_hash
    }
}

struct EventAggregator {
    pending_events: HashMap<SystemEventType, Vec<SystemEvent>>,
    last_flush: Instant,
    debounce_duration: Duration,
}

impl EventAggregator {
    fn new(debounce_duration: Duration) -> Self {
        Self {
            pending_events: HashMap::new(),
            last_flush: Instant::now(),
            debounce_duration,
        }
    }

    fn add_event(&mut self, event: SystemEvent) {
        if !event.verify() {
            warn!("Rejecting invalid event: {:?}", event.event_type);
            return;
        }
        
        self.pending_events
            .entry(event.event_type.clone())
            .or_default()
            .push(event);
    }

    fn should_flush(&self) -> bool {
        self.last_flush.elapsed() >= self.debounce_duration
    }

    fn flush(&mut self) -> Vec<SystemEvent> {
        self.last_flush = Instant::now();
        let mut events = Vec::new();
        
        for (_, event_list) in self.pending_events.drain() {
            if let Some(latest) = event_list.into_iter().last() {
                events.push(latest);
            }
        }
        
        events
    }
    
    fn clear(&mut self) {
        self.pending_events.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventHistory {
    pub events: Vec<SystemEvent>,
    pub max_size: usize,
}

impl EventHistory {
    fn new(max_size: usize) -> Self {
        Self {
            events: Vec::with_capacity(max_size),
            max_size,
        }
    }
    
    fn add(&mut self, event: SystemEvent) {
        if self.events.len() >= self.max_size {
            self.events.remove(0);
        }
        self.events.push(event);
    }
    
    pub fn get_recent(&self, count: usize) -> Vec<SystemEvent> {
        let start = if self.events.len() > count {
            self.events.len() - count
        } else {
            0
        };
        self.events[start..].to_vec()
    }
    
    pub fn get_by_user(&self, user_id: &str) -> Vec<SystemEvent> {
        self.events
            .iter()
            .filter(|e| e.user_id.as_deref() == Some(user_id))
            .cloned()
            .collect()
    }
    
    pub fn get_by_type(&self, event_type: &SystemEventType) -> Vec<SystemEvent> {
        self.events
            .iter()
            .filter(|e| &e.event_type == event_type)
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub user_id: String,
    #[allow(dead_code)]
    pub created_at: Instant,
    pub last_activity: Instant,
    pub permissions: Vec<String>,
}

pub struct EventNotifier {
    version_counter: Arc<RwLock<u64>>,
    event_sender: broadcast::Sender<SystemEvent>,
    aggregator: Arc<RwLock<EventAggregator>>,
    history: Arc<Mutex<EventHistory>>,
    active_sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
}

impl EventNotifier {
    pub fn new(debounce_ms: u64) -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        let aggregator = Arc::new(RwLock::new(EventAggregator::new(
            Duration::from_millis(debounce_ms),
        )));
        let history = Arc::new(Mutex::new(EventHistory::new(10000)));

        Self {
            version_counter: Arc::new(RwLock::new(0)),
            event_sender,
            aggregator,
            history,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SystemEvent> {
        self.event_sender.subscribe()
    }

    pub async fn emit_event(
        &self, 
        event_type: SystemEventType, 
        path: Option<PathBuf>,
        user_id: Option<String>,
        session_id: Option<String>,
    ) {
        if let Some(ref sid) = session_id {
            let sessions = self.active_sessions.read().await;
            if sessions.contains_key(sid) {
                drop(sessions);
                let mut sessions = self.active_sessions.write().await;
                if let Some(session) = sessions.get_mut(sid) {
                    session.last_activity = Instant::now();
                }
            } else {
                warn!("Invalid session ID: {}", sid);
                return;
            }
        }
        
        let mut version = self.version_counter.write().await;
        *version += 1;
        let version_token = *version;
        drop(version);

        let event = SystemEvent::new(
            event_type,
            path,
            version_token,
            user_id,
            session_id,
        );

        let mut history = self.history.lock().await;
        history.add(event.clone());
        drop(history);

        let mut agg = self.aggregator.write().await;
        agg.add_event(event);
        
        if agg.should_flush() {
            let events = agg.flush();
            for evt in events {
                let _ = self.event_sender.send(evt);
            }
        }
    }

    pub fn start_flush_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                
                let mut agg = self.aggregator.write().await;
                if agg.should_flush() {
                    let events = agg.flush();
                    for evt in events {
                        let _ = self.event_sender.send(evt);
                    }
                }
            }
        });
    }
    
    pub fn start_session_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                
                let mut sessions = self.active_sessions.write().await;
                let now = Instant::now();
                sessions.retain(|_, session| {
                    now.duration_since(session.last_activity) < Duration::from_secs(1800)
                });
            }
        });
    }

    pub async fn get_version(&self) -> u64 {
        *self.version_counter.read().await
    }
    
    pub async fn create_session(&self, user_id: String, permissions: Vec<String>) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session_info = SessionInfo {
            user_id,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            permissions,
        };
        
        let mut sessions = self.active_sessions.write().await;
        sessions.insert(session_id.clone(), session_info);
        
        info!("Created new session: {}", session_id);
        session_id
    }
    
    pub async fn verify_session(&self, session_id: &str) -> Option<SessionInfo> {
        let sessions = self.active_sessions.read().await;
        sessions.get(session_id).cloned()
    }
    
    pub async fn revoke_session(&self, session_id: &str) {
        let mut sessions = self.active_sessions.write().await;
        sessions.remove(session_id);
        info!("Revoked session: {}", session_id);
    }
    
    pub async fn get_recent_events(&self, count: usize) -> Vec<SystemEvent> {
        let history = self.history.lock().await;
        history.get_recent(count)
    }
    
    pub async fn get_user_events(&self, user_id: &str) -> Vec<SystemEvent> {
        let history = self.history.lock().await;
        history.get_by_user(user_id)
    }
    
    pub async fn get_events_by_type(&self, event_type: &SystemEventType) -> Vec<SystemEvent> {
        let history = self.history.lock().await;
        history.get_by_type(event_type)
    }
    
    pub async fn clear_pending(&self) {
        let mut agg = self.aggregator.write().await;
        agg.clear();
        info!("Cleared all pending events");
    }
}

/// Global event notifier (using OnceLock for thread safety)
static GLOBAL_NOTIFIER: OnceLock<Arc<EventNotifier>> = OnceLock::new();

pub fn init_global_notifier(debounce_ms: u64) -> Arc<EventNotifier> {
    GLOBAL_NOTIFIER
        .get_or_init(|| {
            let notifier = Arc::new(EventNotifier::new(debounce_ms));
            notifier.clone().start_flush_task();
            notifier.clone().start_session_cleanup_task();
            info!("Event notifier initialized with {}ms debounce and security features", debounce_ms);
            notifier
        })
        .clone()
}

pub fn get_global_notifier() -> Option<Arc<EventNotifier>> {
    GLOBAL_NOTIFIER.get().cloned()
}
