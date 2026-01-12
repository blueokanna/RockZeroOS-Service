use rand::Rng;
use std::sync::Mutex;
use std::time::Instant;

use crate::error::AppError;
use crate::models::InviteCode;

pub struct MonotonicClock {
    start_instant: Instant,
    start_nanos: i64,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self {
            start_instant: Instant::now(),
            start_nanos: 0,
        }
    }

    pub fn now_nanos(&self) -> i64 {
        let elapsed = self.start_instant.elapsed();
        self.start_nanos + elapsed.as_nanos() as i64
    }

    pub fn is_expired(&self, expires_at_mono: i64) -> bool {
        self.now_nanos() > expires_at_mono
    }

    pub fn remaining_seconds(&self, expires_at_mono: i64) -> i64 {
        let remaining_nanos = expires_at_mono - self.now_nanos();
        if remaining_nanos <= 0 {
            0
        } else {
            remaining_nanos / 1_000_000_000
        }
    }
}

pub struct InviteCodeManager {
    clock: Mutex<MonotonicClock>,
    validity_duration_nanos: i64,
}

impl InviteCodeManager {
    pub fn new() -> Self {
        Self {
            clock: Mutex::new(MonotonicClock::new()),
            validity_duration_nanos: 3600 * 1_000_000_000,
        }
    }

    pub fn generate_code(&self) -> String {
        let mut rng = rand::thread_rng();
        format!("{:08}", rng.gen_range(10000000..100000000))
    }

    pub fn create_invite_code(&self, created_by: &str) -> Result<InviteCode, AppError> {
        let clock = self.clock.lock().map_err(|_| AppError::InternalError)?;
        let now_mono = clock.now_nanos();
        let expires_at_mono = now_mono + self.validity_duration_nanos;

        Ok(InviteCode {
            id: uuid::Uuid::new_v4().to_string(),
            code: self.generate_code(),
            created_by: created_by.to_string(),
            created_at_mono: now_mono,
            expires_at_mono,
            created_at: chrono::Utc::now(),
            is_used: false,
            used_by: None,
            used_at: None,
        })
    }

    pub fn validate_code(&self, invite: &InviteCode) -> Result<bool, AppError> {
        let clock = self.clock.lock().map_err(|_| AppError::InternalError)?;
        
        if invite.is_used {
            return Ok(false);
        }

        if clock.is_expired(invite.expires_at_mono) {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn get_remaining_seconds(&self, invite: &InviteCode) -> Result<i64, AppError> {
        let clock = self.clock.lock().map_err(|_| AppError::InternalError)?;
        Ok(clock.remaining_seconds(invite.expires_at_mono))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_monotonic_clock() {
        let clock = MonotonicClock::new();
        let t1 = clock.now_nanos();
        thread::sleep(Duration::from_millis(100));
        let t2 = clock.now_nanos();
        assert!(t2 > t1);
    }

    #[test]
    fn test_invite_code_generation() {
        let manager = InviteCodeManager::new();
        let code = manager.generate_code();
        assert_eq!(code.len(), 8);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_invite_code_validation() {
        let manager = InviteCodeManager::new();
        let invite = manager.create_invite_code("admin").unwrap();
        assert!(manager.validate_code(&invite).unwrap());
    }
}
