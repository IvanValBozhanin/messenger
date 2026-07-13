use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

struct Bucket {
    tokens: f64,
    last: Instant,
}

struct Backoff {
    fails: u32,
    until: Instant,
}

/// In-memory rate limiting. Single-instance by design (state resets on
/// redeploy, which is acceptable): a token bucket per (scope, key) plus an
/// exponential backoff per username for failed logins.
#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<(&'static str, String), Bucket>>,
    backoffs: Mutex<HashMap<String, Backoff>>,
}

impl RateLimiter {
    /// Take one token from the (scope, key) bucket. `rate_per_min` refills,
    /// `burst` caps. Returns false when the caller should get 429.
    pub fn allow(&self, scope: &'static str, key: &str, rate_per_min: f64, burst: f64) -> bool {
        let mut map = self.buckets.lock().unwrap();
        if map.len() > 50_000 {
            // Pathological growth (address-rotating flood): drop state rather
            // than grow without bound.
            map.clear();
        }
        let now = Instant::now();
        let bucket = map.entry((scope, key.to_string())).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate_per_min / 60.0).min(burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Is this username currently in failed-login backoff?
    pub fn login_blocked(&self, username: &str) -> bool {
        let map = self.backoffs.lock().unwrap();
        map.get(username)
            .map(|b| b.until > Instant::now())
            .unwrap_or(false)
    }

    /// Record a failed login: exponential delay, capped at 15 minutes.
    /// Backoff (not lockout) so an attacker cannot permanently lock a
    /// legitimate user out by spamming wrong passwords.
    pub fn login_failed(&self, username: &str) {
        let mut map = self.backoffs.lock().unwrap();
        let entry = map.entry(username.to_string()).or_insert(Backoff {
            fails: 0,
            until: Instant::now(),
        });
        entry.fails += 1;
        if entry.fails >= 5 {
            let secs = 2u64.saturating_pow(entry.fails.min(14) - 5).min(900);
            entry.until = Instant::now() + Duration::from_secs(secs.max(2));
        }
    }

    pub fn login_succeeded(&self, username: &str) {
        self.backoffs.lock().unwrap().remove(username);
    }
}

/// Client IP for rate-limit keying. Behind Render's proxy the real client is
/// the *rightmost* X-Forwarded-For entry (appended by the trusted proxy;
/// leftmost entries are client-controlled and spoofable). Falls back to the
/// socket address locally.
pub fn client_ip(headers: &HeaderMap, fallback: &str) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next_back())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_exhausts_and_refills() {
        let limiter = RateLimiter::default();
        for _ in 0..5 {
            assert!(limiter.allow("t", "ip", 60.0, 5.0));
        }
        assert!(!limiter.allow("t", "ip", 60.0, 5.0));
    }

    #[test]
    fn backoff_kicks_in_after_five_fails() {
        let limiter = RateLimiter::default();
        assert!(!limiter.login_blocked("u"));
        for _ in 0..5 {
            limiter.login_failed("u");
        }
        assert!(limiter.login_blocked("u"));
        limiter.login_succeeded("u");
        assert!(!limiter.login_blocked("u"));
    }

    #[test]
    fn forwarded_for_uses_rightmost() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "6.6.6.6, 1.2.3.4".parse().unwrap());
        assert_eq!(client_ip(&headers, "127.0.0.1"), "1.2.3.4");
        assert_eq!(client_ip(&HeaderMap::new(), "127.0.0.1"), "127.0.0.1");
    }
}
