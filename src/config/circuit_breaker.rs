use failsafe::{
    backoff, failure_policy, CircuitBreaker as FailsafeCircuitBreaker, Config, StateMachine,
};
use std::{sync::Arc, time::Duration};

use crate::app::AppError;

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub backoff_initial_secs: u64,
    pub backoff_max_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            backoff_initial_secs: 10,
            backoff_max_secs: 60,
        }
    }
}

type BreakerImpl = StateMachine<
    failsafe::failure_policy::ConsecutiveFailures<failsafe::backoff::EqualJittered>,
    (),
>;

#[derive(Clone)]
pub struct CircuitBreaker {
    breaker: Arc<BreakerImpl>,
    name: String,
}

impl CircuitBreaker {
    pub fn new(name: &str, config: CircuitBreakerConfig) -> Self {
        let backoff_strategy = backoff::equal_jittered(
            Duration::from_secs(config.backoff_initial_secs),
            Duration::from_secs(config.backoff_max_secs),
        );

        let policy =
            failure_policy::consecutive_failures(config.failure_threshold, backoff_strategy);
        let breaker = Config::new().failure_policy(policy).build();

        Self {
            breaker: Arc::new(breaker),
            name: name.to_string(),
        }
    }

    /// Esegue una chiamata protetta dal circuit breaker
    pub async fn call<F, Fut, T>(&self, f: F) -> Result<T, AppError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, AppError>>,
    {
        let result = f().await;
        match &result {
            Ok(_) => {
                let _ = self.breaker.call(|| Ok::<_, ()>(()));
            }
            Err(e) => {
                let check_result = self.breaker.call(|| Err::<(), _>(()));
                if matches!(check_result, Err(failsafe::Error::Rejected)) {
                    tracing::warn!(
                        circuit_breaker = %self.name,
                        "Circuit breaker OPENED due to repeated failures (exponential backoff active)"
                    );
                } else {
                    tracing::warn!(
                        circuit_breaker = %self.name,
                        error = %e,
                        "Circuit breaker recorded failure"
                    );
                }
            }
        }

        result
    }
}
