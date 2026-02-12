#[macro_export]
macro_rules! track_redis_operation {
    ($operation:expr, $body:expr) => {{
        let _start = std::time::Instant::now();
        let _op = $operation;

        let result = $body;

        let duration = _start.elapsed().as_secs_f64();
        $crate::app::middleware::metrics::track_redis_operation(_op, duration);

        match &result {
            Ok(_) => {}
            Err(_) => {
                $crate::app::middleware::metrics::track_redis_error(_op, "operation_failed");
            }
        }

        result
    }};
}

#[macro_export]
macro_rules! redis_set {
    ($body:expr) => {
        $crate::track_redis_operation!("set", $body)
    };
}

#[macro_export]
macro_rules! redis_get {
    ($body:expr) => {
        $crate::track_redis_operation!("get", $body)
    };
}

#[macro_export]
macro_rules! redis_exists {
    ($body:expr) => {
        $crate::track_redis_operation!("exists", $body)
    };
}

#[macro_export]
macro_rules! redis_ping {
    ($body:expr) => {
        $crate::track_redis_operation!("ping", $body)
    };
}

#[macro_export]
macro_rules! redis_delete {
    ($body:expr) => {
        $crate::track_redis_operation!("delete", $body)
    };
}

pub trait RedisMetrics {
    fn update_redis_metrics(&self);
}
