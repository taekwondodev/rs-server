use std::sync::Arc;

use rs_repository_utils::RepositoryObserver;

use crate::app::middleware::metrics;

pub struct PrometheusObserver;

impl RepositoryObserver for PrometheusObserver {
    fn on_db_query(&self, op: &str, table: &str, duration_secs: f64, success: bool) {
        metrics::track_db_query(op, table, duration_secs);
        if !success {
            metrics::track_db_error(op, "query_failed");
        }
    }

    fn on_redis_op(&self, op: &str, duration_secs: f64, success: bool) {
        metrics::track_redis_operation(op, duration_secs);
        if !success {
            metrics::track_redis_error(op, "operation_failed");
        }
    }
}

pub fn prometheus_observer() -> Option<Arc<dyn RepositoryObserver>> {
    Some(Arc::new(PrometheusObserver))
}
