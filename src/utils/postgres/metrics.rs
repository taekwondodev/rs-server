#[macro_export]
macro_rules! track_db_operation {
    ($operation:expr, $table:expr, $body:expr) => {{
        let _start = std::time::Instant::now();
        let _op = $operation;
        let _tbl = $table;

        let result = $body;

        let duration = _start.elapsed().as_secs_f64();
        $crate::app::middleware::metrics::track_db_query(_op, _tbl, duration);

        match &result {
            Ok(_) => {}
            Err(_) => {
                $crate::app::middleware::metrics::track_db_error(_op, "query_failed");
            }
        }

        result
    }};
}

#[macro_export]
macro_rules! db_select {
    ($table:expr, $body:expr) => {
        $crate::track_db_operation!("select", $table, $body)
    };
}

#[macro_export]
macro_rules! db_insert {
    ($table:expr, $body:expr) => {
        $crate::track_db_operation!("insert", $table, $body)
    };
}

#[macro_export]
macro_rules! db_update {
    ($table:expr, $body:expr) => {
        $crate::track_db_operation!("update", $table, $body)
    };
}

#[macro_export]
macro_rules! db_delete {
    ($table:expr, $body:expr) => {
        $crate::track_db_operation!("delete", $table, $body)
    };
}

pub trait RepositoryMetrics {
    fn update_pool_metrics(&self);
}
