#[derive(Debug)]
pub(crate) enum HealthCheckError {
    Dns(String),
    Api(String),
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HealthCheckState {
    Up,
    Down,
    Unknown,
}

pub(crate) struct HealthMonitor {
    pub(crate) state: HealthCheckState,

    pub(crate) consecutive_success: u32,
    pub(crate) consecutive_failed: u32,

    total_success: u64,
    total_failed: u64,
}

impl HealthMonitor {
    /// retry 回連続で失敗するまでは前の状態を保ち、成功時は即座に Up に戻す。
    /// retry は同一チェック内の再送回数ではなく、監視ループをまたぐ失敗の閾値。
    pub(crate) fn record_with_retry(&mut self, result: &Result<(), HealthCheckError>, retry: u32) {
        let previous = self.state;
        self.record(result);
        if result.is_err() && self.consecutive_failed < retry {
            self.state = previous;
        }
    }

    pub(crate) fn new() -> Self {
        Self {
            state: HealthCheckState::Unknown,
            consecutive_success: 0,
            consecutive_failed: 0,
            total_success: 0,
            total_failed: 0,
        }
    }

    pub(crate) fn record(&mut self, result: &Result<(), HealthCheckError>) {
        match result {
            Ok(()) => {
                self.state = HealthCheckState::Up;
                self.consecutive_success += 1;
                self.consecutive_failed = 0;
                self.total_success += 1;
            }
            Err(_) => {
                self.state = HealthCheckState::Down;
                self.consecutive_success = 0;
                self.consecutive_failed += 1;
                self.total_failed += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_threshold_and_recovery() {
        let mut monitor = HealthMonitor::new();
        monitor.record_with_retry(&Ok(()), 3);
        for _ in 0..2 {
            monitor.record_with_retry(&Err(HealthCheckError::Timeout), 3);
            assert_eq!(monitor.state, HealthCheckState::Up);
        }
        monitor.record_with_retry(&Err(HealthCheckError::Timeout), 3);
        assert_eq!(monitor.state, HealthCheckState::Down);
        monitor.record_with_retry(&Ok(()), 3);
        assert_eq!(monitor.state, HealthCheckState::Up);
        assert_eq!(monitor.consecutive_failed, 0);
    }

    #[test]
    fn monitor_tracks_state_streaks_and_totals() {
        let mut monitor = HealthMonitor::new();
        assert!(matches!(monitor.state, HealthCheckState::Unknown));

        monitor.record(&Ok(()));
        monitor.record(&Ok(()));
        assert!(matches!(monitor.state, HealthCheckState::Up));
        assert_eq!(monitor.consecutive_success, 2);
        assert_eq!(monitor.consecutive_failed, 0);

        monitor.record(&Err(HealthCheckError::Dns("lookup failed".into())));
        monitor.record(&Err(HealthCheckError::Timeout));
        assert!(matches!(monitor.state, HealthCheckState::Down));
        assert_eq!(monitor.consecutive_success, 0);
        assert_eq!(monitor.consecutive_failed, 2);

        monitor.record(&Ok(()));
        assert!(matches!(monitor.state, HealthCheckState::Up));
        assert_eq!(monitor.consecutive_success, 1);
        assert_eq!(monitor.consecutive_failed, 0);
        assert_eq!(monitor.total_success, 3);
        assert_eq!(monitor.total_failed, 2);
    }
}
