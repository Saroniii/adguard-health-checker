use crate::health::HealthCheckState;

#[derive(PartialEq)]
pub(crate) enum FailoverTrigger {
    PrimaryToFallback,
    FallbackToPrimary,
    NoTrigger,
    NoHealthyFallback,
}

pub(crate) fn dns_trigger(
    primary: impl Iterator<Item = HealthCheckState>,
    fallback: impl Iterator<Item = HealthCheckState>,
) -> FailoverTrigger {
    // Unknown や Up/Down の混在時は、切り替え・復帰のどちらも行わない。
    let (count, all_down, all_up) = primary.fold((0, true, true), |(count, down, up), state| {
        (
            count + 1,
            down && state == HealthCheckState::Down,
            up && state == HealthCheckState::Up,
        )
    });
    if count == 0 {
        return FailoverTrigger::NoTrigger;
    }
    if all_down {
        if fallback
            .into_iter()
            .any(|state| state == HealthCheckState::Up)
        {
            FailoverTrigger::PrimaryToFallback
        } else {
            FailoverTrigger::NoHealthyFallback
        }
    } else if all_up {
        FailoverTrigger::FallbackToPrimary
    } else {
        FailoverTrigger::NoTrigger
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use HealthCheckState::{Down, Unknown, Up};

    #[test]
    fn failover_requires_a_healthy_fallback() {
        for fallback in [vec![], vec![Down], vec![Unknown], vec![Down, Unknown]] {
            assert!(matches!(
                dns_trigger([Down, Down].into_iter(), fallback.into_iter()),
                FailoverTrigger::NoHealthyFallback
            ));
        }
        assert!(matches!(
            dns_trigger([Down, Down].into_iter(), [Down, Up].into_iter()),
            FailoverTrigger::PrimaryToFallback
        ));
    }

    #[test]
    fn recovery_requires_all_primary_servers_up() {
        assert!(matches!(
            dns_trigger([Up, Up].into_iter(), [Down].into_iter()),
            FailoverTrigger::FallbackToPrimary
        ));
        for primary in [vec![], vec![Up, Down], vec![Up, Unknown], vec![Unknown]] {
            assert!(matches!(
                dns_trigger(primary.into_iter(), [Up].into_iter()),
                FailoverTrigger::NoTrigger
            ));
        }
    }
}
