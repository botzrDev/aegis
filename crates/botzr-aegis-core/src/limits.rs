//! One canonical optional resource-ceiling contract for the whole pipeline.
//!
//! [`ResourceCeiling`] is the single three-axis optional cap used by both policy
//! evaluation results (the ceiling a rule imposes) and capability resolution (the
//! ceiling folded into grant minting). Living in core keeps `policy` and
//! `capability` siblings — neither depends on the other to share this type — and
//! makes axis transposition impossible: policy and capability speak the *same*
//! type, so the runtime never hand-maps field-by-field between two look-alikes.

/// Optional per-call resource ceiling. Each `Some` may only *lower* a tool's
/// declared limits; `None` means "do not constrain this axis."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceCeiling {
    pub max_memory_bytes: Option<u64>,
    pub max_wall_ms: Option<u64>,
    pub max_output_bytes: Option<u64>,
}

impl ResourceCeiling {
    /// True when no axis is constrained (the ceiling imposes nothing).
    pub fn is_unconstrained(&self) -> bool {
        self.max_memory_bytes.is_none()
            && self.max_wall_ms.is_none()
            && self.max_output_bytes.is_none()
    }

    /// Combine two ceilings by taking the *tighter* bound on each axis (a present
    /// cap always beats absent; two caps take the min). Folding a per-call ceiling
    /// into a standing one can only lower limits, never raise them.
    pub fn combine(self, other: ResourceCeiling) -> ResourceCeiling {
        ResourceCeiling {
            max_memory_bytes: tighter(self.max_memory_bytes, other.max_memory_bytes),
            max_wall_ms: tighter(self.max_wall_ms, other.max_wall_ms),
            max_output_bytes: tighter(self.max_output_bytes, other.max_output_bytes),
        }
    }
}

/// Take the tighter (smaller) of two optional caps; a present cap always wins
/// over an absent one.
fn tighter(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_unconstrained() {
        assert!(ResourceCeiling::default().is_unconstrained());
    }

    #[test]
    fn combine_takes_the_tighter_bound_per_axis() {
        let a = ResourceCeiling {
            max_memory_bytes: Some(100),
            max_wall_ms: None,
            max_output_bytes: Some(50),
        };
        let b = ResourceCeiling {
            max_memory_bytes: Some(40),
            max_wall_ms: Some(200),
            max_output_bytes: None,
        };
        let c = a.combine(b);
        assert_eq!(c.max_memory_bytes, Some(40)); // min of two caps
        assert_eq!(c.max_wall_ms, Some(200)); // present beats absent
        assert_eq!(c.max_output_bytes, Some(50)); // present beats absent
    }

    #[test]
    fn combine_is_axis_addressed_not_transposed() {
        // Distinct per-axis sentinels must stay on their own axis through combine.
        let ceiling = ResourceCeiling {
            max_memory_bytes: Some(11),
            max_wall_ms: Some(22),
            max_output_bytes: Some(33),
        };
        let combined = ResourceCeiling::default().combine(ceiling);
        assert_eq!(combined.max_memory_bytes, Some(11));
        assert_eq!(combined.max_wall_ms, Some(22));
        assert_eq!(combined.max_output_bytes, Some(33));
    }
}
