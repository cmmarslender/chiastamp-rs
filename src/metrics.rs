use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;

pub struct Metrics {
    pub pending_proofs: Arc<Gauge<i64>>,
    pub pending_batches: Arc<Gauge<i64>>,
    pub confirmed_batches: Arc<Gauge<i64>>,
    pub confirmed_proofs: Arc<Gauge<i64>>,
    registry: Arc<Registry>,
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let pending_proofs = Arc::new(Gauge::default());
        let pending_batches = Arc::new(Gauge::default());
        let confirmed_batches = Arc::new(Gauge::default());
        let confirmed_proofs = Arc::new(Gauge::default());

        // Register by cloning the Arc and dereferencing to get &Gauge
        // The registry will store it, but we keep our Arc for updates
        registry.register(
            "pending_proofs",
            "Number of pending proofs not in a batch yet",
            (*pending_proofs).clone(),
        );
        registry.register(
            "pending_batches",
            "Number of batches pending inclusion in a block",
            (*pending_batches).clone(),
        );
        registry.register(
            "confirmed_batches",
            "Number of batches confirmed in a block",
            (*confirmed_batches).clone(),
        );
        registry.register(
            "confirmed_proofs",
            "Total number of proofs across all batches that have made it to blocks",
            (*confirmed_proofs).clone(),
        );

        Metrics {
            pending_proofs,
            pending_batches,
            confirmed_batches,
            confirmed_proofs,
            registry: Arc::new(registry),
        }
    }

    pub fn gather(&self) -> Result<String, std::fmt::Error> {
        let mut buffer = String::new();
        prometheus_client::encoding::text::encode(&mut buffer, &self.registry)?;
        Ok(buffer)
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
