use std::fmt::Display;
use std::fmt::{self};
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;

use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::metrics::ObservableGauge;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::time::Instant;
use tower::BoxError;

use super::redis::*;
use crate::configuration::RedisCache;
use crate::metrics;
use crate::plugins::telemetry::config_new::instruments::METER_NAME;

pub(crate) trait KeyType:
    Clone + fmt::Debug + fmt::Display + Hash + Eq + Send + Sync
{
}
pub(crate) trait ValueType:
    Clone + fmt::Debug + Send + Sync + Serialize + DeserializeOwned
{
    /// Returns an estimated size of the cache entry in bytes.
    fn estimated_size(&self) -> Option<usize> {
        None
    }
}

// Blanket implementation which satisfies the compiler
impl<K> KeyType for K
where
    K: Clone + fmt::Debug + fmt::Display + Hash + Eq + Send + Sync,
{
    // Nothing to implement, since K already supports the other traits.
    // It has the functions it needs already
}

pub(crate) type InMemoryCache<K, V> = moka::future::Cache<K, V>;

// placeholder storage module
//
// this will be replaced by the multi level (in memory + redis/memcached) once we find
// a suitable implementation.
#[derive(Clone)]
pub(crate) struct CacheStorage<K: KeyType, V: ValueType> {
    caller: &'static str,
    inner: moka::future::Cache<K, V>,
    redis: Option<RedisCacheStorage>,
    cache_estimated_storage: Arc<AtomicI64>,
    // It's OK for these to be mutexes as they are only initialized once
    cache_size_gauge: Arc<parking_lot::Mutex<Option<ObservableGauge<i64>>>>,
    cache_estimated_storage_gauge: Arc<parking_lot::Mutex<Option<ObservableGauge<i64>>>>,
}

impl<K, V> CacheStorage<K, V>
where
    K: KeyType + 'static,
    V: ValueType + 'static,
{
    pub(crate) async fn new(
        max_capacity: NonZeroUsize,
        config: Option<RedisCache>,
        caller: &'static str,
    ) -> Result<Self, BoxError> {
        let cache_estimated_storage: Arc<AtomicI64> = Default::default();
        Ok(Self {
            cache_size_gauge: Default::default(),
            cache_estimated_storage_gauge: Default::default(),
            inner: Self::build_moka_cache(max_capacity, cache_estimated_storage.clone()),
            cache_estimated_storage,
            caller,
            redis: if let Some(config) = config {
                let required_to_start = config.required_to_start;
                match RedisCacheStorage::new(config, caller).await {
                    Err(e) => {
                        tracing::error!(
                            cache = caller,
                            e,
                            "could not open connection to Redis for caching",
                        );
                        if required_to_start {
                            return Err(e);
                        }
                        None
                    }
                    Ok(storage) => Some(storage),
                }
            } else {
                None
            },
        })
    }

    pub(crate) fn new_in_memory(max_capacity: NonZeroUsize, caller: &'static str) -> Self {
        let cache_estimated_storage: Arc<AtomicI64> = Default::default();
        Self {
            cache_size_gauge: Default::default(),
            cache_estimated_storage_gauge: Default::default(),
            inner: Self::build_moka_cache(max_capacity, cache_estimated_storage.clone()),
            cache_estimated_storage,
            caller,
            redis: None,
        }
    }

    fn build_moka_cache(
        max_capacity: NonZeroUsize,
        cache_estimated_storage: Arc<AtomicI64>,
    ) -> moka::future::Cache<K, V> {
        moka::future::Cache::builder()
            .max_capacity(max_capacity.get() as u64)
            .eviction_listener(move |_key, value: V, _cause| {
                let evicted_size = value.estimated_size().unwrap_or(0) as i64;
                cache_estimated_storage.fetch_sub(evicted_size, Ordering::SeqCst);
            })
            .build()
    }

    fn create_cache_size_gauge(&self) -> ObservableGauge<i64> {
        let meter: opentelemetry::metrics::Meter = metrics::meter_provider().meter(METER_NAME);
        let inner_clone = self.inner.clone();
        let caller = self.caller;
        meter
            .i64_observable_gauge("apollo.router.cache.size")
            .with_description("Cache size")
            .with_callback(move |i| {
                i.observe(
                    inner_clone.entry_count() as i64,
                    &[
                        KeyValue::new("kind", caller),
                        KeyValue::new("type", "memory"),
                    ],
                )
            })
            .build()
    }

    fn create_cache_estimated_storage_size_gauge(&self) -> ObservableGauge<i64> {
        let meter: opentelemetry::metrics::Meter = metrics::meter_provider().meter(METER_NAME);
        let cache_estimated_storage_for_gauge = self.cache_estimated_storage.clone();
        let caller = self.caller;

        meter
            .i64_observable_gauge("apollo.router.cache.storage.estimated_size")
            .with_description("Estimated cache storage")
            .with_unit("bytes")
            .with_callback(move |i| {
                // If there's no storage then don't bother updating the gauge
                let value = cache_estimated_storage_for_gauge.load(Ordering::SeqCst);
                if value > 0 {
                    i.observe(
                        cache_estimated_storage_for_gauge.load(Ordering::SeqCst),
                        &[
                            KeyValue::new("kind", caller),
                            KeyValue::new("type", "memory"),
                        ],
                    )
                }
            })
            .build()
    }

    /// `init_from_redis` is called with values newly deserialized from Redis cache
    /// if an error is returned, the value is ignored and considered a cache miss.
    pub(crate) async fn get(
        &self,
        key: &K,
        mut init_from_redis: impl FnMut(&mut V) -> Result<(), String>,
    ) -> Option<V> {
        let instant_memory = Instant::now();
        let res = self.inner.get(key).await;

        match res {
            Some(v) => {
                let duration = instant_memory.elapsed();
                f64_histogram!(
                    "apollo.router.cache.hit.time",
                    "Time to get a value from the cache in seconds",
                    duration.as_secs_f64(),
                    kind = self.caller,
                    storage = CacheStorageName::Memory.to_string()
                );
                Some(v)
            }
            None => {
                let duration = instant_memory.elapsed();
                f64_histogram!(
                    "apollo.router.cache.miss.time",
                    "Time to check the cache for an uncached value in seconds",
                    duration.as_secs_f64(),
                    kind = self.caller,
                    storage = CacheStorageName::Memory.to_string()
                );

                let instant_redis = Instant::now();
                if let Some(redis) = self.redis.as_ref() {
                    let inner_key = RedisKey(key.clone());
                    let redis_value = redis.get(inner_key).await.ok().and_then(|mut v| {
                        match init_from_redis(&mut v.0) {
                            Ok(()) => Some(v),
                            Err(e) => {
                                tracing::error!("Invalid value from Redis cache: {e}");
                                None
                            }
                        }
                    });
                    match redis_value {
                        Some(v) => {
                            self.insert_in_memory(key.clone(), v.0.clone()).await;

                            let duration = instant_redis.elapsed();
                            f64_histogram!(
                                "apollo.router.cache.hit.time",
                                "Time to get a value from the cache in seconds",
                                duration.as_secs_f64(),
                                kind = self.caller,
                                storage = CacheStorageName::Redis.to_string()
                            );
                            Some(v.0)
                        }
                        None => {
                            let duration = instant_redis.elapsed();
                            f64_histogram!(
                                "apollo.router.cache.miss.time",
                                "Time to check the cache for an uncached value in seconds",
                                duration.as_secs_f64(),
                                kind = self.caller,
                                storage = CacheStorageName::Redis.to_string()
                            );
                            None
                        }
                    }
                } else {
                    None
                }
            }
        }
    }

    pub(crate) async fn insert(&self, key: K, value: V) {
        if let Some(redis) = self.redis.as_ref() {
            redis
                .insert(RedisKey(key.clone()), RedisValue(value.clone()), None)
                .await;
        }

        self.insert_in_memory(key, value).await;
    }

    pub(crate) async fn insert_in_memory(&self, key: K, value: V)
    where
        V: ValueType,
    {
        let new_size = value.estimated_size().unwrap_or(0) as i64;
        self.inner.insert(key, value).await;
        self.cache_estimated_storage
            .fetch_add(new_size, Ordering::SeqCst);
        // Eviction listener handles subtracting evicted entry sizes
    }

    pub(crate) fn in_memory_cache(&self) -> InMemoryCache<K, V> {
        self.inner.clone()
    }

    #[cfg(test)]
    pub(crate) async fn len(&self) -> usize {
        self.inner.run_pending_tasks().await;
        self.inner.entry_count() as usize
    }

    #[cfg(test)]
    pub(crate) async fn flush_pending(&self) {
        self.inner.run_pending_tasks().await;
    }

    pub(crate) fn activate(&self) {
        // Gauges MUST be created after the meter provider is initialized.
        // This means that on reload we need a non-fallible way to recreate the gauges.
        *self.cache_size_gauge.lock() = Some(self.create_cache_size_gauge());
        *self.cache_estimated_storage_gauge.lock() =
            Some(self.create_cache_estimated_storage_size_gauge());

        // Also activate Redis metrics if present
        if let Some(redis) = &self.redis {
            redis.activate();
        }
    }
}

enum CacheStorageName {
    Redis,
    Memory,
}

impl Display for CacheStorageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheStorageName::Redis => write!(f, "redis"),
            CacheStorageName::Memory => write!(f, "memory"),
        }
    }
}

impl ValueType for String {
    fn estimated_size(&self) -> Option<usize> {
        Some(self.len())
    }
}

impl ValueType for crate::graphql::Response {
    fn estimated_size(&self) -> Option<usize> {
        None
    }
}

impl ValueType for usize {
    fn estimated_size(&self) -> Option<usize> {
        Some(std::mem::size_of::<usize>())
    }
}

#[cfg(test)]
mod test {
    use std::num::NonZeroUsize;

    use crate::cache::estimate_size;
    use crate::cache::storage::CacheStorage;
    use crate::cache::storage::ValueType;
    use crate::metrics::FutureMetricsExt;

    #[tokio::test]
    async fn test_metrics() {
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        struct Stuff {}
        impl ValueType for Stuff {
            fn estimated_size(&self) -> Option<usize> {
                Some(1)
            }
        }

        async {
            let cache: CacheStorage<String, Stuff> =
                CacheStorage::new(NonZeroUsize::new(10).unwrap(), None, "test")
                    .await
                    .unwrap();
            cache.activate();

            cache.insert("test".to_string(), Stuff {}).await;
            cache.flush_pending().await;
            assert_gauge!(
                "apollo.router.cache.storage.estimated_size",
                1,
                "kind" = "test",
                "type" = "memory"
            );
            assert_gauge!(
                "apollo.router.cache.size",
                1,
                "kind" = "test",
                "type" = "memory"
            );
        }
        .with_metrics()
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_metrics_not_emitted_where_no_estimated_size() {
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        struct Stuff {}
        impl ValueType for Stuff {
            fn estimated_size(&self) -> Option<usize> {
                None
            }
        }

        async {
            let cache: CacheStorage<String, Stuff> =
                CacheStorage::new(NonZeroUsize::new(10).unwrap(), None, "test")
                    .await
                    .unwrap();
            cache.activate();

            cache.insert("test".to_string(), Stuff {}).await;
            cache.flush_pending().await;
            // This metric won't exist
            assert_gauge!(
                "apollo.router.cache.size",
                0,
                "kind" = "test",
                "type" = "memory"
            );
        }
        .with_metrics()
        .await;
    }

    #[tokio::test]
    async fn test_metrics_eviction() {
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        struct Stuff {
            test: String,
        }
        impl ValueType for Stuff {
            fn estimated_size(&self) -> Option<usize> {
                Some(estimate_size(self))
            }
        }

        async {
            // note that the cache size is 1
            // so the second insert will always evict
            let cache: CacheStorage<String, Stuff> =
                CacheStorage::new(NonZeroUsize::new(1).unwrap(), None, "test")
                    .await
                    .unwrap();
            cache.activate();

            cache
                .insert(
                    "test".to_string(),
                    Stuff {
                        test: "test".to_string(),
                    },
                )
                .await;
            cache.flush_pending().await;
            assert_gauge!(
                "apollo.router.cache.storage.estimated_size",
                28,
                "kind" = "test",
                "type" = "memory"
            );
            assert_gauge!(
                "apollo.router.cache.size",
                1,
                "kind" = "test",
                "type" = "memory"
            );

            // Insert something slightly larger
            cache
                .insert(
                    "test".to_string(),
                    Stuff {
                        test: "test_extended".to_string(),
                    },
                )
                .await;
            cache.flush_pending().await;
            assert_gauge!(
                "apollo.router.cache.storage.estimated_size",
                37,
                "kind" = "test",
                "type" = "memory"
            );
            assert_gauge!(
                "apollo.router.cache.size",
                1,
                "kind" = "test",
                "type" = "memory"
            );

            // Insert a new entry into the full cache. Unlike LRU, moka uses TinyLFU admission:
            // "test" (higher frequency) is retained; the cold "test2" entry is evicted.
            cache
                .insert(
                    "test2".to_string(),
                    Stuff {
                        test: "test".to_string(),
                    },
                )
                .await;
            cache.flush_pending().await;
            assert_gauge!(
                "apollo.router.cache.storage.estimated_size",
                37,
                "kind" = "test",
                "type" = "memory"
            );
            assert_gauge!(
                "apollo.router.cache.size",
                1,
                "kind" = "test",
                "type" = "memory"
            );
        }
        .with_metrics()
        .await;
    }
}
