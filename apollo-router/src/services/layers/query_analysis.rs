//! Implements GraphQL parsing/validation/usage counting of requests at the supergraph service
//! stage.

use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::sync::Arc;

use apollo_compiler::ExecutableDocument;
use apollo_compiler::Node;
use apollo_compiler::ast;
use apollo_compiler::executable::Operation;
use apollo_compiler::validation::Valid;
use http::StatusCode;
use lru::LruCache;
use tokio::sync::Mutex;

use crate::Configuration;
use crate::Context;
use crate::apollo_studio_interop::ExtendedReferenceStats;
use crate::apollo_studio_interop::UsageReporting;
use crate::apollo_studio_interop::generate_extended_references;
use crate::compute_job;
use crate::compute_job::MaybeBackPressureError;
use crate::context::OPERATION_KIND;
use crate::context::OPERATION_NAME;
use crate::graphql::Error;
use crate::graphql::ErrorExtension;
use crate::graphql::IntoGraphQLErrors;
use crate::plugins::authorization::AuthorizationPlugin;
use crate::plugins::telemetry::config::ApolloMetricsReferenceMode;
use crate::plugins::telemetry::config::Conf as TelemetryConfig;
use crate::plugins::telemetry::consts::QUERY_PARSING_SPAN_NAME;
use crate::query_planner::OperationKind;
use crate::services::SupergraphRequest;
use crate::services::SupergraphResponse;
use crate::spec::GRAPHQL_VALIDATION_FAILURE_ERROR_KEY;
use crate::spec::Query;
use crate::spec::QueryHash;
use crate::spec::Schema;
use crate::spec::SpecError;

/// A layer-like type that handles several aspects of query parsing and analysis.
///
/// The supergraph layer implementation is in [QueryAnalysisLayer::supergraph_request].
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub(crate) struct QueryAnalysisLayer {
    pub(crate) schema: Arc<Schema>,
    configuration: Arc<Configuration>,
    cache: Arc<Mutex<LruCache<QueryAnalysisKey, Result<(Context, ParsedDocument), SpecError>>>>,
    enable_authorization_directives: bool,
    metrics_reference_mode: ApolloMetricsReferenceMode,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct QueryAnalysisKey {
    query: String,
    operation_name: Option<String>,
}

impl QueryAnalysisLayer {
    pub(crate) async fn new(schema: Arc<Schema>, configuration: Arc<Configuration>) -> Self {
        let enable_authorization_directives =
            AuthorizationPlugin::enable_directives(&configuration, &schema).unwrap_or(false);
        let metrics_reference_mode = TelemetryConfig::metrics_reference_mode(&configuration);

        Self {
            schema,
            cache: Arc::new(Mutex::new(LruCache::new(
                configuration
                    .supergraph
                    .query_planning
                    .cache
                    .in_memory
                    .limit,
            ))),
            enable_authorization_directives,
            configuration,
            metrics_reference_mode,
        }
    }

    // XXX(@goto-bus-stop): This is public because query warmup uses it. I think the reason that
    // warmup uses this instead of `Query::parse_document` directly is to use the worker pool.
    pub(crate) async fn parse_document(
        &self,
        query: &str,
        operation_name: Option<&str>,
    ) -> Result<ParsedDocument, MaybeBackPressureError<SpecError>> {
        let query = query.to_string();
        let operation_name = operation_name.map(|o| o.to_string());
        let schema = self.schema.clone();
        let conf = self.configuration.clone();

        // Must be created *outside* of the compute_job or the span is not connected to the parent
        let span = tracing::info_span!(QUERY_PARSING_SPAN_NAME, "otel.kind" = "INTERNAL");

        // TODO: is this correct?
        let span = std::panic::AssertUnwindSafe(span);
        let conf = std::panic::AssertUnwindSafe(conf);

        let priority = compute_job::Priority::P4; // Medium priority
        compute_job::execute(priority, move |_| {
            span.in_scope(|| {
                Query::parse_document(
                    &query,
                    operation_name.as_deref(),
                    schema.as_ref(),
                    conf.as_ref(),
                )
            })
        })
        .map_err(MaybeBackPressureError::TemporaryError)?
        .await
        // `expect()` propagates any panic that potentially happens in the closure, but:
        //
        // * We try to avoid such panics in the first place and consider them bugs
        // * The panic handler in `apollo-router/src/executable.rs` exits the process
        //   so this error case should never be reached.
        .expect("Query::parse_document panicked")
        .map_err(MaybeBackPressureError::PermanentError)
    }

    /// Parses the GraphQL in the supergraph request and computes Apollo usage references.
    ///
    /// This functions similarly to a checkpoint service, short-circuiting the pipeline on error
    /// (using an `Err()` return value).
    /// The user of this function is responsible for propagating short-circuiting.
    ///
    /// # Context
    /// This stores values in the request context:
    /// - [`ParsedDocument`]
    /// - [`ExtendedReferenceStats`]
    /// - "operation_name" and "operation_kind"
    /// - authorization details (required scopes, policies), if any
    /// - [`Arc`]`<`[`UsageReporting`]`>` if there was an error; normally, this would be populated
    ///   by the caching query planner, but we do not reach that code if we fail early here.
    pub(crate) async fn supergraph_request(
        &self,
        request: SupergraphRequest,
    ) -> Result<SupergraphRequest, SupergraphResponse> {
        let query = request.supergraph_request.body().query.as_ref();

        if query.is_none() || query.unwrap().trim().is_empty() {
            let errors = vec![
                crate::error::Error::builder()
                    .message("Must provide query string.".to_string())
                    .extension_code("MISSING_QUERY_STRING")
                    .build(),
            ];
            return Err(SupergraphResponse::builder()
                .errors(errors)
                .status_code(StatusCode::BAD_REQUEST)
                .context(request.context)
                .build()
                .expect("response is valid"));
        }

        let op_name = request.supergraph_request.body().operation_name.clone();
        let query = request
            .supergraph_request
            .body()
            .query
            .clone()
            .expect("query presence was already checked");
        let entry = self
            .cache
            .lock()
            .await
            .get(&QueryAnalysisKey {
                query: query.clone(),
                operation_name: op_name.clone(),
            })
            .cloned();

        let res = match entry {
            None => match self.parse_document(&query, op_name.as_deref()).await {
                Err(e) => {
                    if let MaybeBackPressureError::PermanentError(errors) = &e {
                        (*self.cache.lock().await).put(
                            QueryAnalysisKey {
                                query,
                                operation_name: op_name.clone(),
                            },
                            Err(errors.clone()),
                        );
                    }
                    Err(e)
                }
                Ok(doc) => {
                    let context = Context::new();

                    if self.enable_authorization_directives {
                        AuthorizationPlugin::query_analysis(
                            &doc,
                            op_name.as_deref(),
                            &self.schema,
                            &context,
                        );
                    }

                    context
                        .insert(OPERATION_NAME, doc.operation.name.clone())
                        .expect("cannot insert operation name into context; this is a bug");
                    let operation_kind = OperationKind::from(doc.operation.operation_type);
                    context
                        .insert(OPERATION_KIND, operation_kind)
                        .expect("cannot insert operation kind in the context; this is a bug");

                    (*self.cache.lock().await).put(
                        QueryAnalysisKey {
                            query,
                            operation_name: op_name.clone(),
                        },
                        Ok((context.clone(), doc.clone())),
                    );

                    Ok((context, doc))
                }
            },
            Some(cached_result) => cached_result.map_err(MaybeBackPressureError::PermanentError),
        };

        match res {
            Ok((context, doc)) => {
                request.context.extend(&context);

                let extended_ref_stats = if matches!(
                    self.metrics_reference_mode,
                    ApolloMetricsReferenceMode::Extended
                ) {
                    Some(generate_extended_references(
                        doc.executable.clone(),
                        op_name,
                        self.schema.api_schema(),
                        &request.supergraph_request.body().variables,
                    ))
                } else {
                    None
                };

                request.context.extensions().with_lock(|lock| {
                    lock.insert::<ParsedDocument>(doc.clone());
                    if let Some(stats) = extended_ref_stats {
                        lock.insert::<ExtendedReferenceStats>(stats);
                    }
                });

                Ok(SupergraphRequest {
                    supergraph_request: request.supergraph_request,
                    context: request.context,
                })
            }
            Err(MaybeBackPressureError::PermanentError(errors)) => {
                request.context.extensions().with_lock(|lock| {
                    lock.insert(Arc::new(UsageReporting {
                        stats_report_key: errors.get_error_key().to_string(),
                        referenced_fields_by_type: HashMap::new(),
                    }))
                });
                let errors = match errors.into_graphql_errors() {
                    Ok(v) => v,
                    Err(errors) => vec![
                        Error::builder()
                            .message(errors.to_string())
                            .extension_code(errors.extension_code())
                            .build(),
                    ],
                };
                Err(SupergraphResponse::builder()
                    .errors(errors)
                    .status_code(StatusCode::BAD_REQUEST)
                    .context(request.context)
                    .build()
                    .expect("response is valid"))
            }
            Err(MaybeBackPressureError::TemporaryError(error)) => {
                request.context.extensions().with_lock(|lock| {
                    lock.insert(Arc::new(UsageReporting {
                        stats_report_key: GRAPHQL_VALIDATION_FAILURE_ERROR_KEY.to_string(),
                        referenced_fields_by_type: HashMap::new(),
                    }))
                });
                Err(SupergraphResponse::builder()
                    .error(error.to_graphql_error())
                    .status_code(StatusCode::SERVICE_UNAVAILABLE)
                    .context(request.context)
                    .build()
                    .expect("response is valid"))
            }
        }
    }
}

pub(crate) type ParsedDocument = Arc<ParsedDocumentInner>;

#[derive(Debug)]
pub(crate) struct ParsedDocumentInner {
    pub(crate) ast: ast::Document,
    pub(crate) executable: Arc<Valid<ExecutableDocument>>,
    pub(crate) hash: Arc<QueryHash>,
    pub(crate) operation: Node<Operation>,
    /// `__schema` or `__type`
    pub(crate) has_schema_introspection: bool,
    /// Non-meta fields explicitly defined in the schema
    pub(crate) has_explicit_root_fields: bool,
}

impl ParsedDocumentInner {
    pub(crate) fn new(
        ast: ast::Document,
        executable: Arc<Valid<ExecutableDocument>>,
        operation_name: Option<&str>,
        hash: Arc<QueryHash>,
    ) -> Result<Arc<Self>, SpecError> {
        let operation = get_operation(&executable, operation_name)?;
        let mut has_schema_introspection = false;
        let mut has_explicit_root_fields = false;
        for field in operation.root_fields(&executable) {
            match field.name.as_str() {
                "__typename" => {} // turns out we have no conditional on `has_root_typename`
                "__schema" | "__type" if operation.is_query() => has_schema_introspection = true,
                _ => has_explicit_root_fields = true,
            }
        }
        Ok(Arc::new(Self {
            ast,
            executable,
            hash,
            operation,
            has_schema_introspection,
            has_explicit_root_fields,
        }))
    }
}

pub(crate) fn get_operation(
    executable: &ExecutableDocument,
    operation_name: Option<&str>,
) -> Result<Node<Operation>, SpecError> {
    if let Ok(operation) = executable.operations.get(operation_name) {
        Ok(operation.clone())
    } else if let Some(name) = operation_name {
        Err(SpecError::UnknownOperation(name.to_owned()))
    } else if executable.operations.is_empty() {
        // Maybe not reachable?
        // A valid document is non-empty and has no unused fragments
        Err(SpecError::NoOperation)
    } else {
        debug_assert!(executable.operations.len() > 1);
        Err(SpecError::MultipleOperationWithoutOperationName)
    }
}

impl Display for ParsedDocumentInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Hash for ParsedDocumentInner {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl PartialEq for ParsedDocumentInner {
    fn eq(&self, other: &Self) -> bool {
        self.ast == other.ast
    }
}

impl Eq for ParsedDocumentInner {}
