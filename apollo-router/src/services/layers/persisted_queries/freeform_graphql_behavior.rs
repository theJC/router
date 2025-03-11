use super::PersistedQueryManifest;
use apollo_compiler::ast;
use std::collections::HashSet;

/// Describes whether the router should allow or deny a given request.
/// with an error, or allow it but log the operation as unknown.
pub(crate) struct FreeformGraphQLAction {
    pub(crate) should_allow: bool,
    pub(crate) should_log: bool,
}

/// How the router should respond to requests that are not resolved as the IDs
/// of an operation in the manifest. (For the most part this means "requests
/// sent as freeform GraphQL", though it also includes requests sent as an ID
/// that is not found in the PQ manifest but is found in the APQ cache; because
/// you cannot combine APQs with safelisting, this is only relevant in "allow
/// all" and "log unknown" modes.)
#[derive(Debug)]
pub(crate) enum FreeformGraphQLBehavior {
    AllowAll {
        apq_enabled: bool,
    },
    DenyAll {
        log_unknown: bool,
    },
    AllowIfInSafelist {
        safelist: FreeformGraphQLSafelist,
        log_unknown: bool,
    },
    LogUnlessInSafelist {
        safelist: FreeformGraphQLSafelist,
        apq_enabled: bool,
    },
}

impl FreeformGraphQLBehavior {
    pub(super) fn action_for_freeform_graphql(
        &self,
        ast: Result<&ast::Document, &str>,
    ) -> FreeformGraphQLAction {
        match self {
            FreeformGraphQLBehavior::AllowAll { .. } => FreeformGraphQLAction {
                should_allow: true,
                should_log: false,
            },
            // Note that this branch doesn't get called in practice, because we catch
            // DenyAll at an earlier phase with never_allows_freeform_graphql.
            FreeformGraphQLBehavior::DenyAll { log_unknown, .. } => FreeformGraphQLAction {
                should_allow: false,
                should_log: *log_unknown,
            },
            FreeformGraphQLBehavior::AllowIfInSafelist {
                safelist,
                log_unknown,
                ..
            } => {
                if safelist.is_allowed(ast) {
                    FreeformGraphQLAction {
                        should_allow: true,
                        should_log: false,
                    }
                } else {
                    FreeformGraphQLAction {
                        should_allow: false,
                        should_log: *log_unknown,
                    }
                }
            }
            FreeformGraphQLBehavior::LogUnlessInSafelist { safelist, .. } => {
                FreeformGraphQLAction {
                    should_allow: true,
                    should_log: !safelist.is_allowed(ast),
                }
            }
        }
    }
}

/// The normalized bodies of all operations in the PQ manifest.
///
/// Normalization currently consists of:
/// - Sorting the top-level definitions (operation and fragment definitions)
///   deterministically.
/// - Printing the AST using apollo-encoder's default formatting (ie,
///   normalizing all ignored characters such as whitespace and comments).
///
/// Sorting top-level definitions is important because common clients such as
/// Apollo Client Web have modes of use where it is easy to find all the
/// operation and fragment definitions at build time, but challenging to
/// determine what order the client will put them in at run time.
///
/// Normalizing ignored characters is helpful because being strict on whitespace
/// is more likely to get in your way than to aid in security --- but more
/// importantly, once we're doing any normalization at all, it's much easier to
/// normalize to the default formatting instead of trying to preserve
/// formatting.
#[derive(Debug)]
pub(crate) struct FreeformGraphQLSafelist {
    normalized_bodies: HashSet<String>,
}

impl FreeformGraphQLSafelist {
    pub(super) fn new(manifest: &PersistedQueryManifest) -> Self {
        let mut safelist = Self {
            normalized_bodies: HashSet::new(),
        };

        for body in manifest.values() {
            safelist.insert_from_manifest(body);
        }

        safelist
    }

    fn insert_from_manifest(&mut self, body_from_manifest: &str) {
        self.normalized_bodies.insert(
            self.normalize_body(
                ast::Document::parse(body_from_manifest, "from_manifest")
                    .as_ref()
                    .map_err(|_| body_from_manifest),
            ),
        );
    }

    pub(super) fn is_allowed(&self, ast: Result<&ast::Document, &str>) -> bool {
        // Note: consider adding an LRU cache that caches this function's return
        // value based solely on body_from_request without needing to normalize
        // the body.
        self.normalized_bodies.contains(&self.normalize_body(ast))
    }

    pub(super) fn normalize_body(&self, ast: Result<&ast::Document, &str>) -> String {
        match ast {
            Err(body_from_request) => {
                // If we can't parse the operation (whether from the PQ list or the
                // incoming request), then we can't normalize it. We keep it around
                // unnormalized, so that it at least works as a byte-for-byte
                // safelist entry.
                body_from_request.to_string()
            }
            Ok(ast) => {
                let mut operations = vec![];
                let mut fragments = vec![];

                for definition in &ast.definitions {
                    match definition {
                        ast::Definition::OperationDefinition(def) => operations.push(def.clone()),
                        ast::Definition::FragmentDefinition(def) => fragments.push(def.clone()),
                        _ => {}
                    }
                }

                let mut new_document = ast::Document::new();

                // First include operation definitions, sorted by name.
                operations.sort_by_key(|x| x.name.clone());
                new_document
                    .definitions
                    .extend(operations.into_iter().map(Into::into));

                // Next include fragment definitions, sorted by name.
                fragments.sort_by_key(|x| x.name.clone());
                new_document
                    .definitions
                    .extend(fragments.into_iter().map(Into::into));
                new_document.to_string()
            }
        }
    }
}
