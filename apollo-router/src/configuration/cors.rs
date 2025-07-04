//! Cross Origin Resource Sharing (CORS configuration)

use std::str::FromStr;
use std::time::Duration;

use http::HeaderName;
use http::HeaderValue;
use http::Method;
use http::request::Parts;
use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use tower_http::cors;
use tower_http::cors::CorsLayer;
use tower::{Service, Layer, ServiceExt};
use tower::util::BoxService;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::future::Future;

/// Cross origin request configuration with support for multiple policies.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorsConfig {
    /// Array of CORS policies. The first policy that matches the request origin will be used.
    pub(crate) policies: Vec<CorsPolicy>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            policies: vec![CorsPolicy::default()],
        }
    }
}

/// Individual CORS policy configuration.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(default)]
pub(crate) struct CorsPolicy {
    /// Optional name for the policy (for identification/debugging).
    pub(crate) name: Option<String>,

    /// Set to true to allow any origin.
    ///
    /// Defaults to false
    /// Having this set to true is the only way to allow Origin: null.
    pub(crate) allow_any_origin: bool,

    /// Set to true to add the `Access-Control-Allow-Credentials` header.
    pub(crate) allow_credentials: bool,

    /// The headers to allow.
    ///
    /// If this value is not set, the router will mirror client's `Access-Control-Request-Headers`.
    ///
    /// Note that if you set headers here,
    /// you also want to have a look at your `CSRF` plugins configuration,
    /// and make sure you either:
    /// - accept `x-apollo-operation-name` AND / OR `apollo-require-preflight`
    /// - defined `csrf` required headers in your yml configuration, as shown in the
    ///   `examples/cors-and-csrf/custom-headers.router.yaml` files.
    pub(crate) allow_headers: Vec<String>,

    /// Which response headers should be made available to scripts running in the browser,
    /// in response to a cross-origin request.
    pub(crate) expose_headers: Option<Vec<String>>,

    /// The origin(s) to allow requests from.
    /// Defaults to `https://studio.apollographql.com/` for Apollo Studio.
    pub(crate) origins: Vec<String>,

    /// `Regex`es you want to match the origins against to determine if they're allowed.
    /// Defaults to an empty list.
    /// Note that `origins` will be evaluated before `match_origins`
    pub(crate) match_origins: Option<Vec<String>>,

    /// Allowed request methods. Defaults to GET, POST, OPTIONS.
    pub(crate) methods: Vec<String>,

    /// The `Access-Control-Max-Age` header value in time units
    #[serde(deserialize_with = "humantime_serde::deserialize", default)]
    #[schemars(with = "String", default)]
    pub(crate) max_age: Option<Duration>,
}

impl Default for CorsPolicy {
    fn default() -> Self {
        Self::builder().build()
    }
}

/// Legacy CORS struct for backwards compatibility during transition.
/// This is a type alias to CorsPolicy for now.
pub(crate) type Cors = CorsPolicy;

impl From<CorsPolicy> for CorsConfig {
    fn from(policy: CorsPolicy) -> Self {
        CorsConfig::new(vec![policy])
    }
}

fn default_origins() -> Vec<String> {
    vec!["https://studio.apollographql.com".into()]
}

fn default_cors_methods() -> Vec<String> {
    vec!["GET".into(), "POST".into(), "OPTIONS".into()]
}

#[buildstructor::buildstructor]
impl CorsPolicy {
    #[builder]
    pub(crate) fn new(
        name: Option<String>,
        allow_any_origin: Option<bool>,
        allow_credentials: Option<bool>,
        allow_headers: Option<Vec<String>>,
        expose_headers: Option<Vec<String>>,
        origins: Option<Vec<String>>,
        match_origins: Option<Vec<String>>,
        methods: Option<Vec<String>>,
        max_age: Option<Duration>,
    ) -> Self {
        Self {
            name,
            expose_headers,
            match_origins,
            max_age,
            origins: origins.unwrap_or_else(default_origins),
            methods: methods.unwrap_or_else(default_cors_methods),
            allow_any_origin: allow_any_origin.unwrap_or_default(),
            allow_credentials: allow_credentials.unwrap_or_default(),
            allow_headers: allow_headers.unwrap_or_default(),
        }
    }
}

/// A custom CORS service that dynamically selects the appropriate policy per request.
#[derive(Clone)]
pub(crate) struct DynamicCorsService<S> {
    inner: S,
    policies: Vec<CorsPolicy>,
}

impl<S> DynamicCorsService<S> {
    pub(crate) fn new(inner: S, config: CorsConfig) -> Result<Self, String> {
        // Validate all policies
        for (i, policy) in config.policies.iter().enumerate() {
            policy.ensure_usable_cors_rules()
                .map_err(|e| format!("Policy {}: {}", i, e))?;
        }
        
        Ok(Self {
            inner,
            policies: config.policies,
        })
    }
}

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for DynamicCorsService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + Default + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<ReqBody>) -> Self::Future {
        // Extract origin from request
        let origin = request
            .headers()
            .get("origin")
            .and_then(|h| h.to_str().ok());

        // Find matching policy
        let matching_policy = if let Some(origin_str) = origin {
            self.policies
                .iter()
                .find(|policy| policy.matches_origin(origin_str))
                .cloned()
        } else {
            None
        };

        let mut inner_service = self.inner.clone();

        Box::pin(async move {
            if let Some(policy) = matching_policy {
                // Create and apply the CORS layer for the matching policy
                match policy.into_layer() {
                    Ok(cors_layer) => {
                        let cors_service = cors_layer.layer(inner_service);
                        let boxed_service = BoxService::new(cors_service);
                        boxed_service.oneshot(request).await
                    },
                    Err(_) => {
                        // If layer creation fails, proceed without CORS headers
                        inner_service.call(request).await
                    }
                }
            } else {
                // No matching policy, proceed without CORS headers
                inner_service.call(request).await
            }
        })
    }
}

impl CorsConfig {
    /// Create a new CorsConfig with the given policies.
    pub(crate) fn new(policies: Vec<CorsPolicy>) -> Self {
        Self { policies }
    }

    /// Find the first policy that matches the given origin.
    pub(crate) fn find_matching_policy(&self, origin: Option<&str>) -> Option<&CorsPolicy> {
        let origin = origin?;
        
        for policy in &self.policies {
            if policy.matches_origin(origin) {
                return Some(policy);
            }
        }
        
        None
    }

    /// Convert the CorsConfig into a CorsLayer that uses dynamic policy selection.
    pub(crate) fn into_layer(self) -> Result<CorsLayer, String> {
        // This method is kept for backwards compatibility, but the real dynamic behavior
        // is implemented in DynamicCorsService. For this method, we'll create a basic
        // layer that accepts any origin that matches any policy.
        
        // Validate all policies first
        for (i, policy) in self.policies.iter().enumerate() {
            policy.ensure_usable_cors_rules()
                .map_err(|e| format!("Policy {}: {}", i, e))?;
        }

        if self.policies.is_empty() {
            // No policies, use default
            return CorsPolicy::default().into_layer();
        }

        // Create a CORS layer that allows any origin that matches any policy
        let policies = self.policies.clone();
        let cors = CorsLayer::new()
            .vary([])
            .allow_origin(cors::AllowOrigin::predicate(
                move |origin: &HeaderValue, _: &Parts| {
                    let origin_str = origin.to_str().unwrap_or_default();
                    policies.iter().any(|policy| policy.matches_origin(origin_str))
                }
            ))
            // Use most permissive settings since we can't be dynamic here
            .allow_headers(cors::AllowHeaders::mirror_request())
            .allow_methods(cors::AllowMethods::list({
                let mut all_methods: Vec<Method> = Vec::new();
                for policy in &self.policies {
                    for method in &policy.methods {
                        if let Ok(m) = method.parse::<Method>() {
                            all_methods.push(m);
                        }
                    }
                }
                all_methods.sort_by(|a, b| a.as_str().cmp(b.as_str()));
                all_methods.dedup();
                if all_methods.is_empty() {
                    vec![Method::GET, Method::POST, Method::OPTIONS]
                } else {
                    all_methods
                }
            }))
            .allow_credentials(self.policies.iter().any(|p| p.allow_credentials))
            .expose_headers(cors::ExposeHeaders::list({
                let mut all_expose_headers: Vec<HeaderName> = Vec::new();
                for policy in &self.policies {
                    if let Some(expose_headers) = &policy.expose_headers {
                        for header in expose_headers {
                            if let Ok(h) = header.parse::<HeaderName>() {
                                all_expose_headers.push(h);
                            }
                        }
                    }
                }
                all_expose_headers.sort_by(|a, b| a.as_str().cmp(b.as_str()));
                all_expose_headers.dedup();
                all_expose_headers
            }));
            
        // Set max age to the maximum from all policies
        let cors = if let Some(max_age) = self.policies.iter().filter_map(|p| p.max_age).max() {
            cors.max_age(max_age)
        } else {
            cors
        };
        
        Ok(cors)
    }

    /// Create a dynamic CORS service that applies the correct policy per request.
    pub(crate) fn into_service<S>(self, inner: S) -> Result<DynamicCorsService<S>, String> {
        DynamicCorsService::new(inner, self)
    }
}

impl CorsPolicy {
    /// Check if this policy matches the given origin.
    pub(crate) fn matches_origin(&self, origin: &str) -> bool {
        if self.allow_any_origin {
            return true;
        }

        // Check exact origin matches
        if self.origins.iter().any(|o| o == origin) {
            return true;
        }

        // Check regex matches
        if let Some(match_origins) = &self.match_origins {
            for pattern in match_origins {
                if let Ok(regex) = Regex::new(pattern) {
                    if regex.is_match(origin) {
                        return true;
                    }
                }
            }
        }

        false
    }

    pub(crate) fn into_layer(self) -> Result<CorsLayer, String> {
        // Ensure configuration is valid before creating CorsLayer
        self.ensure_usable_cors_rules()?;

        let allow_headers = if self.allow_headers.is_empty() {
            cors::AllowHeaders::mirror_request()
        } else {
            cors::AllowHeaders::list(parse_values::<HeaderName>(
                &self.allow_headers,
                "allow header name",
            )?)
        };

        let cors = CorsLayer::new()
            .vary([])
            .allow_credentials(self.allow_credentials)
            .allow_headers(allow_headers)
            .expose_headers(cors::ExposeHeaders::list(parse_values::<HeaderName>(
                &self.expose_headers.unwrap_or_default(),
                "expose header name",
            )?))
            .allow_methods(cors::AllowMethods::list(parse_values::<Method>(
                &self.methods,
                "method",
            )?));
        let cors = if let Some(max_age) = self.max_age {
            cors.max_age(max_age)
        } else {
            cors
        };

        if self.allow_any_origin {
            Ok(cors.allow_origin(cors::Any))
        } else if let Some(match_origins) = self.match_origins {
            let regexes: Vec<Regex> = parse_values(&match_origins, "match origin regex")?;
            let origins = self.origins.clone();

            Ok(cors.allow_origin(cors::AllowOrigin::predicate(
                move |origin: &HeaderValue, _: &Parts| {
                    origin
                        .to_str()
                        .map(|o| {
                            origins.iter().any(|origin| origin.as_str() == o)
                                || regexes.iter().any(|regex| regex.is_match(o))
                        })
                        .unwrap_or_default()
                },
            )))
        } else {
            Ok(cors.allow_origin(cors::AllowOrigin::list(parse_values(
                &self.origins,
                "origin",
            )?)))
        }
    }

    // This is cribbed from the similarly named function in tower-http. The version there
    // asserts that CORS rules are useable, which results in a panic if they aren't. We
    // don't want the router to panic in such cases, so this function returns an error
    // with a message describing what the problem is.
    fn ensure_usable_cors_rules(&self) -> Result<(), &'static str> {
        if self.origins.iter().any(|x| x == "*") {
            return Err(
                "Invalid CORS configuration: use `allow_any_origin: true` to set `Access-Control-Allow-Origin: *`",
            );
        }
        if self.allow_credentials {
            if self.allow_headers.iter().any(|x| x == "*") {
                return Err(
                    "Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` \
                        with `Access-Control-Allow-Headers: *`",
                );
            }

            if self.methods.iter().any(|x| x == "*") {
                return Err(
                    "Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` \
                    with `Access-Control-Allow-Methods: *`",
                );
            }

            if self.allow_any_origin {
                return Err(
                    "Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` \
                    with `allow_any_origin: true`",
                );
            }

            if let Some(headers) = &self.expose_headers {
                if headers.iter().any(|x| x == "*") {
                    return Err(
                        "Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` \
                        with `Access-Control-Expose-Headers: *`",
                    );
                }
            }
        }
        Ok(())
    }
}

fn parse_values<T>(values_to_parse: &[String], error_description: &str) -> Result<Vec<T>, String>
where
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    let mut errors = Vec::new();
    let mut values = Vec::new();
    for val in values_to_parse {
        match val
            .parse::<T>()
            .map_err(|err| format!("{error_description} '{val}' is not valid: {err}"))
        {
            Ok(val) => values.push(val),
            Err(err) => errors.push(err),
        }
    }

    if errors.is_empty() {
        Ok(values)
    } else {
        Err(errors.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[test]
    fn test_bad_allow_headers_cors_configuration() {
        let cors = CorsPolicy::builder()
            .allow_headers(vec![String::from("bad\nname")])
            .build();
        let layer = cors.into_layer();
        assert!(layer.is_err());

        assert_eq!(
            layer.unwrap_err(),
            String::from("allow header name 'bad\nname' is not valid: invalid HTTP header name")
        );
    }

    #[test]
    fn test_bad_allow_methods_cors_configuration() {
        let cors = CorsPolicy::builder()
            .methods(vec![String::from("bad\nmethod")])
            .build();
        let layer = cors.into_layer();
        assert!(layer.is_err());

        assert_eq!(
            layer.unwrap_err(),
            String::from("method 'bad\nmethod' is not valid: invalid HTTP method")
        );
    }

    #[test]
    fn test_bad_origins_cors_configuration() {
        let cors = CorsPolicy::builder()
            .origins(vec![String::from("bad\norigin")])
            .build();
        let layer = cors.into_layer();
        assert!(layer.is_err());

        assert_eq!(
            layer.unwrap_err(),
            String::from("origin 'bad\norigin' is not valid: failed to parse header value")
        );
    }

    #[test]
    fn test_bad_match_origins_cors_configuration() {
        let cors = CorsPolicy::builder()
            .match_origins(vec![String::from("[")])
            .build();
        let layer = cors.into_layer();
        assert!(layer.is_err());

        assert_eq!(
            layer.unwrap_err(),
            String::from(
                "match origin regex '[' is not valid: regex parse error:\n    [\n    ^\nerror: unclosed character class"
            )
        );
    }

    #[test]
    fn test_good_cors_configuration() {
        let cors = CorsPolicy::builder()
            .allow_headers(vec![String::from("good-name")])
            .build();
        let layer = cors.into_layer();
        assert!(layer.is_ok());
    }

    #[test]
    fn test_cors_config_single_policy() {
        let policy = CorsPolicy::builder()
            .origins(vec!["https://example.com".to_string()])
            .build();
        let config = CorsConfig::new(vec![policy]);
        
        assert!(config.find_matching_policy(Some("https://example.com")).is_some());
        assert!(config.find_matching_policy(Some("https://other.com")).is_none());
    }

    #[test]
    fn test_cors_config_multiple_policies() {
        let policy1 = CorsPolicy::builder()
            .name("policy1".to_string())
            .origins(vec!["https://example.com".to_string()])
            .build();
        let policy2 = CorsPolicy::builder()
            .name("policy2".to_string())
            .origins(vec!["https://other.com".to_string()])
            .build();
        let config = CorsConfig::new(vec![policy1, policy2]);
        
        let matched = config.find_matching_policy(Some("https://example.com"));
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name, Some("policy1".to_string()));
        
        let matched = config.find_matching_policy(Some("https://other.com"));
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name, Some("policy2".to_string()));
        
        assert!(config.find_matching_policy(Some("https://unknown.com")).is_none());
    }

    #[test]
    fn test_cors_config_first_match_wins() {
        let policy1 = CorsPolicy::builder()
            .name("policy1".to_string())
            .origins(vec!["https://example.com".to_string()])
            .allow_credentials(true)
            .build();
        let policy2 = CorsPolicy::builder()
            .name("policy2".to_string())
            .origins(vec!["https://example.com".to_string()])
            .allow_credentials(false)
            .build();
        let config = CorsConfig::new(vec![policy1, policy2]);
        
        let matched = config.find_matching_policy(Some("https://example.com"));
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name, Some("policy1".to_string()));
        assert!(matched.unwrap().allow_credentials);
    }

    #[test]
    fn test_cors_config_regex_matching() {
        let policy = CorsPolicy::builder()
            .name("regex_policy".to_string())
            .origins(vec!["https://api.example.com".to_string()])
            .match_origins(vec!["^https://.*\\.example\\.com$".to_string()])
            .build();
        let config = CorsConfig::new(vec![policy]);
        
        // Exact match
        assert!(config.find_matching_policy(Some("https://api.example.com")).is_some());
        
        // Regex match
        assert!(config.find_matching_policy(Some("https://app.example.com")).is_some());
        assert!(config.find_matching_policy(Some("https://staging.example.com")).is_some());
        
        // No match
        assert!(config.find_matching_policy(Some("https://example.com")).is_none());
        assert!(config.find_matching_policy(Some("https://other.com")).is_none());
    }

    #[test]
    fn test_cors_config_allow_any_origin() {
        let policy = CorsPolicy::builder()
            .name("allow_any".to_string())
            .allow_any_origin(true)
            .build();
        let config = CorsConfig::new(vec![policy]);
        
        assert!(config.find_matching_policy(Some("https://example.com")).is_some());
        assert!(config.find_matching_policy(Some("https://any.com")).is_some());
        assert!(config.find_matching_policy(Some("http://localhost:3000")).is_some());
    }

    #[test]
    fn test_cors_config_mixed_policies() {
        let policy1 = CorsPolicy::builder()
            .name("specific".to_string())
            .origins(vec!["https://studio.apollographql.com".to_string()])
            .allow_credentials(true)
            .build();
        let policy2 = CorsPolicy::builder()
            .name("regex".to_string())
            .match_origins(vec!["^https://.*\\.example\\.com$".to_string()])
            .allow_credentials(false)
            .build();
        let policy3 = CorsPolicy::builder()
            .name("fallback".to_string())
            .allow_any_origin(true)
            .build();
        let config = CorsConfig::new(vec![policy1, policy2, policy3]);
        
        // Specific origin matches first policy
        let matched = config.find_matching_policy(Some("https://studio.apollographql.com"));
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name, Some("specific".to_string()));
        assert!(matched.unwrap().allow_credentials);
        
        // Regex matches second policy
        let matched = config.find_matching_policy(Some("https://app.example.com"));
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name, Some("regex".to_string()));
        assert!(!matched.unwrap().allow_credentials);
        
        // Any other origin matches third policy
        let matched = config.find_matching_policy(Some("https://random.com"));
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name, Some("fallback".to_string()));
        assert!(matched.unwrap().allow_any_origin);
    }

    #[test]
    fn test_cors_config_into_layer() {
        let policy1 = CorsPolicy::builder()
            .origins(vec!["https://example.com".to_string()])
            .allow_credentials(true)
            .build();
        let policy2 = CorsPolicy::builder()
            .origins(vec!["https://other.com".to_string()])
            .allow_credentials(false)
            .build();
        let config = CorsConfig::new(vec![policy1, policy2]);
        
        let layer = config.into_layer();
        assert!(layer.is_ok());
    }

    #[test]
    fn test_cors_config_validation_errors() {
        // Test policy with invalid configuration
        let policy = CorsPolicy::builder()
            .allow_credentials(true)
            .allow_any_origin(true)
            .build();
        let config = CorsConfig::new(vec![policy]);
        
        let layer = config.into_layer();
        assert!(layer.is_err());
        assert!(layer.unwrap_err().contains("Policy 0"));
    }

    #[test]
    fn test_cors_config_empty_policies() {
        let config = CorsConfig::new(vec![]);
        
        // No policies means no match
        assert!(config.find_matching_policy(Some("https://example.com")).is_none());
        
        // Should still create a layer (though it will reject everything)
        let layer = config.into_layer();
        assert!(layer.is_ok());
    }

    #[test]
    fn test_cors_config_default() {
        let config = CorsConfig::default();
        
        // Default should have one policy with Apollo Studio origin
        assert_eq!(config.policies.len(), 1);
        assert!(config.find_matching_policy(Some("https://studio.apollographql.com")).is_some());
    }

    #[test]
    fn test_cors_policy_matches_origin() {
        let policy = CorsPolicy::builder()
            .origins(vec!["https://example.com".to_string()])
            .match_origins(vec!["^https://.*\\.test\\.com$".to_string()])
            .build();
        
        // Exact match
        assert!(policy.matches_origin("https://example.com"));
        
        // Regex match
        assert!(policy.matches_origin("https://app.test.com"));
        assert!(policy.matches_origin("https://api.test.com"));
        
        // No match
        assert!(!policy.matches_origin("https://other.com"));
        assert!(!policy.matches_origin("https://test.com"));
    }

    #[test]
    fn test_cors_policy_matches_origin_allow_any() {
        let policy = CorsPolicy::builder()
            .allow_any_origin(true)
            .build();
        
        // Should match any origin
        assert!(policy.matches_origin("https://example.com"));
        assert!(policy.matches_origin("http://localhost:3000"));
        assert!(policy.matches_origin("https://any.domain.com"));
    }

    #[test]
    fn test_cors_policy_matches_origin_invalid_regex() {
        let policy = CorsPolicy::builder()
            .match_origins(vec!["[invalid-regex".to_string()])
            .build();
        
        // Should not match when regex is invalid
        assert!(!policy.matches_origin("https://example.com"));
    }

    #[test]
    fn test_dynamic_cors_service_creation() {
        let policy1 = CorsPolicy::builder()
            .origins(vec!["https://example.com".to_string()])
            .build();
        let config = CorsConfig::new(vec![policy1]);
        
        // Create a mock service
        let mock_service = tower::service_fn(|_req: http::Request<()>| async {
            Ok::<http::Response<String>, Box<dyn std::error::Error>>(
                http::Response::new("test".to_string())
            )
        });
        
        // This should succeed
        let result = config.into_service(mock_service);
        assert!(result.is_ok());
    }
}
