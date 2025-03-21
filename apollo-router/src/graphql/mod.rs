//! Types related to GraphQL requests, responses, etc.

mod request;
mod response;
mod visitor;

use std::fmt;
use std::pin::Pin;

use apollo_compiler::response::GraphQLError as CompilerExecutionError;
use apollo_compiler::response::ResponseDataPathSegment;
use futures::Stream;
use heck::ToShoutySnakeCase;
pub use request::Request;
pub use response::IncrementalResponse;
pub use response::Response;
use serde::Deserialize;
use serde::Serialize;
use serde_json_bytes::ByteString;
use serde_json_bytes::Map as JsonMap;
use serde_json_bytes::Value;
pub(crate) use visitor::ResponseVisitor;

use crate::error::FetchError;
use crate::json_ext::Object;
use crate::json_ext::Path;
pub use crate::json_ext::Path as JsonPath;
pub use crate::json_ext::PathElement as JsonPathElement;
use crate::spec::query::ERROR_CODE_RESPONSE_VALIDATION;

/// An asynchronous [`Stream`] of GraphQL [`Response`]s.
///
/// In some cases such as with `@defer`, a single HTTP response from the Router
/// may contain multiple GraphQL responses that will be sent at different times
/// (as more data becomes available).
///
/// We represent this in Rust as a stream,
/// even if that stream happens to only contain one item.
pub type ResponseStream = Pin<Box<dyn Stream<Item = Response> + Send>>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "camelCase")]
/// The error location
pub struct Location {
    /// The line number
    pub line: u32,
    /// The column number
    pub column: u32,
}

/// A [GraphQL error](https://spec.graphql.org/October2021/#sec-Errors)
/// as may be found in the `errors` field of a GraphQL [`Response`].
///
/// Converted to (or from) JSON with serde.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Error {
    /// The error message.
    pub message: String,

    /// The locations of the error in the GraphQL document of the originating request.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub locations: Vec<Location>,

    /// If this is a field error, the JSON path to that field in [`Response::data`]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Path>,

    /// The optional GraphQL extensions for this error.
    #[serde(default, skip_serializing_if = "Object::is_empty")]
    pub extensions: Object,
}
// Implement getter and getter_mut to not use pub field directly

#[buildstructor::buildstructor]
impl Error {
    /// Returns a builder that builds a GraphQL [`Error`] from its components.
    ///
    /// Builder methods:
    ///
    /// * `.message(impl Into<`[`String`]`>)`
    ///   Required.
    ///   Sets [`Error::message`].
    ///
    /// * `.locations(impl Into<`[`Vec`]`<`[`Location`]`>>)`
    ///   Optional.
    ///   Sets the entire `Vec` of [`Error::locations`], which defaults to the empty.
    ///
    /// * `.location(impl Into<`[`Location`]`>)`
    ///   Optional, may be called multiple times.
    ///   Adds one item at the end of [`Error::locations`].
    ///
    /// * `.path(impl Into<`[`Path`]`>)`
    ///   Optional.
    ///   Sets [`Error::path`].
    ///
    /// * `.extensions(impl Into<`[`serde_json_bytes::Map`]`<`[`ByteString`]`, `[`Value`]`>>)`
    ///   Optional.
    ///   Sets the entire [`Error::extensions`] map, which defaults to empty.
    ///
    /// * `.extension(impl Into<`[`ByteString`]`>, impl Into<`[`Value`]`>)`
    ///   Optional, may be called multiple times.
    ///   Adds one item to the [`Error::extensions`] map.
    ///
    /// * `.build()`
    ///   Finishes the builder and returns a GraphQL [`Error`].
    #[builder(visibility = "pub")]
    fn new<T: Into<String>>(
        message: String,
        locations: Vec<Location>,
        path: Option<Path>,
        extension_code: T,
        // Skip the `Object` type alias in order to use buildstructor’s map special-casing
        mut extensions: JsonMap<ByteString, Value>,
    ) -> Self {
        extensions
            .entry("code")
            .or_insert_with(|| extension_code.into().into());
        Self {
            message,
            locations,
            path,
            extensions,
        }
    }

    pub(crate) fn from_value(service_name: &str, value: Value) -> Result<Error, FetchError> {
        let mut object =
            ensure_object!(value).map_err(|error| FetchError::SubrequestMalformedResponse {
                service: service_name.to_string(),
                reason: format!("invalid error within `errors`: {}", error),
            })?;

        let extensions =
            extract_key_value_from_object!(object, "extensions", Value::Object(o) => o)
                .map_err(|err| FetchError::SubrequestMalformedResponse {
                    service: service_name.to_string(),
                    reason: format!("invalid `extensions` within error: {}", err),
                })?
                .unwrap_or_default();
        let message = extract_key_value_from_object!(object, "message", Value::String(s) => s)
            .map_err(|err| FetchError::SubrequestMalformedResponse {
                service: service_name.to_string(),
                reason: format!("invalid `message` within error: {}", err),
            })?
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        let locations = extract_key_value_from_object!(object, "locations")
            .map(skip_invalid_locations)
            .map(serde_json_bytes::from_value)
            .transpose()
            .map_err(|err| FetchError::SubrequestMalformedResponse {
                service: service_name.to_string(),
                reason: format!("invalid `locations` within error: {}", err),
            })?
            .unwrap_or_default();
        let path = extract_key_value_from_object!(object, "path")
            .map(serde_json_bytes::from_value)
            .transpose()
            .map_err(|err| FetchError::SubrequestMalformedResponse {
                service: service_name.to_string(),
                reason: format!("invalid `path` within error: {}", err),
            })?;

        Ok(Error {
            message,
            locations,
            path,
            extensions,
        })
    }

    pub(crate) fn from_value_completion_value(value: &Value) -> Option<Error> {
        let value_completion = ensure_object!(value).ok()?;
        let mut extensions = value_completion
            .get("extensions")
            .and_then(|e: &Value| -> Option<Object> {
                serde_json_bytes::from_value(e.clone()).ok()
            })
            .unwrap_or_default();
        extensions.insert("code", ERROR_CODE_RESPONSE_VALIDATION.into());
        extensions.insert("severity", tracing::Level::WARN.as_str().into());

        let message = value_completion
            .get("message")
            .and_then(|m| m.as_str())
            .map(|m| m.to_string())
            .unwrap_or_default();
        let locations = value_completion
            .get("locations")
            .map(|l: &Value| skip_invalid_locations(l.clone()))
            .map(|l: Value| serde_json_bytes::from_value(l).unwrap_or_default())
            .unwrap_or_default();
        let path =
            value_completion
                .get("path")
                .and_then(|p: &serde_json_bytes::Value| -> Option<Path> {
                    serde_json_bytes::from_value(p.clone()).ok()
                });
        Some(Error {
            message,
            locations,
            path,
            extensions,
        })
    }
}

/// GraphQL spec require that both "line" and "column" are positive numbers.
/// However GraphQL Java and GraphQL Kotlin return `{ "line": -1, "column": -1 }`
/// if they can't determine error location inside query.
/// This function removes such locations from suplied value.
fn skip_invalid_locations(mut value: Value) -> Value {
    if let Some(array) = value.as_array_mut() {
        array.retain(|location| {
            location.get("line") != Some(&Value::from(-1))
                || location.get("column") != Some(&Value::from(-1))
        })
    }
    value
}

/// Displays (only) the error message.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

/// Trait used to convert expected errors into a list of GraphQL errors
pub(crate) trait IntoGraphQLErrors
where
    Self: Sized,
{
    fn into_graphql_errors(self) -> Result<Vec<Error>, Self>;
}

/// Trait used to get extension type from an error
pub(crate) trait ErrorExtension
where
    Self: Sized,
{
    fn extension_code(&self) -> String {
        std::any::type_name::<Self>().to_shouty_snake_case()
    }

    fn custom_extension_details(&self) -> Option<Object> {
        None
    }
}

impl From<CompilerExecutionError> for Error {
    fn from(error: CompilerExecutionError) -> Self {
        let CompilerExecutionError {
            message,
            locations,
            path,
            extensions,
        } = error;
        let locations = locations
            .into_iter()
            .map(|location| Location {
                line: location.line as u32,
                column: location.column as u32,
            })
            .collect::<Vec<_>>();
        let path = if !path.is_empty() {
            let elements = path
                .into_iter()
                .map(|element| match element {
                    ResponseDataPathSegment::Field(name) => {
                        JsonPathElement::Key(name.as_str().to_owned(), None)
                    }
                    ResponseDataPathSegment::ListIndex(i) => JsonPathElement::Index(i),
                })
                .collect();
            Some(Path(elements))
        } else {
            None
        };
        Self {
            message,
            locations,
            path,
            extensions,
        }
    }
}
