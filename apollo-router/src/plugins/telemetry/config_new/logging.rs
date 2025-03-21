use std::collections::BTreeMap;
use std::collections::HashSet;
use std::io::IsTerminal;
use std::time::Duration;

use schemars::JsonSchema;
use schemars::r#gen::SchemaGenerator;
use schemars::schema::InstanceType;
use schemars::schema::Metadata;
use schemars::schema::ObjectValidation;
use schemars::schema::Schema;
use schemars::schema::SchemaObject;
use schemars::schema::SingleOrVec;
use schemars::schema::SubschemaValidation;
use serde::Deserialize;
use serde::Deserializer;
use serde::de::MapAccess;
use serde::de::Visitor;

use crate::plugins::telemetry::config::AttributeValue;
use crate::plugins::telemetry::config::TraceIdFormat;
use crate::plugins::telemetry::resource::ConfigResource;

/// Logging configuration.
#[derive(Deserialize, JsonSchema, Clone, Default, Debug)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Logging {
    /// Common configuration
    pub(crate) common: LoggingCommon,
    /// Settings for logging to stdout.
    pub(crate) stdout: StdOut,
    #[serde(skip)]
    /// Settings for logging to a file.
    pub(crate) file: File,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct LoggingCommon {
    /// Set a service.name resource in your metrics
    pub(crate) service_name: Option<String>,
    /// Set a service.namespace attribute in your metrics
    pub(crate) service_namespace: Option<String>,
    /// The Open Telemetry resource
    pub(crate) resource: BTreeMap<String, AttributeValue>,
}

impl ConfigResource for LoggingCommon {
    fn service_name(&self) -> &Option<String> {
        &self.service_name
    }

    fn service_namespace(&self) -> &Option<String> {
        &self.service_namespace
    }

    fn resource(&self) -> &BTreeMap<String, AttributeValue> {
        &self.resource
    }
}

#[derive(Deserialize, JsonSchema, Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct StdOut {
    /// Set to true to log to stdout.
    pub(crate) enabled: bool,
    /// The format to log to stdout.
    pub(crate) format: Format,
    /// The format to log to stdout when you're running on an interactive terminal. When configured it will automatically use this `tty_format`` instead of the original `format` when an interactive terminal is detected
    pub(crate) tty_format: Option<Format>,
    /// Log rate limiting. The limit is set per type of log message
    pub(crate) rate_limit: RateLimit,
}

impl Default for StdOut {
    fn default() -> Self {
        StdOut {
            enabled: true,
            format: Format::default(),
            tty_format: None,
            rate_limit: RateLimit::default(),
        }
    }
}

#[derive(Deserialize, JsonSchema, Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RateLimit {
    /// Set to true to limit the rate of log messages
    pub(crate) enabled: bool,
    /// Number of log lines allowed in interval per message
    pub(crate) capacity: u32,
    /// Interval for rate limiting
    #[serde(deserialize_with = "humantime_serde::deserialize")]
    #[schemars(with = "String")]
    pub(crate) interval: Duration,
}

impl Default for RateLimit {
    fn default() -> Self {
        RateLimit {
            enabled: false,
            capacity: 1,
            interval: Duration::from_secs(1),
        }
    }
}

/// Log to a file
#[allow(dead_code)]
#[derive(Deserialize, JsonSchema, Clone, Default, Debug)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct File {
    /// Set to true to log to a file.
    pub(crate) enabled: bool,
    /// The path pattern of the file to log to.
    pub(crate) path: String,
    /// The format of the log file.
    pub(crate) format: Format,
    /// The period to rollover the log file.
    pub(crate) rollover: Rollover,
    /// Log rate limiting. The limit is set per type of log message
    pub(crate) rate_limit: Option<RateLimit>,
}

/// The format for logging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Format {
    // !!!!WARNING!!!!, if you change this enum then be sure to add the changes to the JsonSchema AND the custom deserializer.

    // Want to see support for these formats? Please open an issue!
    // /// https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData-discoverable-fields.html
    // Aws,
    // /// https://github.com/trentm/node-bunyan
    // Bunyan,
    // /// https://go2docs.graylog.org/5-0/getting_in_log_data/ingest_gelf.html#:~:text=The%20Graylog%20Extended%20Log%20Format,UDP%2C%20TCP%2C%20or%20HTTP.
    // Gelf,
    //
    // /// https://cloud.google.com/logging/docs/structured-logging
    // Google,
    // /// https://github.com/open-telemetry/opentelemetry-rust/tree/main/opentelemetry-appender-log
    // OpenTelemetry,
    /// https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/format/struct.Json.html
    Json(JsonFormat),

    /// https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/format/struct.Full.html
    Text(TextFormat),
}

// This custom implementation JsonSchema allows the user to supply an enum or a struct in the same way that the custom deserializer does.
impl JsonSchema for Format {
    fn schema_name() -> String {
        "logging_format".to_string()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        // Does nothing, but will compile error if the
        let types = vec![
            (
                "json",
                JsonFormat::json_schema(generator),
                "Tracing subscriber https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/format/struct.Json.html",
            ),
            (
                "text",
                TextFormat::json_schema(generator),
                "Tracing subscriber https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/format/struct.Full.html",
            ),
        ];

        Schema::Object(SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                one_of: Some(
                    types
                        .into_iter()
                        .map(|(name, schema, description)| {
                            (
                                name,
                                ObjectValidation {
                                    required: [name.to_string()].into(),
                                    properties: [(name.to_string(), schema)].into(),
                                    additional_properties: Some(Box::new(Schema::Bool(false))),
                                    ..Default::default()
                                },
                                description,
                            )
                        })
                        .flat_map(|(name, o, dec)| {
                            vec![
                                SchemaObject {
                                    metadata: Some(Box::new(Metadata {
                                        description: Some(dec.to_string()),
                                        ..Default::default()
                                    })),
                                    instance_type: Some(SingleOrVec::Single(Box::new(
                                        InstanceType::Object,
                                    ))),
                                    object: Some(Box::new(o)),
                                    ..Default::default()
                                },
                                SchemaObject {
                                    metadata: Some(Box::new(Metadata {
                                        description: Some(dec.to_string()),
                                        ..Default::default()
                                    })),
                                    instance_type: Some(SingleOrVec::Single(Box::new(
                                        InstanceType::String,
                                    ))),
                                    enum_values: Some(vec![serde_json::Value::String(
                                        name.to_string(),
                                    )]),
                                    ..Default::default()
                                },
                            ]
                        })
                        .map(Schema::Object)
                        .collect::<Vec<_>>(),
                ),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

impl<'de> Deserialize<'de> for Format {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringOrStruct;

        impl<'de> Visitor<'de> for StringOrStruct {
            type Value = Format;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("string or enum")
            }

            fn visit_str<E>(self, value: &str) -> Result<Format, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "json" => Ok(Format::Json(JsonFormat::default())),
                    "text" => Ok(Format::Text(TextFormat::default())),
                    _ => Err(E::custom(format!("unknown log format: {}", value))),
                }
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let key = map.next_key::<String>()?;

                match key.as_deref() {
                    Some("json") => Ok(Format::Json(map.next_value::<JsonFormat>()?)),
                    Some("text") => Ok(Format::Text(map.next_value::<TextFormat>()?)),
                    Some(value) => Err(serde::de::Error::custom(format!(
                        "unknown log format: {}",
                        value
                    ))),
                    _ => Err(serde::de::Error::custom("unknown log format")),
                }
            }
        }

        deserializer.deserialize_any(StringOrStruct)
    }
}

impl Default for Format {
    fn default() -> Self {
        if std::io::stdout().is_terminal() {
            Format::Text(TextFormat::default())
        } else {
            Format::Json(JsonFormat::default())
        }
    }
}

#[derive(Deserialize, JsonSchema, Clone, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case", default)]
pub(crate) struct JsonFormat {
    /// Include the timestamp with the log event. (default: true)
    pub(crate) display_timestamp: bool,
    /// Include the target with the log event. (default: true)
    pub(crate) display_target: bool,
    /// Include the level with the log event. (default: true)
    pub(crate) display_level: bool,
    /// Include the thread_id with the log event.
    pub(crate) display_thread_id: bool,
    /// Include the thread_name with the log event.
    pub(crate) display_thread_name: bool,
    /// Include the filename with the log event.
    pub(crate) display_filename: bool,
    /// Include the line number with the log event.
    pub(crate) display_line_number: bool,
    /// Include the current span in this log event.
    pub(crate) display_current_span: bool,
    /// Include all of the containing span information with the log event. (default: true)
    pub(crate) display_span_list: bool,
    /// Include the resource with the log event. (default: true)
    pub(crate) display_resource: bool,
    /// Include the trace id (if any) with the log event. (default: true)
    pub(crate) display_trace_id: DisplayTraceIdFormat,
    /// Include the span id (if any) with the log event. (default: true)
    pub(crate) display_span_id: bool,
    /// List of span attributes to attach to the json log object
    pub(crate) span_attributes: HashSet<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case", untagged)]
pub(crate) enum DisplayTraceIdFormat {
    // /// Format the Trace ID as a hexadecimal number
    // ///
    // /// (e.g. Trace ID 16 -> 00000000000000000000000000000010)
    // #[default]
    // Hexadecimal,
    // /// Format the Trace ID as a hexadecimal number
    // ///
    // /// (e.g. Trace ID 16 -> 00000000000000000000000000000010)
    // OpenTelemetry,
    // /// Format the Trace ID as a decimal number
    // ///
    // /// (e.g. Trace ID 16 -> 16)
    // Decimal,

    // /// Datadog
    // Datadog,

    // /// UUID format with dashes
    // /// (eg. 67e55044-10b1-426f-9247-bb680e5fe0c8)
    // Uuid,
    TraceIdFormat(TraceIdFormat),
    Bool(bool),
}

impl Default for DisplayTraceIdFormat {
    fn default() -> Self {
        Self::TraceIdFormat(TraceIdFormat::default())
    }
}

impl Default for JsonFormat {
    fn default() -> Self {
        JsonFormat {
            display_timestamp: true,
            display_target: true,
            display_level: true,
            display_thread_id: false,
            display_thread_name: false,
            display_filename: false,
            display_line_number: false,
            display_current_span: false,
            display_span_list: true,
            display_resource: true,
            display_trace_id: DisplayTraceIdFormat::Bool(true),
            display_span_id: true,
            span_attributes: HashSet::new(),
        }
    }
}

#[derive(Deserialize, JsonSchema, Clone, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case", default)]
pub(crate) struct TextFormat {
    /// Process ansi escapes (default: true)
    pub(crate) ansi_escape_codes: bool,
    /// Include the timestamp with the log event. (default: true)
    pub(crate) display_timestamp: bool,
    /// Include the target with the log event.
    pub(crate) display_target: bool,
    /// Include the level with the log event. (default: true)
    pub(crate) display_level: bool,
    /// Include the thread_id with the log event.
    pub(crate) display_thread_id: bool,
    /// Include the thread_name with the log event.
    pub(crate) display_thread_name: bool,
    /// Include the filename with the log event.
    pub(crate) display_filename: bool,
    /// Include the line number with the log event.
    pub(crate) display_line_number: bool,
    /// Include the service namespace with the log event.
    pub(crate) display_service_namespace: bool,
    /// Include the service name with the log event.
    pub(crate) display_service_name: bool,
    /// Include the resource with the log event.
    pub(crate) display_resource: bool,
    /// Include the current span in this log event. (default: true)
    pub(crate) display_current_span: bool,
    /// Include all of the containing span information with the log event. (default: true)
    pub(crate) display_span_list: bool,
    /// Include the trace id (if any) with the log event. (default: false)
    pub(crate) display_trace_id: DisplayTraceIdFormat,
    /// Include the span id (if any) with the log event. (default: false)
    pub(crate) display_span_id: bool,
}

impl Default for TextFormat {
    fn default() -> Self {
        TextFormat {
            ansi_escape_codes: true,
            display_timestamp: true,
            display_target: false,
            display_level: true,
            display_thread_id: false,
            display_thread_name: false,
            display_filename: false,
            display_line_number: false,
            display_service_namespace: false,
            display_service_name: false,
            display_resource: false,
            display_current_span: true,
            display_span_list: true,
            display_trace_id: DisplayTraceIdFormat::Bool(false),
            display_span_id: false,
        }
    }
}

/// The period to rollover the log file.
#[allow(dead_code)]
#[derive(Deserialize, JsonSchema, Clone, Default, Debug)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Rollover {
    /// Roll over every hour.
    Hourly,
    /// Roll over every day.
    Daily,
    #[default]
    /// Never roll over.
    Never,
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::plugins::telemetry::config_new::logging::Format;

    #[test]
    fn format_de() {
        let format = serde_json::from_value::<Format>(json!("text")).unwrap();
        assert_eq!(format, Format::Text(Default::default()));
        let format = serde_json::from_value::<Format>(json!("json")).unwrap();
        assert_eq!(format, Format::Json(Default::default()));
        let format = serde_json::from_value::<Format>(json!({"text":{}})).unwrap();
        assert_eq!(format, Format::Text(Default::default()));
        let format = serde_json::from_value::<Format>(json!({"json":{}})).unwrap();
        assert_eq!(format, Format::Json(Default::default()));
    }
}
