//! Serialize auth timestamps with JavaScript's millisecond precision.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Serialize, Serializer};

/// Serialize an auth timestamp as an ISO 8601 string with three fractional digits.
pub fn serialize<S: Serializer>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// Serialize an optional auth timestamp, preserving absent values as null.
pub fn serialize_option<S: Serializer>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value
        .map(|date| date.to_rfc3339_opts(SecondsFormat::Millis, true))
        .serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Dates {
        #[serde(serialize_with = "serialize")]
        required: DateTime<Utc>,
        #[serde(serialize_with = "serialize_option")]
        optional: Option<DateTime<Utc>>,
    }

    #[test]
    fn truncates_submillisecond_precision_without_changing_the_second()
    -> Result<(), Box<dyn std::error::Error>> {
        let date =
            DateTime::parse_from_rfc3339("2026-09-30T10:32:24.133279123Z")?.with_timezone(&Utc);
        let mut dates = Dates {
            required: date,
            optional: Some(date),
        };
        let json = serde_json::to_value(&dates)?;
        assert_eq!(json["required"], "2026-09-30T10:32:24.133Z");
        assert_eq!(json["optional"], json["required"]);
        dates.optional = None;
        assert_eq!(
            serde_json::to_value(dates)?["optional"],
            serde_json::Value::Null
        );
        Ok(())
    }
}
