//! Schreibweisen der Policy-Sprache für die lesende Map-Darstellung.

use tails_pdp_common::{ANY_SUBJECT, Entitlement, StreamAttribute, StreamOperator};

/// Zeigt nur tatsächlich gesetzte UID- und Kommando-Filter an.
pub(crate) fn policy_filters(subject: u32, command: &str) -> String {
    let mut fields = String::new();
    if subject != ANY_SUBJECT {
        fields.push_str(&format!(" subject.uid={subject}"));
    }
    if !command.is_empty() {
        fields.push_str(&format!(" command={command:?}"));
    }
    fields
}

pub(crate) fn operator_symbol(operator: StreamOperator) -> &'static str {
    match operator {
        StreamOperator::LessThan => "<",
        StreamOperator::LessThanOrEqual => "<=",
        StreamOperator::Equal => "==",
        StreamOperator::GreaterThanOrEqual => ">=",
        StreamOperator::GreaterThan => ">",
    }
}

pub(crate) fn entitlement_keyword(entitlement: Entitlement) -> &'static str {
    match entitlement {
        Entitlement::Permit => "permit",
        Entitlement::Deny => "deny",
    }
}

pub(crate) fn time_condition(
    attribute: StreamAttribute,
    modulo: u64,
    operator: StreamOperator,
    value: u64,
) -> String {
    let field = match attribute {
        StreamAttribute::Time => format!("environment.time % {modulo}"),
        StreamAttribute::Hour => "environment.utc.hour".to_owned(),
        StreamAttribute::Minute => "environment.utc.minute".to_owned(),
        StreamAttribute::Second => "environment.utc.second".to_owned(),
    };
    format!("{field} {} {value};", operator_symbol(operator))
}

/// Ergänzt die technische Zeitbedingung nur, wenn sie tatsächlich aktiviert ist.
pub(crate) fn legacy_condition(
    enabled: bool,
    attribute: StreamAttribute,
    modulo: u64,
    operator: StreamOperator,
    value: u64,
) -> String {
    if !enabled {
        String::new()
    } else if attribute == StreamAttribute::Time {
        format!(
            " legacy_condition={attribute:?} % {modulo} {} {value}",
            operator_symbol(operator)
        )
    } else {
        format!(
            " legacy_condition={attribute:?} {} {value}",
            operator_symbol(operator)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_time_conditions_are_omitted_but_enabled_conditions_remain_visible() {
        assert_eq!(
            legacy_condition(
                false,
                StreamAttribute::Time,
                20,
                StreamOperator::GreaterThanOrEqual,
                10
            ),
            ""
        );
        assert_eq!(
            legacy_condition(
                true,
                StreamAttribute::Time,
                20,
                StreamOperator::GreaterThanOrEqual,
                10
            ),
            " legacy_condition=Time % 20 >= 10"
        );
        assert_eq!(
            legacy_condition(true, StreamAttribute::Hour, 0, StreamOperator::Equal, 0),
            " legacy_condition=Hour == 0"
        );
    }

    #[test]
    fn unset_filters_are_omitted_independently() {
        assert_eq!(policy_filters(ANY_SUBJECT, ""), "");
        assert_eq!(policy_filters(ANY_SUBJECT, "cat"), " command=\"cat\"");
        assert_eq!(policy_filters(0, ""), " subject.uid=0");
        assert_eq!(
            policy_filters(1000, "cat"),
            " subject.uid=1000 command=\"cat\""
        );
    }

    #[test]
    fn comparison_operators_use_policy_symbols() {
        for (operator, symbol) in [
            (StreamOperator::LessThan, "<"),
            (StreamOperator::LessThanOrEqual, "<="),
            (StreamOperator::Equal, "=="),
            (StreamOperator::GreaterThanOrEqual, ">="),
            (StreamOperator::GreaterThan, ">"),
        ] {
            assert_eq!(operator_symbol(operator), symbol);
        }
    }

    #[test]
    fn entitlements_use_policy_keywords() {
        assert_eq!(entitlement_keyword(Entitlement::Permit), "permit");
        assert_eq!(entitlement_keyword(Entitlement::Deny), "deny");
    }

    #[test]
    fn time_conditions_use_policy_names_and_semicolons() {
        assert_eq!(
            time_condition(
                StreamAttribute::Time,
                86400,
                StreamOperator::GreaterThanOrEqual,
                64800
            ),
            "environment.time % 86400 >= 64800;"
        );
        assert_eq!(
            time_condition(
                StreamAttribute::Time,
                4_294_967_296,
                StreamOperator::GreaterThanOrEqual,
                1_850_757,
            ),
            "environment.time % 4294967296 >= 1850757;"
        );
        for (attribute, field) in [
            (StreamAttribute::Hour, "hour"),
            (StreamAttribute::Minute, "minute"),
            (StreamAttribute::Second, "second"),
        ] {
            assert_eq!(
                time_condition(attribute, 0, StreamOperator::Equal, 2),
                format!("environment.utc.{field} == 2;")
            );
        }
    }
}
