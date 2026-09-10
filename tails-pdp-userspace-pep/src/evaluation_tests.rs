//! COMP-03: conjunction evaluated through the production lookup loop.
use tails_pdp_common::{AttributeCondition, AttributeNamespace, attribute_hash};

use super::*;

#[test]
fn comp03_all_conditions_required_with_missing_wrong_type_and_wrong_value() {
    let mut conditions = [AttributeCondition::disabled(); MAX_ATTRIBUTE_CONDITIONS];
    let namespaces = [
        AttributeNamespace::System,
        AttributeNamespace::Subject,
        AttributeNamespace::Resource,
        AttributeNamespace::System,
    ];
    let mut entries = Vec::new();
    for (index, namespace) in namespaces.into_iter().enumerate() {
        let name = attribute_hash(&format!("field{index}"));
        conditions[index].namespace = namespace;
        conditions[index].name_hash = name;
        conditions[index].value_number = index as u64 + 1;
        let (primary, secondary) = attribute_object_ids(namespace, 1001, 42, 99);
        entries.push((
            AttributeKey::new(1, namespace, primary, secondary, name),
            AttributeValue::number(index as u64 + 1),
        ));
    }
    let evaluate = |values: &Vec<(AttributeKey, AttributeValue)>| {
        attribute_conditions_match_with_lookup(4, &conditions, 1001, 42, 99, 1, |key| {
            values.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
        })
    };
    assert!(evaluate(&entries));
    for index in 0..4 {
        let mut missing = entries.clone();
        missing.remove(index);
        assert!(!evaluate(&missing), "missing condition {index}");
        for value in [AttributeValue::number(99), AttributeValue::bool(true)] {
            let mut changed = entries.clone();
            changed[index].1 = value;
            assert!(!evaluate(&changed), "wrong condition {index}");
        }
    }
    assert!(!attribute_conditions_match_with_lookup(
        4,
        &conditions,
        1002,
        42,
        99,
        1,
        |key| entries.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
    ));
    assert!(!attribute_conditions_match_with_lookup(
        4,
        &conditions,
        1001,
        42,
        99,
        0,
        |key| entries.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
    ));
}

#[test]
fn failed_close_does_not_prevent_another_target_from_being_attempted() {
    struct Closer(Vec<(u32, i32)>);
    impl FdCloser for Closer {
        fn close(&mut self, pid: u32, fd: i32) -> anyhow::Result<()> {
            self.0.push((pid, fd));
            if pid == 100 {
                anyhow::bail!("injected failure");
            }
            Ok(())
        }
    }
    let mut closer = Closer(Vec::new());
    let mut revoked = HashSet::new();
    for pid in [100, 200] {
        let violation = Violation {
            key: ViolationKey {
                policy_kind: PolicyKind::Static,
                policy_index: 0,
                resource_kind: ResourceKind::File,
                pid,
                fd: 3,
            },
        };
        enforce_violation(&violation, &mut revoked, &mut closer);
    }
    assert_eq!(closer.0, [(100, 3), (200, 3)]);
}
