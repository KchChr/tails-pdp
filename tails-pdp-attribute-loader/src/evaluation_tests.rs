//! COMP-01 and COMP-02. These tests exercise production parsing/commit control flow.
use super::*;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("tails-attributes-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn write(&self, relative: impl AsRef<Path>, text: &str) {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn comp01_reads_namespaces_resource_identity_and_ignores_other_extensions() {
    let fixture = Fixture::new();
    fixture.write("resource.txt", "data");
    fixture.write("system.attributes", "defcon = 2\nready = true\n");
    fixture.write("subjects/1001.attributes", "position = \"engineer\"\n");
    fixture.write("subjects/ignored.tmp", "invalid");
    fixture.write("resources/ignored.txt", "invalid");
    let resource = fixture.0.join("resource.txt");
    let metadata = fs::metadata(&resource).unwrap();
    fixture.write(
        format!("resources{}.attributes", resource.display()),
        "classification = \"internal\"\n",
    );
    let attributes = read_attribute_directory(&fixture.0).unwrap();
    assert_eq!(attributes.len(), 4);
    for (namespace, primary, secondary, name, value) in [
        (
            AttributeNamespace::System,
            0,
            0,
            "defcon",
            AttributeValue::number(2),
        ),
        (
            AttributeNamespace::System,
            0,
            0,
            "ready",
            AttributeValue::bool(true),
        ),
        (
            AttributeNamespace::Subject,
            1001,
            0,
            "position",
            AttributeValue::string(attribute_hash("engineer")),
        ),
        (
            AttributeNamespace::Resource,
            encode_kernel_dev_t(metadata.dev()),
            metadata.ino(),
            "classification",
            AttributeValue::string(attribute_hash("internal")),
        ),
    ] {
        assert!(
            attributes.iter().any(|a| a.namespace == namespace
                && a.object_id_primary == primary
                && a.object_id_secondary == secondary
                && a.name_hash == attribute_hash(name)
                && a.value == value),
            "missing {name}"
        );
    }
}

#[test]
fn comp01_rejects_invalid_recognized_files_and_duplicate_attributes() {
    for (name, value) in [
        ("subjects/not-a-uid.attributes", "x = 1"),
        ("system.attributes", "x = 1\nx = 2"),
        ("system.attributes", "defcon = 9"),
        ("resources/nonexistent-tails-resource.attributes", "x = 1"),
    ] {
        let fixture = Fixture::new();
        fixture.write(name, value);
        assert!(
            read_attribute_directory(&fixture.0).is_err(),
            "accepted {name}: {value}"
        );
    }
}

#[derive(Default)]
struct Store {
    generation: u32,
    entries: Vec<(AttributeKey, AttributeValue)>,
    operations: Vec<&'static str>,
    fail_at: Option<usize>,
    capacity: Option<usize>,
    fail_generation_read: bool,
    fail_inspection: bool,
}
impl Store {
    fn step(&mut self, label: &'static str) -> anyhow::Result<()> {
        self.operations.push(label);
        if self.fail_at == Some(self.operations.len()) {
            bail!("injected {label}");
        }
        Ok(())
    }
}
impl AttributeStore for Store {
    fn current_generation(&self) -> anyhow::Result<u32> {
        if self.fail_generation_read {
            bail!("injected generation read failure");
        }
        Ok(self.generation)
    }
    fn capacity(&self) -> anyhow::Result<usize> {
        Ok(self
            .capacity
            .unwrap_or(tails_pdp_common::ATTRIBUTE_MAP_MAX_ENTRIES as usize))
    }
    fn retained_entries(&self, replaced_bank: u32) -> anyhow::Result<usize> {
        if self.fail_inspection {
            bail!("injected occupancy read failure");
        }
        Ok(self
            .entries
            .iter()
            .filter(|(key, _)| key.bank != replaced_bank)
            .count())
    }
    fn clear_bank(&mut self, bank: u32) -> anyhow::Result<()> {
        self.step("clear")?;
        self.entries.retain(|(k, _)| k.bank != bank);
        Ok(())
    }
    fn insert(&mut self, key: AttributeKey, value: AttributeValue) -> anyhow::Result<()> {
        self.step("insert")?;
        self.entries.push((key, value));
        Ok(())
    }
    fn activate(&mut self, generation: u32) -> anyhow::Result<()> {
        self.step("activate")?;
        self.generation = generation;
        Ok(())
    }
}
fn attributes() -> Vec<ParsedAttribute> {
    [1, 2]
        .map(|id| ParsedAttribute {
            namespace: AttributeNamespace::Subject,
            object_id_primary: id,
            object_id_secondary: 0,
            name_hash: attribute_hash("level"),
            value: AttributeValue::number(id),
        })
        .to_vec()
}

#[test]
fn comp02_clear_partial_write_and_activation_errors_preserve_visible_generation() {
    for fail_at in 1..=4 {
        let mut store = Store::default();
        commit_attributes(&mut store, &attributes()).unwrap();
        let previous = store.entries.clone();
        store.operations.clear();
        store.fail_at = Some(fail_at);
        assert!(commit_attributes(&mut store, &attributes()).is_err());
        assert_eq!(store.generation, 1);
        assert_eq!(
            store
                .entries
                .iter()
                .filter(|(k, _)| k.bank == 1)
                .cloned()
                .collect::<Vec<_>>(),
            previous
        );
        assert_eq!(store.operations.len(), fail_at);
    }
}

#[test]
fn comp02_activation_follows_complete_write_and_clears_stale_entries() {
    let mut store = Store::default();
    assert_eq!(commit_attributes(&mut store, &attributes()).unwrap(), 1);
    assert_eq!(store.operations, ["clear", "insert", "insert", "activate"]);
    commit_attributes(&mut store, &attributes()).unwrap();
    commit_attributes(&mut store, &attributes()[..1]).unwrap();
    assert_eq!(store.entries.iter().filter(|(k, _)| k.bank == 1).count(), 1);
    assert_eq!(store.entries.iter().filter(|(k, _)| k.bank == 0).count(), 2);
    store.generation = u32::MAX;
    assert_eq!(commit_attributes(&mut store, &[]).unwrap(), 0);
    assert!(store.entries.iter().all(|(k, _)| k.bank != 0));
}

#[test]
fn capacity_rejection_happens_before_any_map_mutation() {
    let mut store = Store {
        capacity: Some(4),
        ..Store::default()
    };
    commit_attributes(&mut store, &attributes()).unwrap();
    commit_attributes(&mut store, &attributes()).unwrap();
    let previous = store.entries.clone();
    store.operations.clear();
    let mut oversized = attributes();
    let mut third = oversized[0].clone();
    third.object_id_primary = 3;
    oversized.push(third);
    let error = commit_attributes(&mut store, &oversized).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("retained=2 requested=3 capacity=4")
    );
    assert!(store.operations.is_empty());
    assert_eq!(store.entries, previous);
    assert_eq!(store.generation, 2);
}

#[test]
fn capacity_accounts_for_retained_entries_not_a_fixed_half_map_limit() {
    let mut store = Store {
        capacity: Some(4),
        ..Store::default()
    };
    let mut three = attributes();
    let mut third = three[0].clone();
    third.object_id_primary = 3;
    three.push(third);
    // Three entries are valid with an empty active bank, despite a capacity of four.
    commit_attributes(&mut store, &three).unwrap();
    commit_attributes(&mut store, &three[..1]).unwrap();
    // The three stale entries in the replaced bank must not be counted twice.
    commit_attributes(&mut store, &three).unwrap();
    assert_eq!(store.generation, 3);
    assert_eq!(store.entries.len(), 4);
}

#[test]
fn generation_and_occupancy_read_errors_never_modify_either_bank() {
    for fail_generation_read in [true, false] {
        let mut store = Store::default();
        commit_attributes(&mut store, &attributes()).unwrap();
        let previous = store.entries.clone();
        store.operations.clear();
        store.fail_generation_read = fail_generation_read;
        store.fail_inspection = !fail_generation_read;
        assert!(commit_attributes(&mut store, &attributes()).is_err());
        assert!(store.operations.is_empty());
        assert_eq!(store.generation, 1);
        assert_eq!(store.entries, previous);
    }
}

#[test]
fn update_commit_errors_preserve_state_and_allow_a_later_successful_update() {
    for fail_at in 1..=4 {
        let fixture = Fixture::new();
        fixture.write("system.attributes", "x = 1\ny = 2\n");
        let initial = read_attribute_directory(&fixture.0).unwrap();
        let mut store = Store::default();
        commit_attributes(&mut store, &initial).unwrap();
        let previous = store.entries.clone();
        let mut last_applied = Some(initial.clone());
        let (sender, mut receiver) = mpsc::channel(1);
        fixture.write("system.attributes", "x = 3\ny = 4\n");
        store.operations.clear();
        store.fail_at = Some(fail_at);
        // Clearing, partial insertion, and activation errors must not end the updater.
        apply_attribute_directory(&fixture.0, &mut store, &mut last_applied, &sender).unwrap();
        assert_eq!(store.generation, 1);
        assert!(last_applied.as_ref() == Some(&initial));
        assert_eq!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        assert_eq!(
            store
                .entries
                .iter()
                .filter(|(k, _)| k.bank == 1)
                .cloned()
                .collect::<Vec<_>>(),
            previous
        );

        store.fail_at = None;
        // A later event for the same failed contents may retry; last_applied wasn't advanced.
        apply_attribute_directory(&fixture.0, &mut store, &mut last_applied, &sender).unwrap();
        assert_eq!(store.generation, 2);
        assert_eq!(store.entries.iter().filter(|(k, _)| k.bank == 0).count(), 2);
        assert!(last_applied == Some(read_attribute_directory(&fixture.0).unwrap()));
        assert_eq!(
            receiver.try_recv().unwrap(),
            EnforcementTrigger::AttributeGenerationActivated { generation: 2 }
        );
    }
}

#[test]
fn update_capacity_and_generation_read_errors_send_no_trigger_and_recover() {
    for generation_read_error in [false, true] {
        let fixture = Fixture::new();
        fixture.write("system.attributes", "x = 1\n");
        let initial = read_attribute_directory(&fixture.0).unwrap();
        let mut store = Store {
            capacity: Some(2),
            ..Store::default()
        };
        commit_attributes(&mut store, &initial).unwrap();
        let previous = store.entries.clone();
        let mut last_applied = Some(initial.clone());
        let (sender, mut receiver) = mpsc::channel(1);
        store.fail_generation_read = generation_read_error;
        fixture.write("system.attributes", "x = 2\ny = 3\n");
        store.operations.clear();
        apply_attribute_directory(&fixture.0, &mut store, &mut last_applied, &sender).unwrap();
        assert_eq!(store.generation, 1);
        assert_eq!(store.entries, previous);
        assert!(store.operations.is_empty());
        assert!(last_applied.as_ref() == Some(&initial));
        assert_eq!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        store.fail_generation_read = false;
        fixture.write("system.attributes", "x = 4\n");
        apply_attribute_directory(&fixture.0, &mut store, &mut last_applied, &sender).unwrap();
        assert_eq!(store.generation, 2);
        assert_eq!(
            receiver.try_recv().unwrap(),
            EnforcementTrigger::AttributeGenerationActivated { generation: 2 }
        );
    }
}

#[test]
fn closed_enforcement_channel_remains_fatal_after_successful_activation() {
    let fixture = Fixture::new();
    fixture.write("system.attributes", "x = 1\n");
    let mut store = Store::default();
    let mut last_applied = None;
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let error =
        apply_attribute_directory(&fixture.0, &mut store, &mut last_applied, &sender).unwrap_err();
    assert!(error.to_string().contains("trigger channel is closed"));
    assert_eq!(store.generation, 1);
    assert!(last_applied.is_some());
}

#[test]
fn initial_commit_failure_is_still_reported_to_the_caller() {
    let mut store = Store {
        capacity: Some(1),
        ..Store::default()
    };
    assert!(commit_attributes(&mut store, &attributes()).is_err());
    assert_eq!(store.generation, 0);
    assert!(store.entries.is_empty());
    assert!(store.operations.is_empty());
}
