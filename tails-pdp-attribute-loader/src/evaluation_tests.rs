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
    fn current_generation(&self) -> u32 {
        self.generation
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
