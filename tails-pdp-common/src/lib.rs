//! Gemeinsame Datenrepräsentation und reine Policylogik für Kernel und Userspace.
//!
//! Die Crate ist `no_std`; das Feature `user` ergänzt Aya-Map-Typen und die
//! Linux-/Unix-Auflösung von Dateiidentitäten. Sie definiert die binäre Map-Schnittstelle:
//! Feldreihenfolge, `repr(C)`-Padding und Enumwerte müssen auf beiden Seiten übereinstimmen.
//! Statische Regeln kombinieren UID, Command und Gerät/Inode; Stream-Regeln ergänzen
//! Zeitbedingungen und strukturierte Attributbedingungen. Deny hat Vorrang vor Permit.
//!
//! # Beispiel
//!
//! ```
//! use tails_pdp_common::{policy_bank_offset, DecisionState, Entitlement};
//! assert_eq!(policy_bank_offset(1), 16);
//! let mut decision = DecisionState::empty_for_generation(1);
//! decision.record(Entitlement::Permit);
//! decision.record(Entitlement::Deny);
//! assert_eq!(decision.lsm_return_value(), -1);
//! ```
//!
//! # Grenzen
//!
//! Dateiidentitäten sind keine dauerhafte Bindung an einen Pfadnamen. Stringattribute
//! werden als nicht kryptografische Hashwerte verglichen. Fehlende oder unpassende
//! Bedingungen liefern keine passende Policy; dies ist von einer Deny-Entscheidung zu trennen.

#![no_std]

#[cfg(any(feature = "user", test))]
extern crate std;

pub mod kernel_logging;

/// Größe des festen Linux-Commandfelds in Byte einschließlich Nullbyte.
pub const COMMAND_LEN: usize = 16;
/// Linux task comm reserves one byte of its fixed-size field for the trailing NUL.
pub const COMMAND_MAX_BYTES: usize = COMMAND_LEN - 1;
/// Maximale Bytezahl der gespeicherten Ressourcenpfaddarstellung.
pub const RESOURCE_LEN: usize = 64;
/// UID-Wildcard; dieser Wert passt auf jeden anfragenden Benutzer.
pub const ANY_SUBJECT: u32 = u32::MAX;

/// Maximalzahl aktiver Regeln je Policyart und Generation.
pub const MAX_POLICIES: u32 = 16;
/// Anzahl abwechselnd aktiver und beschreibbarer Policybänke.
pub const POLICY_BANK_COUNT: u32 = 2;
/// Anzahl Map-Slots je Policybank.
pub const POLICY_BANK_SIZE: u32 = MAX_POLICIES;
/// Gesamte Arraykapazität einschließlich beider Policybänke.
pub const POLICY_MAP_MAX_ENTRIES: u32 = POLICY_BANK_COUNT * POLICY_BANK_SIZE;
/// Kapazität der Map mit der aktiven Policygeneration.
pub const POLICY_GENERATION_MAX_ENTRIES: u32 = 1;
/// Anzahl generationenabhängiger Attributbänke.
pub const ATTRIBUTE_BANK_COUNT: u32 = 2;
/// Gesamtkapazität der Attribut-HashMap einschließlich beider Bänke.
pub const ATTRIBUTE_MAP_MAX_ENTRIES: u32 = 1024;
/// Kapazität der Map mit der aktiven Attributgeneration.
pub const ATTRIBUTE_GENERATION_MAX_ENTRIES: u32 = 1;
/// Maximalzahl strukturierter Bedingungen je Stream-Policy.
pub const MAX_ATTRIBUTE_CONDITIONS: usize = 4;
/// Kleinster zulässiger Wert von `system.defcon`.
pub const DEFCON_MIN_LEVEL: u32 = 1;
/// Größter zulässiger Wert von `system.defcon`.
pub const DEFCON_MAX_LEVEL: u32 = 5;
/// Initialer DEFCON-Wert bei fehlender Systemattributdatei.
pub const DEFAULT_DEFCON_LEVEL: u32 = DEFCON_MAX_LEVEL;

/// Linux LSM return value used when this policy engine permits an operation.
pub const LSM_ALLOW: i32 = 0;
/// Linux LSM return value used when this policy engine denies an operation (`-EPERM`).
pub const LSM_DENY: i32 = -1;

/// Arraykapazität für statische File-Open-Regeln, einschließlich inaktiver Bank.
pub const FILE_OPEN_STATIC_POLICY_MAX_ENTRIES: u32 = POLICY_MAP_MAX_ENTRIES;
/// Arraykapazität für Stream-File-Open-Regeln, einschließlich inaktiver Bank.
pub const FILE_OPEN_STREAM_POLICY_MAX_ENTRIES: u32 = POLICY_MAP_MAX_ENTRIES;

/// Startslot der durch `generation` gewählten Policybank.
///
/// Gerade Generationen beginnen bei 0, ungerade bei [`POLICY_BANK_SIZE`].
pub const fn policy_bank_offset(generation: u32) -> u32 {
    (generation % POLICY_BANK_COUNT) * POLICY_BANK_SIZE
}

/// Bankkennung der aktiven Attributgeneration (Generation modulo Bankanzahl).
pub const fn attribute_bank(generation: u32) -> u32 {
    generation % ATTRIBUTE_BANK_COUNT
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Ergebnis einer passenden Policy; [`DecisionState`] kombiniert mehrere Ergebnisse.
pub enum Entitlement {
    /// Erlaubendes Entitlement; ein anderes passendes Deny hat weiterhin Vorrang.
    Permit = 0,
    /// Ablehnendes Entitlement.
    Deny = 1,
}

impl Entitlement {
    /// Kodiert das Entitlement als Zustandsflag: Permit ist 0, Deny ist 1.
    ///
    /// Dies ist kein Linux-Rückgabewert; dafür dient [`DecisionState::lsm_return_value`].
    pub const fn decision(self) -> i32 {
        match self {
            Self::Permit => 0,
            Self::Deny => 1,
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Binär kodierte Aktion; nur `FileOpen = 1` ist implementiert.
pub enum PolicyAction {
    /// Dateiöffnung, mit unveränderlicher ABI-Kennung 1.
    FileOpen = 1,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Zeitkomponente einer Stream-Bedingung; UTC-Werte stammen aus [`PolicyTime`].
pub enum StreamAttribute {
    /// Unix-Sekunden, optional modulo Divisor.
    Time = 1,
    /// UTC-Stunde.
    Hour = 2,
    /// UTC-Minute.
    Minute = 3,
    /// UTC-Sekunde.
    Second = 4,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Vergleichsoperator für numerische Bedingungen; Strings unterstützen nur Gleichheit.
pub enum StreamOperator {
    /// Linke Seite ist kleiner.
    LessThan = 1,
    /// Linke Seite ist kleiner oder gleich.
    LessThanOrEqual = 2,
    /// Beide Seiten sind gleich.
    Equal = 3,
    /// Linke Seite ist größer oder gleich.
    GreaterThanOrEqual = 4,
    /// Linke Seite ist größer.
    GreaterThan = 5,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Geltungsbereich eines Attributs; bestimmt die Objektidentität des Map-Schlüssels.
pub enum AttributeNamespace {
    /// Globale Attribute ohne requestabhängiges Objekt.
    System = 1,
    /// Attribute der anfragenden UID.
    Subject = 2,
    /// Attribute der Dateiidentität.
    Resource = 3,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Typkennung für Map-Werte und Policybedingungen; Typkonflikte passen nicht.
pub enum AttributeValueKind {
    /// Vorzeichenloser numerischer Wert.
    Number = 1,
    /// Stringhash.
    String = 2,
    /// Boolescher Wert, kodiert als 0/1.
    Bool = 3,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Zwei deterministische 64-Bit-Hashkomponenten für Namen und Stringwerte.
///
/// Dies ist kein kryptografischer Hash und keine Garantie gegen Kollisionen.
pub struct AttributeHash {
    /// Erste 64-Bit-Hashkomponente.
    pub low: u64,
    /// Zweite 64-Bit-Hashkomponente.
    pub high: u64,
}

impl AttributeHash {
    /// Erzeugt einen Nullhash für unbenutzte oder deaktivierte Felder.
    pub const fn zero() -> Self {
        Self { low: 0, high: 0 }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Binärer HashMap-Schlüssel aus Bank, Namensraum, Objektidentität und Attributname.
///
/// Mit [`attribute_object_ids`] wird die passende Objektidentität gebildet.
pub struct AttributeKey {
    /// Generationengewählte Bankkennung.
    pub bank: u32,
    /// Numerische Kennung des Attributnamensraums.
    pub namespace: u32,
    /// Erste Objektkennung: 0, UID oder Kernel-Gerätenummer, je nach Namensraum.
    pub object_id_primary: u64,
    /// Zweite Objektkennung: Ressourcen-Inode oder 0.
    pub object_id_secondary: u64,
    /// Hash des Attributnamens ohne Namensraumprefix.
    pub name_hash: AttributeHash,
}

impl AttributeKey {
    /// Bildet einen Map-Schlüssel. `bank` wählt die Generation; `namespace` und
    /// beide Objektkennungen müssen zu [`attribute_object_ids`] passen.
    pub const fn new(
        bank: u32,
        namespace: AttributeNamespace,
        object_id_primary: u64,
        object_id_secondary: u64,
        name_hash: AttributeHash,
    ) -> Self {
        Self {
            bank,
            namespace: namespace as u32,
            object_id_primary,
            object_id_secondary,
            name_hash,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Binärer Wert: Zahl/Bool im Zahlenfeld oder Stringhash, ausgewählt durch `kind`.
pub struct AttributeValue {
    /// Typkennung des kodierten Werts.
    pub kind: AttributeValueKind,
    /// Explizites ABI-Padding; Konstruktoren initialisieren es mit Nullen.
    pub _pad: [u8; 7],
    /// Zahlenwert bzw. Bool-Kodierung 0/1; bei Stringwerten unbenutzt.
    pub number: u64,
    /// Hash eines Stringwerts; bei Zahlen und Bool unbenutzt.
    pub hash: AttributeHash,
}

impl AttributeValue {
    /// Kodiert eine vorzeichenlose Zahl; das unbenutzte Hashfeld bleibt null.
    pub const fn number(value: u64) -> Self {
        Self {
            kind: AttributeValueKind::Number,
            _pad: [0; 7],
            number: value,
            hash: AttributeHash::zero(),
        }
    }

    /// Kodiert `false` als 0 und `true` als 1 mit Bool-Typkennung.
    pub const fn bool(value: bool) -> Self {
        Self {
            kind: AttributeValueKind::Bool,
            _pad: [0; 7],
            number: value as u64,
            hash: AttributeHash::zero(),
        }
    }

    /// Kodiert einen zuvor mit [`attribute_hash`] gebildeten Stringhash.
    ///
    /// Der Originalstring ist nicht Bestandteil der Kernelmap.
    pub const fn string(hash: AttributeHash) -> Self {
        Self {
            kind: AttributeValueKind::String,
            _pad: [0; 7],
            number: 0,
            hash,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Binäre strukturierte Policybedingung; nur Slots unterhalb des Bedingungszählers sind aktiv.
pub struct AttributeCondition {
    /// Numerische Kennung des Attributnamensraums.
    pub namespace: AttributeNamespace,
    /// Anzuwendender Vergleichsoperator.
    pub operator: StreamOperator,
    /// Erwarteter Typ des Attributwerts.
    pub value_kind: AttributeValueKind,
    /// Explizites ABI-Padding; Konstruktoren initialisieren es mit Nullen.
    pub _pad: [u8; 5],
    /// Hash des Attributnamens ohne Namensraumprefix.
    pub name_hash: AttributeHash,
    /// Numerische rechte Vergleichsseite einschließlich Bool-Kodierung.
    pub value_number: u64,
    /// Stringhash der rechten Vergleichsseite.
    pub value_hash: AttributeHash,
}

impl AttributeCondition {
    /// Nullinitialisiert einen unbenutzten Bedingungsslot.
    ///
    /// Ob ein Slot ausgewertet wird, bestimmt der Bedingungszähler der Policy.
    pub const fn disabled() -> Self {
        Self {
            namespace: AttributeNamespace::System,
            operator: StreamOperator::Equal,
            value_kind: AttributeValueKind::Number,
            _pad: [0; 5],
            name_hash: AttributeHash::zero(),
            value_number: 0,
            value_hash: AttributeHash::zero(),
        }
    }
}

/// Hasht die UTF-8-Bytes eines Attributnamens oder Stringwerts identisch auf beiden Seiten.
pub fn attribute_hash(value: &str) -> AttributeHash {
    attribute_hash_bytes(value.as_bytes())
}

/// Bildet zwei deterministische, FNV-basierte 64-Bit-Komponenten mit umschlagender Arithmetik.
///
/// `bytes` wird unverändert verarbeitet; Normalisierung und kryptografische
/// Kollisionsfreiheit werden nicht zugesichert.
pub fn attribute_hash_bytes(bytes: &[u8]) -> AttributeHash {
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut low = 0xcbf2_9ce4_8422_2325u64;
    let mut high = 0x6c62_272e_07bb_0142u64;
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index] as u64;
        low ^= byte;
        low = low.wrapping_mul(FNV_PRIME);
        high ^= byte.rotate_left((index % 8) as u32);
        high = high.wrapping_mul(FNV_PRIME);
        index += 1;
    }

    AttributeHash { low, high }
}

/// Time representation used by stream-policy evaluation in both eBPF and userspace.
///
/// The only external input is a Unix timestamp. UTC components are derived here so both
/// enforcement paths use identical conversion logic.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PolicyTime {
    /// Sekunden seit Unix-Epoch als gemeinsame Zeitbasis.
    pub unix_seconds: u64,
    /// UTC-Stunde von 0 bis 23.
    pub hour: u8,
    /// UTC-Minute von 0 bis 59.
    pub minute: u8,
    /// UTC-Sekunde von 0 bis 59.
    pub second: u8,
}

impl PolicyTime {
    /// Leitet UTC-Stunde, -Minute und -Sekunde aus Unix-Sekunden ab, ohne lokale Zeitzone.
    pub const fn from_unix_seconds(unix_seconds: u64) -> Self {
        Self {
            unix_seconds,
            hour: ((unix_seconds / 3_600) % 24) as u8,
            minute: ((unix_seconds / 60) % 60) as u8,
            second: (unix_seconds % 60) as u8,
        }
    }
}

fn fixed_name<const N: usize>(name: &str) -> [u8; N] {
    let mut value = [0; N];
    let bytes = name.as_bytes();
    let mut index = 0;

    while index < bytes.len() && index < N {
        value[index] = bytes[index];
        index += 1;
    }

    value
}

/// Kopiert UTF-8-Bytes in das feste Commandfeld und füllt den Rest mit Nullen.
///
/// Überlange Eingaben werden byteweise abgeschnitten, nicht validiert. Der Parser
/// begrenzt Commands deshalb auf [`COMMAND_MAX_BYTES`]; dieser Helfer allein tut das nicht.
pub fn command_name(name: &str) -> [u8; COMMAND_LEN] {
    fixed_name(name)
}

/// Kopiert einen Pfad byteweise in das feste Ressourcenfeld; Überlänge wird abgeschnitten.
///
/// Die Policyvalidierung muss die Länge vor diesem Aufruf prüfen.
pub fn resource_name(name: &str) -> [u8; RESOURCE_LEN] {
    fixed_name(name)
}

#[cfg(feature = "user")]
fn fixed_string_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
}

#[cfg(feature = "user")]
/// Wandelt ein Userspace-`dev_t` in die im Kernel verglichene Major-/Minor-Kodierung um.
pub fn encode_kernel_dev_t(device: u64) -> u64 {
    let major = libc::major(device) as u64;
    let minor = libc::minor(device) as u64;
    (major << 20) | minor
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Binäre statische File-Open-Policy für UID, Command und Dateiidentität.
///
/// `new` erzeugt eine ungelöste Pfadangabe. Vor Aktivierung muss ein nicht leerer
/// Ressourcenpfad mit der Userspace-Methode `resolve_resource_identity` aufgelöst werden.
/// Ein nicht aufgelöster Pfad besitzt sonst die Identitäts-Wildcard `(0, 0)`.
pub struct FileOpenStaticPolicy {
    /// Entitlement bei vollständig passender Policy.
    pub entitlement: Entitlement,
    /// Binäre Aktionskennung; derzeit ausschließlich FileOpen.
    pub action: PolicyAction,
    /// 0 deaktiviert den Slot; ein Wert ungleich 0 aktiviert ihn.
    pub enabled: u8,
    /// Explizites ABI-Padding; Konstruktoren initialisieren es mit Nullen.
    pub _pad: u8,
    /// UID-Filter; [`ANY_SUBJECT`] passt auf jeden Benutzer.
    pub subject: u32,
    /// Kernel-Commandbytes; ein führendes Nullbyte bezeichnet bei Policies die Wildcard.
    pub command: [u8; COMMAND_LEN],
    /// Gespeicherte Pfadbytes für Userspace-Auflösung; die Evaluierung nutzt Gerät/Inode.
    pub resource: [u8; RESOURCE_LEN],
    /// Kernel-kodierte Gerätenummer der Ressource.
    pub resource_device: u64,
    /// Inode der Ressource.
    pub resource_inode: u64,
}

impl FileOpenStaticPolicy {
    /// Erzeugt einen deaktivierten Map-Slot, der bei der Evaluierung nicht passt.
    pub const fn disabled() -> Self {
        Self {
            entitlement: Entitlement::Permit,
            action: PolicyAction::FileOpen,
            enabled: 0,
            _pad: 0,
            subject: ANY_SUBJECT,
            command: [0; COMMAND_LEN],
            resource: [0; RESOURCE_LEN],
            resource_device: 0,
            resource_inode: 0,
        }
    }

    /// Erzeugt eine aktivierte statische Regel. `subject` kann [`ANY_SUBJECT`] sein;
    /// leere Commands und leere Ressourcen sind Wildcards. Längen werden hier nicht geprüft.
    /// Die Dateiidentität eines nicht leeren Pfads muss vor dem Schreiben aufgelöst werden.
    pub fn new(entitlement: Entitlement, subject: u32, command: &str, resource: &str) -> Self {
        Self {
            entitlement,
            action: PolicyAction::FileOpen,
            enabled: 1,
            _pad: 0,
            subject,
            command: command_name(command),
            resource: resource_name(resource),
            resource_device: 0,
            resource_inode: 0,
        }
    }

    /// Prüft, ob Gerät und Inode beide null sind und damit jede Ressource passen kann.
    pub const fn matches_any_resource(&self) -> bool {
        self.resource_device == 0 && self.resource_inode == 0
    }

    #[cfg(feature = "user")]
    /// Löst den gespeicherten Pfad mit Dateimetadaten in Kernel-Gerätenummer und Inode auf.
    ///
    /// Ein leerer Pfad erhält die Wildcard `(0, 0)`.
    ///
    /// # Errors
    ///
    /// Liefert einen I/O-Fehler bei ungültigem UTF-8, fehlender Datei oder nicht lesbaren
    /// Metadaten. Eine spätere Dateiersetzung wird nicht automatisch nachverfolgt.
    pub fn resolve_resource_identity(mut self) -> std::io::Result<Self> {
        use std::{fs, io, os::unix::fs::MetadataExt, str};

        let len = fixed_string_len(&self.resource);
        if len == 0 {
            self.resource_device = 0;
            self.resource_inode = 0;
            return Ok(self);
        }

        let path = str::from_utf8(&self.resource[..len]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                std::format!("resource path is not valid UTF-8: {error}"),
            )
        })?;
        let metadata = fs::metadata(path)?;
        self.resource_device = encode_kernel_dev_t(metadata.dev());
        self.resource_inode = metadata.ino();
        Ok(self)
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Binäre File-Open-Policy mit statischen Filtern, optionaler Zeitbedingung und Attributbedingungen.
///
/// Höchstens vier Attributbedingungen und eine Zeitbedingung werden ausgewertet.
/// Die Ressourcenidentität muss vor Aktivierung wie bei [`FileOpenStaticPolicy`] aufgelöst sein.
pub struct FileOpenStreamPolicy {
    /// Entitlement bei vollständig passender Policy.
    pub entitlement: Entitlement,
    /// Binäre Aktionskennung; derzeit ausschließlich FileOpen.
    pub action: PolicyAction,
    /// Für die optionale Zeitbedingung ausgewählte Zeitkomponente.
    pub attribute: StreamAttribute,
    /// Anzuwendender Vergleichsoperator.
    pub operator: StreamOperator,
    /// 0 deaktiviert den Slot; ein Wert ungleich 0 aktiviert ihn.
    pub enabled: u8,
    /// 0 überspringt die Zeitbedingung; ungleich 0 wertet sie aus.
    pub stream_condition_enabled: u8,
    /// Anzahl aktiver Slots in `attribute_conditions`, höchstens [`MAX_ATTRIBUTE_CONDITIONS`].
    pub attribute_condition_count: u8,
    /// Explizites ABI-Padding; Konstruktoren initialisieren es mit Nullen.
    pub _pad: u8,
    /// UID-Filter; [`ANY_SUBJECT`] passt auf jeden Benutzer.
    pub subject: u32,
    /// Kernel-Commandbytes; ein führendes Nullbyte bezeichnet bei Policies die Wildcard.
    pub command: [u8; COMMAND_LEN],
    /// Gespeicherte Pfadbytes für Userspace-Auflösung; die Evaluierung nutzt Gerät/Inode.
    pub resource: [u8; RESOURCE_LEN],
    /// Kernel-kodierte Gerätenummer der Ressource.
    pub resource_device: u64,
    /// Inode der Ressource.
    pub resource_inode: u64,
    /// Divisor der Unixzeit-Bedingung; bei UTC-Komponenten unbenutzt.
    pub modulo: u64,
    /// Rechte Vergleichsseite der Zeitbedingung.
    pub value: u64,
    /// Feste Bedingungsslots; der Zähler bestimmt die ausgewertete Teilmenge.
    pub attribute_conditions: [AttributeCondition; MAX_ATTRIBUTE_CONDITIONS],
}

impl FileOpenStreamPolicy {
    /// Erzeugt einen deaktivierten Stream-Map-Slot mit unbenutzten Bedingungen.
    pub const fn disabled() -> Self {
        Self {
            entitlement: Entitlement::Permit,
            action: PolicyAction::FileOpen,
            attribute: StreamAttribute::Time,
            operator: StreamOperator::LessThan,
            enabled: 0,
            stream_condition_enabled: 0,
            attribute_condition_count: 0,
            _pad: 0,
            subject: ANY_SUBJECT,
            command: [0; COMMAND_LEN],
            resource: [0; RESOURCE_LEN],
            resource_device: 0,
            resource_inode: 0,
            modulo: 0,
            value: 0,
            attribute_conditions: [AttributeCondition::disabled(); MAX_ATTRIBUTE_CONDITIONS],
        }
    }

    /// Erzeugt eine aktive Regel ohne Zeitbedingung und mit null aktiven Attributbedingungen.
    ///
    /// Der Loader ergänzt Attributbedingungen und löst den Ressourcenpfad vor Aktivierung auf.
    /// UID-/Command-/Ressourcen-Wildcards entsprechen [`FileOpenStaticPolicy::new`].
    pub fn stream(entitlement: Entitlement, subject: u32, command: &str, resource: &str) -> Self {
        Self {
            entitlement,
            action: PolicyAction::FileOpen,
            attribute: StreamAttribute::Time,
            operator: StreamOperator::LessThan,
            enabled: 1,
            stream_condition_enabled: 0,
            attribute_condition_count: 0,
            _pad: 0,
            subject,
            command: command_name(command),
            resource: resource_name(resource),
            resource_device: 0,
            resource_inode: 0,
            modulo: 0,
            value: 0,
            attribute_conditions: [AttributeCondition::disabled(); MAX_ATTRIBUTE_CONDITIONS],
        }
    }

    /// Erzeugt eine aktive Zeitregel mit `unix_seconds % modulo` als linker Vergleichsseite.
    ///
    /// `operator` vergleicht den Rest mit `value`. Bei `modulo == 0` passt die Zeitbedingung
    /// nicht. `subject`, `command` und `resource` sind zusätzliche statische Filter;
    /// Längenprüfung und Ressourcenauflösung sind Aufgaben des Loaders.
    pub fn time(
        entitlement: Entitlement,
        subject: u32,
        command: &str,
        resource: &str,
        operator: StreamOperator,
        modulo: u64,
        value: u64,
    ) -> Self {
        Self {
            entitlement,
            action: PolicyAction::FileOpen,
            attribute: StreamAttribute::Time,
            operator,
            enabled: 1,
            stream_condition_enabled: 1,
            attribute_condition_count: 0,
            _pad: 0,
            subject,
            command: command_name(command),
            resource: resource_name(resource),
            resource_device: 0,
            resource_inode: 0,
            modulo,
            value,
            attribute_conditions: [AttributeCondition::disabled(); MAX_ATTRIBUTE_CONDITIONS],
        }
    }

    /// Prüft die Identitäts-Wildcard `(Gerät, Inode) == (0, 0)`.
    pub const fn matches_any_resource(&self) -> bool {
        self.resource_device == 0 && self.resource_inode == 0
    }

    #[cfg(feature = "user")]
    /// Löst den Ressourcenpfad wie bei der statischen Policy in Gerät und Inode auf.
    ///
    /// # Errors
    ///
    /// Fehlerhafte UTF-8-Pfade und Metadaten-/Dateizugriffsfehler werden zurückgegeben.
    /// Ein leerer Pfad wird als Wildcard behandelt.
    pub fn resolve_resource_identity(mut self) -> std::io::Result<Self> {
        use std::{fs, io, os::unix::fs::MetadataExt, str};

        let len = fixed_string_len(&self.resource);
        if len == 0 {
            self.resource_device = 0;
            self.resource_inode = 0;
            return Ok(self);
        }

        let path = str::from_utf8(&self.resource[..len]).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                std::format!("resource path is not valid UTF-8: {error}"),
            )
        })?;
        let metadata = fs::metadata(path)?;
        self.resource_device = encode_kernel_dev_t(metadata.dev());
        self.resource_inode = metadata.ino();
        Ok(self)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Gesammelte Entitlements eines Requests und dessen Policygeneration.
///
/// Deny-Overrides erlaubt einen Request nur, wenn kein passendes Deny aufgezeichnet ist.
pub struct DecisionState {
    /// Flag für mindestens ein passendes Deny.
    pub deny: u32,
    /// Flag für mindestens ein passendes Permit.
    pub permit: u32,
    /// Policygeneration dieser Auswertung; kein Entitlement.
    pub generation: u32,
}

impl DecisionState {
    /// Erzeugt einen leeren Entscheidungszustand für Generation 0.
    pub const fn empty() -> Self {
        Self {
            deny: 0,
            permit: 0,
            generation: 0,
        }
    }

    /// Beginnt eine Auswertung ohne passende Entitlements für die übergebene Generation.
    pub const fn empty_for_generation(generation: u32) -> Self {
        Self {
            deny: 0,
            permit: 0,
            generation,
        }
    }

    /// Merkt ein passendes Entitlement, ohne bereits gesetzte Permit-/Deny-Flags zu löschen.
    pub fn record(&mut self, entitlement: Entitlement) {
        match entitlement {
            Entitlement::Deny => self.deny = 1,
            Entitlement::Permit => self.permit = 1,
        }
    }

    /// Vereinigt Entitlement-Flags mit `other`; die eigene Generation bleibt unverändert.
    ///
    /// Der Aufrufer muss bei Bedarf die Generationszuordnung selbst sicherstellen.
    pub fn merge(&mut self, other: Self) {
        if other.deny != 0 {
            self.deny = 1;
        }
        if other.permit != 0 {
            self.permit = 1;
        }
    }

    /// Applies the project's deny-overrides combining rule to an LSM return value.
    pub const fn lsm_return_value(self) -> i32 {
        if self.deny != 0 { LSM_DENY } else { LSM_ALLOW }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Ausgewählte Requestdaten für dieselbe Auswertung im Kernel und im Userspace.
pub struct FileOpenRequest {
    /// UID-Filter; [`ANY_SUBJECT`] passt auf jeden Benutzer.
    pub subject: u32,
    /// Kernel-Commandbytes; ein führendes Nullbyte bezeichnet bei Policies die Wildcard.
    pub command: [u8; COMMAND_LEN],
    /// Kernel-kodierte Gerätenummer der Ressource.
    pub resource_device: u64,
    /// Inode der Ressource.
    pub resource_inode: u64,
}

/// Vergleicht die vorzeichenlosen Werte `left` und `right` gemäß `operator`.
pub fn matches_stream_operator(operator: StreamOperator, left: u64, right: u64) -> bool {
    match operator {
        StreamOperator::LessThan => left < right,
        StreamOperator::LessThanOrEqual => left <= right,
        StreamOperator::Equal => left == right,
        StreamOperator::GreaterThanOrEqual => left >= right,
        StreamOperator::GreaterThan => left > right,
    }
}

fn matches_subject(policy_subject: u32, current_subject: u32) -> bool {
    policy_subject == ANY_SUBJECT || policy_subject == current_subject
}

fn matches_bytes<const N: usize>(policy_value: &[u8; N], current_value: &[u8; N]) -> bool {
    policy_value[0] == 0 || policy_value == current_value
}

fn matches_file_resource(
    policy_device: u64,
    policy_inode: u64,
    resource_device: u64,
    resource_inode: u64,
) -> bool {
    (policy_device == 0 && policy_inode == 0)
        || (policy_device == resource_device && policy_inode == resource_inode)
}

struct StreamEvaluation {
    attribute: StreamAttribute,
    operator: StreamOperator,
    modulo: u64,
    value: u64,
    current_time: PolicyTime,
}

fn evaluate_stream_condition(evaluation: &StreamEvaluation) -> Option<bool> {
    match evaluation.attribute {
        StreamAttribute::Time => {
            if evaluation.modulo == 0 {
                return None;
            }
            Some(matches_stream_operator(
                evaluation.operator,
                evaluation.current_time.unix_seconds % evaluation.modulo,
                evaluation.value,
            ))
        }
        StreamAttribute::Hour => Some(matches_stream_operator(
            evaluation.operator,
            evaluation.current_time.hour as u64,
            evaluation.value,
        )),
        StreamAttribute::Minute => Some(matches_stream_operator(
            evaluation.operator,
            evaluation.current_time.minute as u64,
            evaluation.value,
        )),
        StreamAttribute::Second => Some(matches_stream_operator(
            evaluation.operator,
            evaluation.current_time.second as u64,
            evaluation.value,
        )),
    }
}

fn stream_entitlement(
    entitlement: Entitlement,
    evaluation: &StreamEvaluation,
) -> Option<Entitlement> {
    if evaluate_stream_condition(evaluation)? {
        Some(entitlement)
    } else {
        None
    }
}

/// Prüft Typ und Vergleich einer strukturierten Bedingung gegen einen vorhandenen Wert.
///
/// Typkonflikte liefern `false`. Zahlen und Bool werden numerisch verglichen;
/// Stringhashes passen nur bei Gleichheit. Fehlende Map-Werte behandelt der Aufrufer.
pub fn matches_attribute_condition(condition: &AttributeCondition, value: &AttributeValue) -> bool {
    if condition.value_kind != value.kind {
        return false;
    }

    match condition.value_kind {
        AttributeValueKind::Number => {
            matches_stream_operator(condition.operator, value.number, condition.value_number)
        }
        AttributeValueKind::Bool => {
            matches_stream_operator(condition.operator, value.number, condition.value_number)
        }
        AttributeValueKind::String => {
            condition.operator == StreamOperator::Equal && value.hash == condition.value_hash
        }
    }
}

/// Wählt die Objektidentität: System `(0, 0)`, Subject `(UID, 0)`, Resource `(Gerät, Inode)`.
pub const fn attribute_object_ids(
    namespace: AttributeNamespace,
    subject: u32,
    resource_device: u64,
    resource_inode: u64,
) -> (u64, u64) {
    match namespace {
        AttributeNamespace::System => (0, 0),
        AttributeNamespace::Subject => (subject as u64, 0),
        AttributeNamespace::Resource => (resource_device, resource_inode),
    }
}

/// Liefert das Entitlement, wenn aktivierte Regel, UID, Command und Dateiidentität passen.
///
/// `None` bezeichnet eine nicht passende/deaktivierte Regel und ist kein Deny.
/// Die Kombination mehrerer Ergebnisse erfolgt getrennt in [`DecisionState`].
pub fn evaluate_file_open_static_policy(
    request: &FileOpenRequest,
    policy: &FileOpenStaticPolicy,
) -> Option<Entitlement> {
    if policy.enabled == 0 || policy.action != PolicyAction::FileOpen {
        return None;
    }
    if !matches_subject(policy.subject, request.subject) {
        return None;
    }
    if !matches_bytes(&policy.command, &request.command) {
        return None;
    }
    if !matches_file_resource(
        policy.resource_device,
        policy.resource_inode,
        request.resource_device,
        request.resource_inode,
    ) {
        return None;
    }
    Some(policy.entitlement)
}

/// Prüft Aktivierung und statische Requestfilter einer Stream-Policy.
///
/// Zeit und dynamische Attribute sind zusätzliche, separat zu prüfende Bedingungen.
pub fn file_open_stream_policy_applies_to_request(
    request: &FileOpenRequest,
    policy: &FileOpenStreamPolicy,
) -> bool {
    if policy.enabled == 0 || policy.action != PolicyAction::FileOpen {
        return false;
    }
    if !matches_subject(policy.subject, request.subject) {
        return false;
    }
    if !matches_bytes(&policy.command, &request.command) {
        return false;
    }
    if !matches_file_resource(
        policy.resource_device,
        policy.resource_inode,
        request.resource_device,
        request.resource_inode,
    ) {
        return false;
    }
    true
}

/// Wertet die optionale Zeitbedingung aus und liefert das Entitlement bei Übereinstimmung.
///
/// Ohne aktivierte Zeitbedingung wird das Entitlement unmittelbar zurückgegeben.
/// Statische Requestfilter und Attributbedingungen werden hier nicht geprüft.
/// Der historische Name bezeichnet weiterhin aktiv verwendete Logik.
pub fn file_open_stream_legacy_entitlement(
    current_time: PolicyTime,
    policy: &FileOpenStreamPolicy,
) -> Option<Entitlement> {
    if policy.stream_condition_enabled == 0 {
        return Some(policy.entitlement);
    }

    let evaluation = StreamEvaluation {
        attribute: policy.attribute,
        operator: policy.operator,
        modulo: policy.modulo,
        value: policy.value,
        current_time,
    };
    stream_entitlement(policy.entitlement, &evaluation)
}

/// Wertet Requestfilter und Zeit einer Stream-Policy ohne dynamische Bedingungen aus.
///
/// `None` wird auch bei vorhandenen dynamischen Bedingungen zurückgegeben, weil
/// dieser reine Helfer keine Map-Abfrage durchführt. Kernel und PEP kombinieren
/// Requestfilter, Attributabfrage und Zeit deshalb separat.
pub fn evaluate_file_open_stream_policy(
    request: &FileOpenRequest,
    current_time: PolicyTime,
    policy: &FileOpenStreamPolicy,
) -> Option<Entitlement> {
    if !file_open_stream_policy_applies_to_request(request, policy) {
        return None;
    }
    if policy.attribute_condition_count != 0 {
        return None;
    }
    file_open_stream_legacy_entitlement(current_time, policy)
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AttributeHash {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AttributeKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AttributeValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AttributeCondition {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileOpenStaticPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileOpenStreamPolicy {}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_open_request() -> FileOpenRequest {
        FileOpenRequest {
            subject: 1000,
            command: command_name("cat"),
            resource_device: 0,
            resource_inode: 0,
        }
    }

    fn attribute_condition(
        value_kind: AttributeValueKind,
        operator: StreamOperator,
        value_number: u64,
        value_hash: AttributeHash,
    ) -> AttributeCondition {
        AttributeCondition {
            namespace: AttributeNamespace::Subject,
            operator,
            value_kind,
            _pad: [0; 5],
            name_hash: attribute_hash("position"),
            value_number,
            value_hash,
        }
    }

    #[test]
    fn policy_time_derives_utc_components_from_unix_seconds() {
        assert_eq!(
            PolicyTime::from_unix_seconds(12 * 3_600 + 34 * 60 + 56),
            PolicyTime {
                unix_seconds: 45_296,
                hour: 12,
                minute: 34,
                second: 56,
            }
        );
        assert_eq!(PolicyTime::from_unix_seconds(86_400).hour, 0);
    }

    #[test]
    fn decision_state_uses_deny_overrides() {
        assert_eq!(DecisionState::empty().lsm_return_value(), LSM_ALLOW);

        let mut permit_only = DecisionState::empty();
        permit_only.record(Entitlement::Permit);
        assert_eq!(permit_only.lsm_return_value(), LSM_ALLOW);

        permit_only.record(Entitlement::Deny);
        assert_eq!(permit_only.lsm_return_value(), LSM_DENY);
    }

    #[test]
    fn file_open_static_policy_matches_all_request_fields() {
        let mut policy = FileOpenStaticPolicy::new(Entitlement::Deny, 1000, "cat", "");
        policy.resource_device = 42;
        policy.resource_inode = 99;
        let matching = FileOpenRequest {
            resource_device: 42,
            resource_inode: 99,
            ..file_open_request()
        };

        assert_eq!(
            evaluate_file_open_static_policy(&matching, &policy),
            Some(Entitlement::Deny)
        );

        for non_matching in [
            FileOpenRequest {
                subject: 1001,
                ..matching
            },
            FileOpenRequest {
                command: command_name("tail"),
                ..matching
            },
            FileOpenRequest {
                resource_inode: 100,
                ..matching
            },
        ] {
            assert_eq!(
                evaluate_file_open_static_policy(&non_matching, &policy),
                None
            );
        }
    }

    #[test]
    fn any_subject_static_policy_matches_every_uid() {
        let policy = FileOpenStaticPolicy::new(Entitlement::Permit, ANY_SUBJECT, "", "");

        for subject in [0, 1000, u32::MAX - 1] {
            let request = FileOpenRequest {
                subject,
                ..file_open_request()
            };
            assert_eq!(
                evaluate_file_open_static_policy(&request, &policy),
                Some(Entitlement::Permit)
            );
        }
    }

    #[test]
    fn utc_component_policies_respect_operator_boundaries() {
        let mut policy = FileOpenStreamPolicy::stream(Entitlement::Deny, 1000, "", "");
        policy.stream_condition_enabled = 1;
        policy.attribute = StreamAttribute::Hour;
        policy.value = 8;

        for (operator, hour, expected) in [
            (StreamOperator::LessThan, 7, true),
            (StreamOperator::LessThan, 8, false),
            (StreamOperator::LessThanOrEqual, 8, true),
            (StreamOperator::Equal, 8, true),
            (StreamOperator::GreaterThanOrEqual, 8, true),
            (StreamOperator::GreaterThan, 8, false),
            (StreamOperator::GreaterThan, 9, true),
        ] {
            policy.operator = operator;
            let result = evaluate_file_open_stream_policy(
                &file_open_request(),
                PolicyTime::from_unix_seconds(hour * 3_600),
                &policy,
            );
            assert_eq!(result == Some(Entitlement::Deny), expected);
        }
    }

    #[test]
    fn attribute_conditions_match_numbers_and_booleans() {
        let number_condition = attribute_condition(
            AttributeValueKind::Number,
            StreamOperator::LessThanOrEqual,
            3,
            AttributeHash::zero(),
        );
        let bool_condition = attribute_condition(
            AttributeValueKind::Bool,
            StreamOperator::Equal,
            1,
            AttributeHash::zero(),
        );

        assert!(matches_attribute_condition(
            &number_condition,
            &AttributeValue::number(2)
        ));
        assert!(!matches_attribute_condition(
            &number_condition,
            &AttributeValue::number(4)
        ));
        assert!(matches_attribute_condition(
            &bool_condition,
            &AttributeValue::bool(true)
        ));
        assert!(!matches_attribute_condition(
            &bool_condition,
            &AttributeValue::bool(false)
        ));
    }

    #[test]
    fn attribute_conditions_match_string_hashes_only_by_equality() {
        let condition = attribute_condition(
            AttributeValueKind::String,
            StreamOperator::Equal,
            0,
            attribute_hash("engineer"),
        );
        let unsupported_operator = attribute_condition(
            AttributeValueKind::String,
            StreamOperator::GreaterThan,
            0,
            attribute_hash("engineer"),
        );

        assert!(matches_attribute_condition(
            &condition,
            &AttributeValue::string(attribute_hash("engineer"))
        ));
        assert!(!matches_attribute_condition(
            &condition,
            &AttributeValue::string(attribute_hash("manager"))
        ));
        assert!(!matches_attribute_condition(
            &unsupported_operator,
            &AttributeValue::string(attribute_hash("engineer"))
        ));
    }

    #[test]
    fn attribute_conditions_reject_type_mismatches() {
        let condition = attribute_condition(
            AttributeValueKind::Number,
            StreamOperator::Equal,
            3,
            AttributeHash::zero(),
        );

        assert!(!matches_attribute_condition(
            &condition,
            &AttributeValue::string(attribute_hash("3"))
        ));
    }

    #[test]
    fn attribute_object_ids_are_namespace_scoped() {
        assert_eq!(
            attribute_object_ids(AttributeNamespace::System, 1000, 42, 99),
            (0, 0)
        );
        assert_eq!(
            attribute_object_ids(AttributeNamespace::Subject, 1000, 42, 99),
            (1000, 0)
        );
        assert_eq!(
            attribute_object_ids(AttributeNamespace::Resource, 1000, 42, 99),
            (42, 99)
        );
    }

    #[test]
    fn stream_policy_with_dynamic_attributes_requires_map_lookup() {
        let mut policy = FileOpenStreamPolicy::stream(Entitlement::Deny, 1000, "", "");
        policy.attribute_condition_count = 1;
        policy.attribute_conditions[0] = attribute_condition(
            AttributeValueKind::String,
            StreamOperator::Equal,
            0,
            attribute_hash("engineer"),
        );

        let result = evaluate_file_open_stream_policy(
            &file_open_request(),
            PolicyTime::from_unix_seconds(0),
            &policy,
        );

        assert_eq!(result, None);
    }

    #[test]
    fn stream_policy_returns_entitlement_when_condition_matches() {
        let policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "",
            "",
            StreamOperator::LessThan,
            10,
            5,
        );

        let result = evaluate_file_open_stream_policy(
            &file_open_request(),
            PolicyTime::from_unix_seconds(3),
            &policy,
        );

        assert_eq!(result, Some(Entitlement::Deny));
    }

    #[test]
    fn stream_policy_uses_utc_hour_from_shared_policy_time() {
        let mut policy = FileOpenStreamPolicy::stream(Entitlement::Deny, 1000, "", "");
        policy.stream_condition_enabled = 1;
        policy.attribute = StreamAttribute::Hour;
        policy.operator = StreamOperator::Equal;
        policy.value = 12;

        assert_eq!(
            evaluate_file_open_stream_policy(
                &file_open_request(),
                PolicyTime::from_unix_seconds(12 * 3_600),
                &policy,
            ),
            Some(Entitlement::Deny)
        );
    }

    #[test]
    fn stream_policy_is_not_applicable_when_condition_does_not_match() {
        let policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "",
            "",
            StreamOperator::LessThan,
            10,
            5,
        );

        let result = evaluate_file_open_stream_policy(
            &file_open_request(),
            PolicyTime::from_unix_seconds(8),
            &policy,
        );

        assert_eq!(result, None);
    }

    #[test]
    fn stream_policy_with_zero_modulo_is_not_applicable() {
        let policy = FileOpenStreamPolicy::time(
            Entitlement::Permit,
            1000,
            "",
            "",
            StreamOperator::LessThan,
            0,
            5,
        );

        let result = evaluate_file_open_stream_policy(
            &file_open_request(),
            PolicyTime::from_unix_seconds(3),
            &policy,
        );

        assert_eq!(result, None);
    }

    #[test]
    fn file_open_stream_policy_respects_command_filter() {
        let policy = FileOpenStreamPolicy::time(
            Entitlement::Deny,
            1000,
            "cat",
            "",
            StreamOperator::LessThanOrEqual,
            10,
            2,
        );

        let denied = evaluate_file_open_stream_policy(
            &file_open_request(),
            PolicyTime::from_unix_seconds(1),
            &policy,
        );

        let allowed_request = FileOpenRequest {
            command: command_name("tail"),
            ..file_open_request()
        };
        let not_applicable = evaluate_file_open_stream_policy(
            &allowed_request,
            PolicyTime::from_unix_seconds(1),
            &policy,
        );

        assert_eq!(denied, Some(Entitlement::Deny));
        assert_eq!(not_applicable, None);
    }
}
