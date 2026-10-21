//! Gemeinsame Loggingmodi für den Userspace-Schalter und die Kernel-Ausgabe.

/// Werte der nicht gepinnten `DEBUG_LOGGING`-Map.
///
/// Der bisherige Wert 1 bleibt ausführliches Debuglogging. Der reduzierte
/// Deny-Modus unterdrückt Meldungen bereits vor dem Aufruf von `bpf_printk`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum KernelLogMode {
    /// Keine Kernel-Debugausgaben; Standard ohne explizite Aktivierung.
    Off = 0,
    /// Alle Diagnosemeldungen einschließlich Permit und Zwischenständen.
    Verbose = 1,
    /// Nur endgültige Deny-Entscheidungen und fehlgeschlagene Tail-Calls.
    Deny = 2,
}

impl KernelLogMode {
    /// Interpretiert `TAILS_PDP_EBPF_DEBUG`; bisherige boolesche Werte bleiben gültig.
    pub fn from_setting(value: Option<&str>) -> Self {
        match value {
            None
            | Some(
                "" | "0" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" | "no" | "No" | "NO",
            ) => Self::Off,
            Some("deny" | "deny-only") => Self::Deny,
            Some(_) => Self::Verbose,
        }
    }

    /// Dekodiert den Map-Wert; unbekannte Werte aktivieren keine Ausgabe.
    #[inline(always)]
    pub const fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::Verbose,
            2 => Self::Deny,
            _ => Self::Off,
        }
    }

    /// Ob Permit-, UID- und Auswertungszwischenstände protokolliert werden.
    #[inline(always)]
    pub const fn logs_verbose(self) -> bool {
        matches!(self, Self::Verbose)
    }

    /// Ob endgültige Deny-Entscheidungen und Tail-Call-Fehler protokolliert werden.
    #[inline(always)]
    pub const fn logs_denials(self) -> bool {
        matches!(self, Self::Verbose | Self::Deny)
    }
}

#[cfg(test)]
mod tests {
    use super::KernelLogMode;

    #[test]
    fn old_boolean_settings_keep_their_meaning() {
        assert_eq!(KernelLogMode::from_setting(None), KernelLogMode::Off);
        for value in [
            "", "0", "false", "False", "FALSE", "off", "Off", "OFF", "no", "No", "NO",
        ] {
            assert_eq!(KernelLogMode::from_setting(Some(value)), KernelLogMode::Off);
        }
        for value in ["1", "true", "yes", "verbose", "other"] {
            assert_eq!(
                KernelLogMode::from_setting(Some(value)),
                KernelLogMode::Verbose
            );
        }
    }

    #[test]
    fn deny_mode_suppresses_verbose_events_but_keeps_denials() {
        for value in ["deny", "deny-only"] {
            let mode = KernelLogMode::from_setting(Some(value));
            assert_eq!(mode, KernelLogMode::Deny);
            assert_eq!(KernelLogMode::from_raw(mode as u32), mode);
            assert!(!mode.logs_verbose());
            assert!(mode.logs_denials());
        }
        assert!(KernelLogMode::Verbose.logs_verbose());
        assert!(KernelLogMode::Verbose.logs_denials());
    }

    #[test]
    fn disabled_and_unknown_map_values_emit_nothing() {
        for value in [0, 3, u32::MAX] {
            let mode = KernelLogMode::from_raw(value);
            assert!(!mode.logs_verbose());
            assert!(!mode.logs_denials());
        }
        assert_eq!(KernelLogMode::from_raw(1), KernelLogMode::Verbose);
    }
}
