# Architekturvorschlag zu F12

```mermaid
flowchart TB
    PF["Policydateien"]
    AF["Attributquellen"]
    TARGET["Zielprozess<br/>neue Opens und bestehende FDs"]

    subgraph RT["Userspace: Hauptprogramm / gemeinsame Runtime"]
        PL["Policyloader"]
        AL["Attributloader"]
        CLOCK["Zeitaktualisierer"]
        Q["Aktivierungskanal<br/>max. ein ausstehendes Ereignis"]
        subgraph PEP["Userspace-PEP"]
            TIMER["Nächste relevante Zeitgrenze"]
            SCAN["/proc-Scan und lokale Policybewertung"]
        end
    end

    subgraph KERNEL["Kernelspace"]
        MAPS[("Gepinnte eBPF-Maps<br/>Policies · Attribute · Generationen · Zeit")]
        HOOK["eBPF-LSM: file_open<br/>lokale Policybewertung"]
        DECISION["Erlauben oder verweigern"]
    end

    PF --> PL
    AF --> AL
    PL -->|"Policies und Generation"| MAPS
    AL -->|"Attribute und Generation"| MAPS
    CLOCK -->|"CURRENT_TIME"| MAPS
    PL -.->|"Policygeneration aktiviert"| Q
    AL -.->|"Attributgeneration aktiviert"| Q
    Q -.->|"Nachbewertung auslösen"| SCAN
    MAPS -->|"aktive Zeitbedingungen"| TIMER
    TIMER -.->|"Zeitgrenze erreicht"| SCAN
    MAPS -->|"Entscheidungsgrundlagen"| SCAN
    SCAN -->|"Zeit bei Zeittrigger aktualisieren"| MAPS
    TARGET -->|"FD-Informationen über /proc"| SCAN
    SCAN -->|"ptrace: gezielter Schließversuch"| TARGET
    TARGET -->|"neue Dateiöffnung"| HOOK
    MAPS -->|"Entscheidungsgrundlagen"| HOOK
    HOOK --> DECISION

    classDef state fill:#edf2f7,stroke:#526477,color:#172635
    classDef event fill:#fff3df,stroke:#a76b16,color:#513509
    class MAPS state
    class Q,TIMER event
```

**Legende:** Durchgezogene Pfeile zeigen Datenzugriffe oder Operationen, gestrichelte Pfeile Aktivierungs- und Zeitereignisse. Die Gruppierung zeigt Zuständigkeiten, keine parallelen Threads. Während des synchronen Scans warten die übrigen Zweige der gemeinsamen Runtime.

**Vorgeschlagene Bildunterschrift:** Konzeptionelle Architektur mit Zustandsbereitstellung, ereignisbasierter Nachbewertung bestehender File Descriptors und Prüfung neuer Dateiöffnungen. Erfolgreiche Policy- und Attributaktivierungen sowie relevante Zeitgrenzen lösen die Nachbewertung aus. Der nachträgliche Entzug erfolgt als Best-Effort-Schließversuch. Eigene Darstellung.

Der Zeitaktualisierer schreibt normalerweise sekündlich CURRENT_TIME, löst aber nicht bei jedem Tick einen Scan aus. Der Userspace-PEP berechnet die nächste relevante Grenze aus den aktiven Zeitbedingungen und aktualisiert bei diesem Trigger den Zeitwert selbst.

Zur Lesbarkeit ausgelassen: Initialisierung/Attach durch das Hauptprogramm, lesendes Administrationstool, interne Tail-Call-Stufen und getrennte Diagnoseausgaben. Es gibt keinen dargestellten zentralen Decision-Stream oder Log-Kanal. Der Vorschlag ersetzt die eingebundene Thesis-Grafik noch nicht.

