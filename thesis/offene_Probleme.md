- Muss die Seitenzahl bei der Quellenangabe mit angegeben werden?


16	Maps sind generischer Speicher für unterschiedliche Datentypen und ermöglichen Datenaustausch zwischen Kernel- und Userspace.	sections/02-grundlagen.tex:161	kernelBpfMaps – BPF maps	Abschnitt „Usage Notes“ beschreibt Erstellung und Zugriffe, enthält aber keine ausdrückliche Aussage zum Datenaustausch zwischen Kernel und Userspace. Die genaue Formulierung steht stattdessen in bpf(2), Abschnitt „eBPF maps“.	Teilweise belegt. Die verwendete Quelle zeigt Map-Operationen, trägt aber den Sharing-Satz nicht ausdrücklich. Empfehlung: zusätzlich oder stattdessen manBpf zitieren.




20	BPF-Programme besitzen 512 Byte Stack; der Verifier hat interne Komplexitätsgrenzen, etwa für untersuchte Instruktionen und Zustände.	sections/02-grundlagen.tex:188	kernelBpfDesignQA – BPF Design Q&A	Fragen „What are the verifier limits?“ und „How much stack space a BPF program uses?“.	Vollständig belegt. Die konkreten Zahlen sind versionsabhängig; der Satz sollte nicht zeitlos formuliert werden.