# 1735_SPL01
# Prompt Anomaly and Malicious Detection

Deterministic, pure-Java real-time input firewall for AI prompts (Java 11+, no external libraries).

## Build and run (from this folder)

Quick start: `./build.sh` then `./run.sh` (Windows: `build.bat`, `run.bat`). Needs a JDK, Java 11+.
Manual commands:

    javac -d out $(find src -name '*.java')
    java -cp out com.promptanomalydetection.gui.MainDashboard            # GUI; reads data/, writes threat_logs.csv
    java -cp out com.promptanomalydetection.gui.MainDashboard data logs/threats.csv   # custom data dir / log file

    javac -d out $(find src test -name '*.java')
    java -Djava.awt.headless=true -cp out DashboardSmokeTest  # end-to-end check, no window needed

Module demos: `com.promptanomalydetection.Module1Demo`, `Module2Demo`, `Module3Demo`.

## Packages

| Package | Classes | Role |
|---|---|---|
| datastructures | WeightedTrie, ThreatMinHeap, IntList | custom Trie, binary min-heap, int array |
| dataset | InvertedIndex, DatasetReader | category -> terms table, streaming CSV/JSON reader |
| algorithms | KarpRabinHash, ZScoreCalculator, ThreatGraph | rolling hash, entropy Z-score, adjacency-list graph + BFS/DFS |
| models | ThreatNode | immutable threat log record |
| engine | ThreatEngine, ScoringPolicy, AnalysisResult, RiskLevel, ThreatLogger | scoring pipeline (no Swing), CSV log |
| threading | BackgroundWorker, ThreatRecorder | off-EDT analysis; off-EDT logging / heap / graph |
| gui | MainDashboard, DashboardPanel, LiveOverlayPanel | JFrame shell, dashboard content, live status panel |

## Scoring (ScoringPolicy defaults, block at total >= 7)

    total = WeightedTrie hits + 7 (any Karp-Rabin signature, once) + proximity bonuses
          + Z-score anomaly (HIGH_ENTROPY 7, LOW_ENTROPY 4, LENGTH_SPIKE 3)

## Threading model

    EDT: DocumentListener -> BackgroundWorker.submit(text)            O(1), never blocks
    pamd-coordinator + pamd-stage-1/2: Trie | Karp-Rabin | Z-score in parallel, total risk summed
    EDT: result callback -> banner, gauges, Send enabled/disabled
    pamd-recorder: ThreatNode -> ThreatGraph + ThreatMinHeap + threat_logs.csv -> snapshot -> EDT
