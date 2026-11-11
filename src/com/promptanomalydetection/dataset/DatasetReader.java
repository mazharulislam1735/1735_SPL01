package com.promptanomalydetection.dataset;

import com.promptanomalydetection.datastructures.WeightedTrie;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * DatasetReader - streaming, line-by-line ingestion of offline threat datasets.
 *
 * Only ONE line is held in memory at a time (BufferedReader.readLine), so a
 * large offline dataset never has to fit in RAM. Parsed records are pushed
 * straight into the shared WeightedTrie and InvertedIndex.
 *
 * Supported sample formats (the small, normalised files committed to the repo):
 *
 *   CSV  (.csv)          header optional:  term,weight,category[,synonyms]
 *                        synonyms are separated by '|'; fields may be "quoted".
 *                        e.g.  dissolve,3,CAT_CHEMICAL_DESTRUCTION,liquefy|melt away
 *
 *   JSON (.json/.jsonl)  ONE flat object per line, optionally wrapped in a
 *                        [ ... ] array with trailing commas:
 *                        {"term":"acid","weight":2,"category":"CAT_CHEMICAL_DESTRUCTION","synonyms":["lye"]}
 *
 * Blank lines, '#' comment lines (CSV) and bare '[' / ']' lines are ignored.
 * Malformed lines are skipped and reported - one bad line never aborts startup.
 * Multi-line quoted CSV fields and nested JSON objects are not supported.
 *
 * Complexity (F = number of lines, L = average line length, S = synonyms per record):
 *   parse one line          O(L)
 *   insert one record       O(K * (1 + S)) trie work, where K = term length
 *   whole file              O(total characters) = O(F * L)  -- single pass
 * Memory while reading: O(L) for the current line + the Trie/Index themselves.
 *
 * Requires Java 11+ (FileReader with an explicit charset).
 */
public class DatasetReader {

    private static final int MAX_WARNINGS = 20;

    private final WeightedTrie trie;
    private final InvertedIndex index;

    public DatasetReader(WeightedTrie trie, InvertedIndex index) {
        if (trie == null || index == null) {
            throw new IllegalArgumentException("trie and index must not be null");
        }
        this.trie = trie;
        this.index = index;
    }

    // ------------------------------------------------------------------
    // Result types
    // ------------------------------------------------------------------

    /** Statistics for one loaded file. */
    public static final class LoadReport {
        public final String fileName;
        public int linesRead;
        public int recordsLoaded;
        public int linesSkipped;
        public String error;                               // non-null if the file could not be read
        public final List<String> warnings = new ArrayList<>();

        LoadReport(String fileName) {
            this.fileName = fileName;
        }

        void skip(int lineNo, String reason) {
            linesSkipped++;
            if (warnings.size() < MAX_WARNINGS) {
                warnings.add("line " + lineNo + ": " + reason);
            }
        }

        @Override
        public String toString() {
            return fileName + " -> read=" + linesRead + ", loaded=" + recordsLoaded
                    + ", skipped=" + linesSkipped + (error != null ? ", ERROR=" + error : "");
        }
    }

    /** One parsed dataset row. */
    private static final class Record {
        final String term;
        final int weight;
        final String category;
        final List<String> synonyms;

        Record(String term, int weight, String category, List<String> synonyms) {
            this.term = term;
            this.weight = weight;
            this.category = category;
            this.synonyms = synonyms;
        }
    }

    // ------------------------------------------------------------------
    // Loading
    // ------------------------------------------------------------------

    /**
     * Loads several datasets in order into the same Trie and Index. A missing
     * or unreadable file is recorded in its report and does not stop the others.
     */
    public List<LoadReport> loadAll(String... paths) {
        List<LoadReport> reports = new ArrayList<>();
        for (String path : paths) {
            try {
                reports.add(load(path));
            } catch (IOException | IllegalArgumentException e) {
                LoadReport failed = new LoadReport(path);
                failed.error = e.getMessage();
                reports.add(failed);
            }
        }
        return reports;
    }

    /**
     * Streams one file line by line and populates the Trie and Index.
     *
     * @throws IOException              if the file cannot be opened/read
     * @throws IllegalArgumentException if the extension is not csv/json/jsonl
     */
    public LoadReport load(String path) throws IOException {
        String lower = path.toLowerCase(Locale.ROOT);
        boolean csv = lower.endsWith(".csv");
        boolean json = lower.endsWith(".json") || lower.endsWith(".jsonl");
        if (!csv && !json) {
            throw new IllegalArgumentException("Unsupported dataset type (use .csv/.json/.jsonl): " + path);
        }

        LoadReport report = new LoadReport(path);
        try (BufferedReader reader = new BufferedReader(new FileReader(path, StandardCharsets.UTF_8))) {
            String line;
            int lineNo = 0;
            while ((line = reader.readLine()) != null) {   // O(L) per line, one line in memory
                lineNo++;
                report.linesRead++;
                Record rec;
                try {
                    rec = csv ? parseCsvLine(line) : parseJsonLine(line);
                } catch (IllegalArgumentException e) {
                    report.skip(lineNo, e.getMessage());
                    continue;
                }
                if (rec == null) {
                    continue;                              // blank / comment / header / bracket line
                }
                if (ingest(rec)) {
                    report.recordsLoaded++;
                } else {
                    report.skip(lineNo, "rejected (empty term, weight <= 0, or non-ASCII characters)");
                }
            }
        }
        return report;
    }

    /**
     * Pushes one record into both structures. The main term and every synonym
     * share the record's weight and category, so a synonym is scored exactly
     * like the primary term.
     * Time: O(K * (1 + S)) trie work plus index insertions.
     */
    private boolean ingest(Record rec) {
        String category = InvertedIndex.normalizeCategory(rec.category);
        if (category == null) {
            category = WeightedTrie.DEFAULT_CATEGORY;
        }
        boolean ok = trie.insert(rec.term, rec.weight, category);
        if (ok) {
            index.addTerm(category, rec.term);
        }
        for (String syn : rec.synonyms) {
            if (trie.insert(syn, rec.weight, category)) {
                index.addTerm(category, syn);
            }
        }
        return ok;
    }

    // ------------------------------------------------------------------
    // CSV parsing
    // ------------------------------------------------------------------

    /** Returns null for lines that carry no record. O(L). */
    private static Record parseCsvLine(String raw) {
        String line = raw.trim();
        if (line.isEmpty() || line.startsWith("#")) {
            return null;
        }
        List<String> f = splitCsv(line);
        if (f.size() < 2) {
            throw new IllegalArgumentException("expected at least term,weight");
        }
        if (f.get(0).equalsIgnoreCase("term") && f.get(1).equalsIgnoreCase("weight")) {
            return null;                                   // header row
        }
        int weight = parseWeight(f.get(1));
        String category = f.size() > 2 ? f.get(2) : null;
        List<String> synonyms = new ArrayList<>();
        if (f.size() > 3) {
            for (String s : f.get(3).split("\\|")) {
                String t = s.trim();
                if (!t.isEmpty()) {
                    synonyms.add(t);
                }
            }
        }
        return new Record(f.get(0), weight, category, synonyms);
    }

    /** Single-pass CSV splitter with "quoted, fields" and "" escapes. O(L). */
    private static List<String> splitCsv(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        sb.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    sb.append(c);
                }
            } else if (c == '"') {
                inQuotes = true;
            } else if (c == ',') {
                fields.add(sb.toString().trim());
                sb.setLength(0);
            } else {
                sb.append(c);
            }
        }
        fields.add(sb.toString().trim());
        return fields;
    }

    private static int parseWeight(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid weight '" + s + "'");
        }
    }

    // ------------------------------------------------------------------
    // Minimal flat-JSON parsing (no libraries)
    // ------------------------------------------------------------------

    /** Returns null for lines that carry no record. O(L). */
    private static Record parseJsonLine(String raw) {
        String s = raw.trim();
        // Strip array wrapper characters: leading "[" / "," and trailing "," / "]".
        while (!s.isEmpty() && (s.charAt(0) == '[' || s.charAt(0) == ',')) {
            s = s.substring(1).trim();
        }
        while (!s.isEmpty() && (s.charAt(s.length() - 1) == ',' || s.charAt(s.length() - 1) == ']')) {
            s = s.substring(0, s.length() - 1).trim();
        }
        if (s.isEmpty()) {
            return null;
        }
        if (s.charAt(0) != '{' || s.charAt(s.length() - 1) != '}') {
            throw new IllegalArgumentException("not a single flat JSON object");
        }

        Map<String, Object> fields = new HashMap<>();
        int[] p = {1};                                     // cursor, shared by the helpers
        try {
            skipWs(s, p);
            while (s.charAt(p[0]) != '}') {
                String key = readJsonString(s, p);
                skipWs(s, p);
                if (s.charAt(p[0]++) != ':') {
                    throw new IllegalArgumentException("expected ':' after key '" + key + "'");
                }
                skipWs(s, p);
                fields.put(key.toLowerCase(Locale.ROOT), readJsonValue(s, p));
                skipWs(s, p);
                char c = s.charAt(p[0]);
                if (c == ',') {
                    p[0]++;
                    skipWs(s, p);
                } else if (c != '}') {
                    throw new IllegalArgumentException("expected ',' or '}' at column " + p[0]);
                }
            }
        } catch (StringIndexOutOfBoundsException e) {
            throw new IllegalArgumentException("truncated JSON object");
        }

        Object term = fields.get("term");
        Object weight = fields.get("weight");
        Object category = fields.get("category");
        Object synonyms = fields.get("synonyms");
        if (!(term instanceof String) || ((String) term).trim().isEmpty()) {
            throw new IllegalArgumentException("missing \"term\"");
        }
        if (!(weight instanceof String)) {
            throw new IllegalArgumentException("missing \"weight\"");
        }
        List<String> syn = new ArrayList<>();
        if (synonyms instanceof List) {
            for (Object o : (List<?>) synonyms) {
                syn.add((String) o);
            }
        }
        return new Record((String) term, parseWeight((String) weight),
                category instanceof String ? (String) category : null, syn);
    }

    private static void skipWs(String s, int[] p) {
        while (p[0] < s.length() && Character.isWhitespace(s.charAt(p[0]))) {
            p[0]++;
        }
    }

    /** Reads a quoted JSON string with escapes, leaving the cursor after the closing quote. */
    private static String readJsonString(String s, int[] p) {
        if (s.charAt(p[0]) != '"') {
            throw new IllegalArgumentException("expected string at column " + p[0]);
        }
        p[0]++;
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = s.charAt(p[0]++);
            if (c == '"') {
                return sb.toString();
            }
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            char e = s.charAt(p[0]++);
            switch (e) {
                case '"':  sb.append('"');  break;
                case '\\': sb.append('\\'); break;
                case '/':  sb.append('/');  break;
                case 'n':  sb.append('\n'); break;
                case 't':  sb.append('\t'); break;
                case 'r':  sb.append('\r'); break;
                case 'b':  sb.append('\b'); break;
                case 'f':  sb.append('\f'); break;
                case 'u':
                    sb.append((char) Integer.parseInt(s.substring(p[0], p[0] + 4), 16));
                    p[0] += 4;
                    break;
                default:
                    throw new IllegalArgumentException("bad escape \\" + e);
            }
        }
    }

    /** A value is a string, an array of strings, or a raw token (number/true/null). */
    private static Object readJsonValue(String s, int[] p) {
        char c = s.charAt(p[0]);
        if (c == '"') {
            return readJsonString(s, p);
        }
        if (c == '[') {
            p[0]++;
            List<String> list = new ArrayList<>();
            skipWs(s, p);
            if (s.charAt(p[0]) == ']') {
                p[0]++;
                return list;
            }
            while (true) {
                skipWs(s, p);
                list.add(readJsonString(s, p));
                skipWs(s, p);
                char d = s.charAt(p[0]++);
                if (d == ']') {
                    return list;
                }
                if (d != ',') {
                    throw new IllegalArgumentException("expected ',' or ']' in array");
                }
            }
        }
        int start = p[0];
        while (p[0] < s.length() && s.charAt(p[0]) != ',' && s.charAt(p[0]) != '}') {
            p[0]++;
        }
        return s.substring(start, p[0]).trim();
    }
}
