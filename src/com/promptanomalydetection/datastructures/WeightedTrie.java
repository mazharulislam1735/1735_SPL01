package com.promptanomalydetection.datastructures;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * WeightedTrie - a custom prefix tree for the in-memory threat dictionary.
 *
 * Every node stores one character. A node that ends a dictionary entry is
 * "terminal" and carries an integer threat weight plus a category tag
 * (e.g. CAT_CHEMICAL_DESTRUCTION).
 *
 * Complexity summary (K = length of the term / longest dictionary entry,
 * N = length of the scanned text, A = alphabet size = 128):
 *   insert(term)        O(K)
 *   contains/getWeight  O(K)
 *   startsWith(prefix)  O(K)
 *   matchAt(text, i)    O(K)    -- longest dictionary entry starting at i
 *   scan(text)          O(N*K) worst case, O(N) in practice, because K is a
 *                       small constant bounded by the longest entry and the
 *                       walk dies after 1-2 characters for non-threat text.
 * Space: O(total characters * A) worst case; child arrays are allocated
 * lazily so leaf nodes cost nothing.
 *
 * Matching is case-insensitive, whitespace-normalised and word-bounded
 * ("acid" does NOT match inside "placid").
 *
 * NOT thread-safe for concurrent insert + scan. Build it at startup, then
 * treat it as read-only while background threads call scan().
 */
public class WeightedTrie {

    public static final String DEFAULT_CATEGORY = "CAT_UNCATEGORIZED";

    /** ASCII alphabet. Direct array indexing gives O(1) child lookup per character. */
    private static final int ALPHABET_SIZE = 128;

    /** One trie node. */
    private static final class Node {
        final char ch;            // character on the edge leading into this node
        Node[] children;          // lazily allocated, indexed by character code
        boolean terminal;         // true if a dictionary entry ends here
        int weight;               // threat weight (> 0 only when terminal)
        String category;          // category tag (only when terminal)

        Node(char ch) {
            this.ch = ch;
        }
    }

    /** One dictionary hit found inside scanned text. */
    public static final class Match {
        public final String term;      // matched text (normalised)
        public final int weight;
        public final String category;
        public final int start;        // inclusive offset in the NORMALISED text
        public final int end;          // exclusive offset in the NORMALISED text

        Match(String term, int weight, String category, int start, int end) {
            this.term = term;
            this.weight = weight;
            this.category = category;
            this.start = start;
            this.end = end;
        }

        @Override
        public String toString() {
            return "\"" + term + "\" [weight=" + weight + ", " + category
                    + ", @" + start + "-" + end + "]";
        }
    }

    /** Result of scanning a whole text. */
    public static final class ScanResult {
        public final int totalScore;
        public final List<Match> matches;

        ScanResult(int totalScore, List<Match> matches) {
            this.totalScore = totalScore;
            this.matches = Collections.unmodifiableList(matches);
        }
    }

    private final Node root = new Node('\0');
    private int termCount = 0;
    private int nodeCount = 1;
    private int maxTermLength = 0;

    // ------------------------------------------------------------------
    // Normalisation
    // ------------------------------------------------------------------

    /**
     * Lower-cases, trims, and collapses every whitespace run into one space,
     * so "Without   Leaving\ta  TRACE" matches "without leaving a trace".
     * Time: O(N).
     */
    public static String normalize(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(text.length());
        boolean pendingSpace = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isWhitespace(c)) {
                pendingSpace = sb.length() > 0;      // never emit a leading space
            } else {
                if (pendingSpace) {
                    sb.append(' ');
                    pendingSpace = false;
                }
                sb.append(Character.toLowerCase(c));
            }
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Insertion
    // ------------------------------------------------------------------

    /**
     * Inserts a word or phrase with its threat weight and category tag.
     * If the term already exists, the HIGHER weight (and its category) wins.
     *
     * @return false if the entry was rejected (blank, weight <= 0, non-ASCII)
     *
     * Time: O(K) - one array lookup per character. Space: O(K) new nodes worst case.
     */
    public boolean insert(String term, int weight, String category) {
        if (weight <= 0) {
            return false;
        }
        String key = normalize(term);
        if (key.isEmpty()) {
            return false;
        }
        for (int i = 0; i < key.length(); i++) {      // validate BEFORE mutating the trie
            if (key.charAt(i) >= ALPHABET_SIZE) {
                return false;
            }
        }

        Node cur = root;
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (cur.children == null) {
                cur.children = new Node[ALPHABET_SIZE];
            }
            Node next = cur.children[c];
            if (next == null) {
                next = new Node(c);
                cur.children[c] = next;
                nodeCount++;
            }
            cur = next;
        }

        String cat = (category == null || category.isEmpty()) ? DEFAULT_CATEGORY : category;
        if (!cur.terminal) {
            cur.terminal = true;
            cur.weight = weight;
            cur.category = cat;
            termCount++;
        } else if (weight > cur.weight) {
            cur.weight = weight;
            cur.category = cat;
        }
        maxTermLength = Math.max(maxTermLength, key.length());
        return true;
    }

    // ------------------------------------------------------------------
    // Exact lookups
    // ------------------------------------------------------------------

    /** Walks the trie along key. Time: O(K). Returns null if the path is missing. */
    private Node findNode(String key) {
        Node cur = root;
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            if (c >= ALPHABET_SIZE || cur.children == null) {
                return null;
            }
            cur = cur.children[c];
            if (cur == null) {
                return null;
            }
        }
        return cur;
    }

    /** Exact-entry lookup. Time: O(K). */
    public boolean contains(String term) {
        Node n = findNode(normalize(term));
        return n != null && n.terminal;
    }

    /** Weight of an exact entry, or 0 if absent. Time: O(K). */
    public int getWeight(String term) {
        Node n = findNode(normalize(term));
        return (n != null && n.terminal) ? n.weight : 0;
    }

    /** Category of an exact entry, or null if absent. Time: O(K). */
    public String getCategory(String term) {
        Node n = findNode(normalize(term));
        return (n != null && n.terminal) ? n.category : null;
    }

    /** True if some dictionary entry starts with prefix. Time: O(K). */
    public boolean startsWith(String prefix) {
        String key = normalize(prefix);
        return !key.isEmpty() && findNode(key) != null;
    }

    // ------------------------------------------------------------------
    // Substring search / scoring
    // ------------------------------------------------------------------

    /**
     * Longest dictionary entry that begins exactly at offset start of an
     * ALREADY NORMALISED text (see normalize()). Returns null if none.
     * The match must begin and end on a word boundary.
     *
     * Time: O(K) - the walk is bounded by the longest dictionary entry and
     * stops at the first character with no matching child.
     */
    public Match matchAt(String normalizedText, int start) {
        int n = normalizedText.length();
        if (start < 0 || start >= n || !startsOnBoundary(normalizedText, start)) {
            return null;
        }
        Node cur = root;
        Node best = null;
        int bestEnd = -1;
        for (int j = start; j < n; j++) {
            char c = normalizedText.charAt(j);
            if (c >= ALPHABET_SIZE || cur.children == null) {
                break;
            }
            cur = cur.children[c];
            if (cur == null) {
                break;
            }
            if (cur.terminal && endsOnBoundary(normalizedText, j + 1)) {
                best = cur;                    // remember longest valid entry so far
                bestEnd = j + 1;
            }
        }
        if (best == null) {
            return null;
        }
        return new Match(normalizedText.substring(start, bestEnd),
                best.weight, best.category, start, bestEnd);
    }

    /**
     * Scans free text and sums the weights of all dictionary hits.
     * Uses maximal munch: at each position the longest entry wins and the scan
     * resumes AFTER it, so words inside a matched phrase are not double counted
     * (e.g. "without leaving a trace" scores 5, not 5 + score("trace")).
     * Every occurrence counts, so repetition raises the score.
     *
     * Offsets in the returned Matches refer to normalize(text), not the raw input.
     *
     * Time: O(N) normalisation + at most N calls of O(K) = O(N*K), effectively O(N).
     * Space: O(N) for the normalised copy + O(matches).
     */
    public ScanResult scan(String text) {
        String norm = normalize(text);
        int n = norm.length();
        List<Match> matches = new ArrayList<>();
        int total = 0;
        int i = 0;
        while (i < n) {
            Match m = matchAt(norm, i);
            if (m != null) {
                matches.add(m);
                total += m.weight;
                i = m.end;                      // skip past the matched phrase
            } else {
                i++;
            }
        }
        return new ScanResult(total, matches);
    }

    // ------------------------------------------------------------------
    // Word-boundary helpers (O(1))
    // ------------------------------------------------------------------

    private static boolean isWordChar(char c) {
        return Character.isLetterOrDigit(c);
    }

    /** A match may not start in the middle of a word. */
    private static boolean startsOnBoundary(String s, int i) {
        return i == 0 || !isWordChar(s.charAt(i - 1)) || !isWordChar(s.charAt(i));
    }

    /** A match may not end in the middle of a word. */
    private static boolean endsOnBoundary(String s, int end) {
        return end == s.length() || !isWordChar(s.charAt(end - 1)) || !isWordChar(s.charAt(end));
    }

    // ------------------------------------------------------------------
    // Statistics
    // ------------------------------------------------------------------

    public int size()          { return termCount; }
    public int nodeCount()     { return nodeCount; }
    public int maxTermLength() { return maxTermLength; }
}
