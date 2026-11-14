package com.promptanomalydetection.algorithms;

import com.promptanomalydetection.datastructures.IntList;
import com.promptanomalydetection.datastructures.WeightedTrie;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * KarpRabinHash - Rabin-Karp rolling-hash matching for Prompt Anomaly and Malicious Detection.
 *
 * Two layers live in this class:
 *
 *  1. Static textbook primitives: hash(), highestPower(), roll(), findAll().
 *
 *  2. A reusable detector (instance) that holds
 *       - direct SIGNATURES  (e.g. "ignore all previous instructions"), and
 *       - PROXIMITY RULES    (e.g. "dissolve" + "acid" within 5 words),
 *     and evaluates all of them against a prompt with rolling hashes only.
 *
 * ---------------------------------------------------------------------
 * Hash design (integer-overflow safety)
 * ---------------------------------------------------------------------
 *   H(s[0..m-1]) = ( s[0]*B^(m-1) + s[1]*B^(m-2) + ... + s[m-1] ) mod P
 *   P = 1_000_000_007  (prime, < 2^30)      B = 257 (> 256 symbols, so
 *   Latin-1 characters never alias each other before the modulus).
 *   Every intermediate product is at most (P-1)*65535 < 2^46, so plain
 *   Java 64-bit `long` arithmetic can NEVER overflow. Reducing mod P after
 *   each step keeps the stored hash inside the positive int range.
 *   (A 32-bit `int` would overflow as soon as P*B exceeds 2^31.)
 *
 * Rolling update (slide the window one character right, O(1)):
 *   H' = ( (H - out * B^(m-1)) * B + in ) mod P
 *
 * Correctness: equal hashes are only a CANDIDATE. Every candidate is
 * verified character by character, so there are zero false positives.
 *
 * ---------------------------------------------------------------------
 * Complexity (N = text length, M = pattern length, P_n = patterns,
 *             d = distinct pattern lengths, R = proximity rules)
 * ---------------------------------------------------------------------
 *   hash(pattern), highestPower      O(M)
 *   roll                             O(1)
 *   findAll(text, pattern)           O(N + M) expected; the O(M) verify runs
 *                                    only when hashes are equal. Worst case O(N*M)
 *                                    if an attacker engineers collisions.
 *   build() (lazy, once)             O(sum of pattern lengths)
 *   analyze(text)                    O(N) normalise + O(d * N) rolling passes
 *                                    (one pass per distinct length, O(1) table
 *                                    lookup per window) + O(occurrences) for the
 *                                    proximity merge. d is tiny, so effectively O(N).
 *
 * Thread-safety: register signatures/rules at startup, then call analyze()
 * from any number of background threads (analyze keeps only local state).
 */
public class KarpRabinHash {

    /** Prime modulus. */
    public static final long MOD = 1_000_000_007L;
    /** Base, larger than the Latin-1 alphabet. */
    public static final long BASE = 257L;

    // ==================================================================
    // 1. Static primitives
    // ==================================================================

    /** Polynomial hash of a whole string. O(M). */
    public static long hash(CharSequence s) {
        long h = 0;
        for (int i = 0; i < s.length(); i++) {
            h = (h * BASE + s.charAt(i)) % MOD;
        }
        return h;
    }

    /** BASE^(length-1) mod MOD: the weight of the character that leaves the window. O(M). */
    public static long highestPower(int length) {
        long p = 1;
        for (int i = 1; i < length; i++) {
            p = (p * BASE) % MOD;
        }
        return p;
    }

    /** Slides the window one position: drop {@code out}, append {@code in}. O(1). */
    public static long roll(long h, char out, char in, long highPow) {
        long removed = (h - (out * highPow) % MOD + MOD) % MOD;   // never negative
        return (removed * BASE + in) % MOD;
    }

    /**
     * Textbook Rabin-Karp: every start offset where pattern occurs in text
     * (exact, case-sensitive, no word-boundary rule). Overlaps are reported.
     * Expected O(N + M).
     */
    public static int[] findAll(String text, String pattern) {
        IntList out = new IntList();
        int n = text.length();
        int m = pattern.length();
        if (m == 0 || m > n) {
            return out.toArray();
        }
        long patHash = hash(pattern);
        long highPow = highestPower(m);
        long win = 0;
        for (int i = 0; i < m; i++) {                      // first window: O(M)
            win = (win * BASE + text.charAt(i)) % MOD;
        }
        for (int i = 0; ; i++) {                           // N-M+1 windows, O(1) each
            if (win == patHash && matchesAt(text, i, pattern)) {
                out.add(i);
            }
            if (i + m >= n) {
                break;
            }
            win = roll(win, text.charAt(i), text.charAt(i + m), highPow);
        }
        return out.toArray();
    }

    /** Character-by-character verification of a hash candidate. O(M). */
    private static boolean matchesAt(String text, int at, String pattern) {
        for (int k = 0; k < pattern.length(); k++) {
            if (text.charAt(at + k) != pattern.charAt(k)) {
                return false;
            }
        }
        return true;
    }

    // ==================================================================
    // 2. Result types
    // ==================================================================

    /** A direct signature found in the (normalised) prompt. */
    public static final class SignatureHit {
        public final String pattern;
        public final String label;
        public final int start;       // inclusive, offset in normalised text
        public final int end;         // exclusive

        SignatureHit(String pattern, String label, int start, int end) {
            this.pattern = pattern;
            this.label = label;
            this.start = start;
            this.end = end;
        }

        @Override
        public String toString() {
            return "SIGNATURE \"" + pattern + "\" [" + label + ", @" + start + "-" + end + "]";
        }
    }

    /** A proximity rule that fired: both terms present within the allowed word gap. */
    public static final class ProximityHit {
        public final String termA;
        public final String termB;
        public final String label;
        public final int wordGap;         // closest observed gap = words BETWEEN the two terms
        public final int maxWordGap;      // the rule's window
        public final int bonusScore;

        ProximityHit(String termA, String termB, String label, int wordGap, int maxWordGap, int bonusScore) {
            this.termA = termA;
            this.termB = termB;
            this.label = label;
            this.wordGap = wordGap;
            this.maxWordGap = maxWordGap;
            this.bonusScore = bonusScore;
        }

        @Override
        public String toString() {
            return "PROXIMITY \"" + termA + "\" + \"" + termB + "\" [" + label + ", gap=" + wordGap
                    + " <= " + maxWordGap + " words, +" + bonusScore + "]";
        }
    }

    /** Everything analyze() found. */
    public static final class Report {
        public final String normalizedText;
        public final List<SignatureHit> signatureHits;
        public final List<ProximityHit> proximityHits;

        Report(String normalizedText, List<SignatureHit> signatureHits, List<ProximityHit> proximityHits) {
            this.normalizedText = normalizedText;
            this.signatureHits = Collections.unmodifiableList(signatureHits);
            this.proximityHits = Collections.unmodifiableList(proximityHits);
        }

        public boolean hasDirectSignature() {
            return !signatureHits.isEmpty();
        }

        /** Sum of the bonus scores of all fired proximity rules. */
        public int proximityScore() {
            int s = 0;
            for (ProximityHit h : proximityHits) {
                s += h.bonusScore;
            }
            return s;
        }
    }

    // ==================================================================
    // 3. Detector configuration
    // ==================================================================

    private static final class Signature {
        final int id;
        final String pattern;         // normalised
        String label;
        boolean direct;               // true => reported as a SignatureHit

        Signature(int id, String pattern, String label, boolean direct) {
            this.id = id;
            this.pattern = pattern;
            this.label = label;
            this.direct = direct;
        }
    }

    private static final class Rule {
        final int sigA;
        final int sigB;
        final int maxWordGap;
        final int bonusScore;
        final String label;

        Rule(int sigA, int sigB, int maxWordGap, int bonusScore, String label) {
            this.sigA = sigA;
            this.sigB = sigB;
            this.maxWordGap = maxWordGap;
            this.bonusScore = bonusScore;
            this.label = label;
        }
    }

    /**
     * All signatures of ONE length. A rolling window has a fixed width, so
     * patterns are grouped by length; each group owns a small chained hash
     * table: hash value -> candidate signature ids (O(1) average lookup).
     */
    private static final class Group {
        final int length;
        final long highPow;
        int[] sigIds = new int[4];
        long[] hashes = new long[4];
        int size = 0;
        int[] buckets;               // bucket -> first entry index, -1 = empty
        int[] next;                  // entry -> next entry in the chain
        int mask;

        Group(int length) {
            this.length = length;
            this.highPow = highestPower(length);
        }

        void add(int sigId, long h) {
            if (size == sigIds.length) {                    // amortised O(1) growth
                int[] ids = new int[size * 2];
                long[] hs = new long[size * 2];
                System.arraycopy(sigIds, 0, ids, 0, size);
                System.arraycopy(hashes, 0, hs, 0, size);
                sigIds = ids;
                hashes = hs;
            }
            sigIds[size] = sigId;
            hashes[size] = h;
            size++;
        }

        /** Builds the chained table after all patterns are known. O(size). */
        void seal() {
            int cap = 1;
            while (cap < size * 2) {
                cap <<= 1;
            }
            buckets = new int[cap];
            for (int i = 0; i < cap; i++) {
                buckets[i] = -1;
            }
            next = new int[size];
            mask = cap - 1;
            for (int e = 0; e < size; e++) {
                int b = (int) (hashes[e] & mask);
                next[e] = buckets[b];
                buckets[b] = e;
            }
        }
    }

    private final List<Signature> signatures = new ArrayList<>();
    private final List<Rule> rules = new ArrayList<>();
    private volatile Group[] groups = new Group[0];
    private volatile boolean built = true;                  // nothing to build yet

    // ------------------------------------------------------------------
    // Registration (startup only)
    // ------------------------------------------------------------------

    /**
     * Registers a direct injection signature, e.g. "ignore all previous instructions".
     * The pattern is normalised exactly like prompts (lower-case, single spaces).
     * Time: O(M) + O(P_n) duplicate check.
     *
     * @return the signature id, or -1 if the pattern is blank
     */
    public int addSignature(String pattern, String label) {
        return register(pattern, label, true);
    }

    /**
     * Registers a proximity rule: fire when termA and termB both occur and at
     * most {@code maxWordGap} words separate them, in either order.
     *
     * Example: ("dissolve", "acid", 5, 4, ...) fires on
     *   "dissolve a 60 kg chicken in acid"  (5 words between: a, 60, kg, chicken, in).
     *
     * @return false if a term is blank, both terms are identical, or numbers are negative
     */
    public boolean addProximityRule(String termA, String termB, int maxWordGap, int bonusScore, String label) {
        if (maxWordGap < 0 || bonusScore < 0) {
            return false;
        }
        int a = register(termA, null, false);
        int b = register(termB, null, false);
        if (a < 0 || b < 0 || a == b) {
            return false;
        }
        rules.add(new Rule(a, b, maxWordGap, bonusScore, label == null ? "PROXIMITY" : label));
        return true;
    }

    private int register(String pattern, String label, boolean direct) {
        String p = WeightedTrie.normalize(pattern);
        if (p.isEmpty()) {
            return -1;
        }
        for (Signature s : signatures) {                    // dedupe, O(P_n)
            if (s.pattern.equals(p)) {
                if (direct && label != null) {
                    s.label = label;                        // a direct signature's label wins
                }
                s.direct |= direct;
                built = false;
                return s.id;
            }
        }
        Signature s = new Signature(signatures.size(), p, label == null ? "SIGNATURE" : label, direct);
        signatures.add(s);
        built = false;
        return s.id;
    }

    /** Groups signatures by length and seals each hash table. O(sum of pattern lengths). */
    private synchronized void build() {
        if (built) {
            return;
        }
        List<Group> list = new ArrayList<>();
        for (Signature s : signatures) {
            int len = s.pattern.length();
            Group g = null;
            for (Group candidate : list) {
                if (candidate.length == len) {
                    g = candidate;
                    break;
                }
            }
            if (g == null) {
                g = new Group(len);
                list.add(g);
            }
            g.add(s.id, hash(s.pattern));
        }
        for (Group g : list) {
            g.seal();
        }
        groups = list.toArray(new Group[0]);
        built = true;
    }

    // ==================================================================
    // 4. Analysis
    // ==================================================================

    /**
     * Scans a prompt for every registered signature and proximity rule.
     * Offsets in the report refer to {@code normalizedText}, not the raw input.
     */
    public Report analyze(String text) {
        String norm = WeightedTrie.normalize(text);
        if (!built) {
            build();
        }
        Group[] gs = groups;
        IntList[] occ = new IntList[signatures.size()];     // occurrences per signature id

        for (Group g : gs) {                                // O(d * N)
            scanGroup(norm, g, occ);
        }

        // ---- direct signatures
        List<SignatureHit> sigHits = new ArrayList<>();
        for (Signature s : signatures) {
            IntList o = occ[s.id];
            if (s.direct && o != null) {
                for (int k = 0; k < o.size(); k++) {
                    int start = o.get(k);
                    sigHits.add(new SignatureHit(s.pattern, s.label, start, start + s.pattern.length()));
                }
            }
        }
        sigHits.sort((x, y) -> Integer.compare(x.start, y.start));

        // ---- proximity rules
        List<ProximityHit> proxHits = new ArrayList<>();
        int[] spaces = null;                                // lazily built word index table
        for (Rule r : rules) {
            IntList a = occ[r.sigA];
            IntList b = occ[r.sigB];
            if (a == null || b == null) {
                continue;                                   // one of the terms is absent
            }
            if (spaces == null) {
                spaces = spacePrefix(norm);                 // O(N), once
            }
            int gap = minWordGap(a, signatures.get(r.sigA).pattern.length(),
                                 b, signatures.get(r.sigB).pattern.length(), spaces);
            if (gap <= r.maxWordGap) {
                proxHits.add(new ProximityHit(signatures.get(r.sigA).pattern, signatures.get(r.sigB).pattern,
                        r.label, gap, r.maxWordGap, r.bonusScore));
            }
        }
        return new Report(norm, sigHits, proxHits);
    }

    /**
     * One rolling pass of window width g.length over the text.
     * Every window costs O(1): update the hash, look it up in the chained
     * table, and verify only real candidates.
     */
    private void scanGroup(String text, Group g, IntList[] occ) {
        int n = text.length();
        int len = g.length;
        if (len > n) {
            return;
        }
        long win = 0;
        for (int i = 0; i < len; i++) {
            win = (win * BASE + text.charAt(i)) % MOD;
        }
        for (int i = 0; ; i++) {
            for (int e = g.buckets[(int) (win & g.mask)]; e != -1; e = g.next[e]) {
                if (g.hashes[e] != win) {
                    continue;                               // different hash in same bucket
                }
                int id = g.sigIds[e];
                String pat = signatures.get(id).pattern;
                if (matchesAt(text, i, pat) && onWordBoundaries(text, i, i + len)) {
                    if (occ[id] == null) {
                        occ[id] = new IntList();
                    }
                    occ[id].add(i);
                }
            }
            if (i + len >= n) {
                break;
            }
            win = roll(win, text.charAt(i), text.charAt(i + len), g.highPow);
        }
    }

    /** A hit must not start or end inside a word ("acid" must not match "placid"). O(1). */
    private static boolean onWordBoundaries(String s, int start, int end) {
        boolean startOk = start == 0
                || !Character.isLetterOrDigit(s.charAt(start - 1))
                || !Character.isLetterOrDigit(s.charAt(start));
        boolean endOk = end == s.length()
                || !Character.isLetterOrDigit(s.charAt(end - 1))
                || !Character.isLetterOrDigit(s.charAt(end));
        return startOk && endOk;
    }

    /** spaces[i] = number of ' ' characters before offset i, i.e. the word index at i. O(N). */
    private static int[] spacePrefix(String norm) {
        int[] p = new int[norm.length() + 1];
        for (int i = 0; i < norm.length(); i++) {
            p[i + 1] = p[i] + (norm.charAt(i) == ' ' ? 1 : 0);
        }
        return p;
    }

    /**
     * Smallest number of words BETWEEN an occurrence of A and an occurrence of B
     * (either order). Both lists are sorted by offset, so a two-pointer merge
     * examines every neighbouring pair in O(|A| + |B|).
     * Overlapping/adjacent terms give 0.
     */
    private static int minWordGap(IntList a, int lenA, IntList b, int lenB, int[] spaces) {
        int best = Integer.MAX_VALUE;
        int i = 0;
        int j = 0;
        while (i < a.size() && j < b.size()) {
            int sa = a.get(i);
            int sb = b.get(j);
            if (sa <= sb) {
                best = Math.min(best, gapBetween(sa, lenA, sb, spaces));
                i++;                                        // advance the earlier occurrence
            } else {
                best = Math.min(best, gapBetween(sb, lenB, sa, spaces));
                j++;
            }
        }
        return best;
    }

    /** Words strictly between the end of the earlier term and the start of the later one. O(1). */
    private static int gapBetween(int firstStart, int firstLen, int secondStart, int[] spaces) {
        int firstEndWord = spaces[firstStart + firstLen - 1];   // word index of its last character
        int secondStartWord = spaces[secondStart];
        return Math.max(0, secondStartWord - firstEndWord - 1);
    }

    public int signatureCount() { return signatures.size(); }
    public int ruleCount()      { return rules.size(); }
}
