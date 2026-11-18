package com.promptanomalydetection.algorithms;

/**
 * ZScoreCalculator - statistical anomaly engine for Prompt Anomaly and Malicious Detection.
 *
 * Idea: ordinary prompts have a typical character-entropy and a typical
 * length. Encoded payloads (Base64, hex, ciphers) use many different symbols
 * almost uniformly, so their Shannon entropy jumps far above the baseline;
 * floods such as "aaaaaaaa..." collapse it far below. The Z-score says how
 * many standard deviations an observation lies from the baseline mean:
 *
 *        Z = (X - mu) / sigma
 *
 * Shannon entropy of a string (bits per character):
 *
 *        H = - SUM over distinct chars c of  p(c) * log2( p(c) ),   p(c) = count(c) / N
 *
 * Small-sample correction (Miller-Madow): the plain estimate is biased LOW on
 * short strings, and the bias grows with the number of distinct characters A,
 * which is exactly what short encoded payloads have. So the Z-score uses
 *
 *        H_corrected = H + (A - 1) / (2 * N * ln 2)
 *
 * On a quick check, benign English prompts (38-98 chars) score 4.1-4.5 bits
 * corrected, while Base64 payloads of 43-104 chars score 5.2-5.4 bits.
 *
 * Complexity (N = text length, A = distinct characters, S = baseline samples):
 *   shannonEntropy(text)   O(N + A)   one counting pass + one pass over the distinct
 *   correctedEntropy(text)            characters (A <= min(N, 65536); space O(A)).
 *   zScore(x, mu, sigma)   O(1)
 *   analyze(text)          O(N + A)   -- far below a millisecond for chat-sized prompts
 *   Baseline.fit(samples)  O(total characters) -- single pass, Welford's online mean/variance
 *
 * Instances are immutable, so one calculator can be shared by many
 * background threads.
 *
 * IMPORTANT - calibration: the default baseline below is a reasonable
 * starting point for short English chat prompts, NOT a measured corpus
 * statistic. For the report/demo, call Baseline.fit(...) on your offline
 * benign sample (e.g. the benign half of WildChat) and use that baseline.
 */
public class ZScoreCalculator {

    /** Z at or above which a feature is considered anomalous (spec: +3.5). */
    public static final double DEFAULT_THRESHOLD = 3.5;

    /**
     * Below this length a low entropy is meaningless ("hi" has tiny entropy),
     * so the LOW_ENTROPY (flood) rule only applies from this length upward.
     */
    public static final int MIN_LENGTH_FOR_LOW_ENTROPY = 32;

    private static final double LN2 = Math.log(2.0);

    // ==================================================================
    // Baseline
    // ==================================================================

    /** Offline mean / standard deviation of the two monitored features. */
    public static final class Baseline {
        public final double meanEntropy;
        public final double stdEntropy;
        public final double meanLength;
        public final double stdLength;

        public Baseline(double meanEntropy, double stdEntropy, double meanLength, double stdLength) {
            if (!(stdEntropy > 0) || !(stdLength > 0)
                    || Double.isInfinite(stdEntropy) || Double.isInfinite(stdLength)) {
                throw new IllegalArgumentException("standard deviations must be finite and > 0");
            }
            this.meanEntropy = meanEntropy;
            this.stdEntropy = stdEntropy;
            this.meanLength = meanLength;
            this.stdLength = stdLength;
        }

        /**
         * Starting values for short English chat prompts, in CORRECTED bits/char.
         * Entropy: mean 4.25 measured on 11 hand-written prompts (std 0.11),
         * with sigma deliberately widened to 0.25 because 11 samples understate
         * real variety. Length: mean 150 / std 200 chars is a rough guess for chat.
         * Replace both with Baseline.fit(...) on your offline corpus.
         */
        public static Baseline defaults() {
            return new Baseline(4.25, 0.25, 150.0, 200.0);
        }

        /**
         * Learns the baseline from benign sample prompts using Welford's
         * single-pass algorithm (numerically stable, O(total characters), O(1) extra space).
         * Uses the sample standard deviation (n - 1).
         *
         * @throws IllegalArgumentException if fewer than 2 samples or no variance
         */
        public static Baseline fit(Iterable<String> samples) {
            long n = 0;
            double meanH = 0, m2H = 0;
            double meanL = 0, m2L = 0;
            for (String s : samples) {
                if (s == null) {
                    continue;
                }
                n++;
                double h = correctedEntropy(s);
                double dh = h - meanH;
                meanH += dh / n;
                m2H += dh * (h - meanH);

                double len = s.length();
                double dl = len - meanL;
                meanL += dl / n;
                m2L += dl * (len - meanL);
            }
            if (n < 2) {
                throw new IllegalArgumentException("need at least 2 samples to fit a baseline");
            }
            return new Baseline(meanH, Math.sqrt(m2H / (n - 1)), meanL, Math.sqrt(m2L / (n - 1)));
        }
    }

    // ==================================================================
    // Result
    // ==================================================================

    /** Full statistical verdict for one prompt. */
    public static final class Analysis {
        public final int length;
        public final double entropy;       // corrected bits per character
        public final double entropyZ;
        public final double lengthZ;
        /** Magnitude of the worst applicable deviation: the single number to show in the UI. */
        public final double anomalyZ;
        public final boolean anomalous;
        /** "NONE", "HIGH_ENTROPY", "LOW_ENTROPY" or "LENGTH_SPIKE". */
        public final String reason;

        Analysis(int length, double entropy, double entropyZ, double lengthZ,
                 double anomalyZ, boolean anomalous, String reason) {
            this.length = length;
            this.entropy = entropy;
            this.entropyZ = entropyZ;
            this.lengthZ = lengthZ;
            this.anomalyZ = anomalyZ;
            this.anomalous = anomalous;
            this.reason = reason;
        }

        @Override
        public String toString() {
            return String.format("len=%d H=%.3f bits  Z(entropy)=%+.2f  Z(length)=%+.2f  anomalyZ=%+.2f  %s",
                    length, entropy, entropyZ, lengthZ, anomalyZ, anomalous ? "ANOMALOUS:" + reason : "normal");
        }
    }

    private final Baseline baseline;
    private final double threshold;

    public ZScoreCalculator() {
        this(Baseline.defaults(), DEFAULT_THRESHOLD);
    }

    public ZScoreCalculator(Baseline baseline, double threshold) {
        if (baseline == null || !(threshold > 0)) {
            throw new IllegalArgumentException("baseline required and threshold must be > 0");
        }
        this.baseline = baseline;
        this.threshold = threshold;
    }

    // ==================================================================
    // Z-score
    // ==================================================================

    /** Z = (x - mean) / std. O(1). */
    public static double zScore(double x, double mean, double std) {
        if (!(std > 0)) {
            throw new IllegalArgumentException("std must be > 0");
        }
        return (x - mean) / std;
    }

    /** Z-score of the prompt's (corrected) character entropy against the baseline. O(N + A). */
    public double entropyZ(String text) {
        return zScore(correctedEntropy(text), baseline.meanEntropy, baseline.stdEntropy);
    }

    /** Z-score of the prompt's length against the baseline. O(1). */
    public double lengthZ(String text) {
        int len = text == null ? 0 : text.length();
        return zScore(len, baseline.meanLength, baseline.stdLength);
    }

    /**
     * Computes both Z-scores and the verdict:
     *   HIGH_ENTROPY  entropyZ >= threshold                         (Base64 / cipher payloads)
     *   LOW_ENTROPY   entropyZ <= -threshold and length >= 32       (character floods)
     *   LENGTH_SPIKE  lengthZ  >= threshold                         (abnormally long input)
     * Time: O(N + A).
     */
    public Analysis analyze(String text) {
        String s = text == null ? "" : text;
        int len = s.length();
        double h = correctedEntropy(s);
        double zE = zScore(h, baseline.meanEntropy, baseline.stdEntropy);
        double zL = zScore(len, baseline.meanLength, baseline.stdLength);

        boolean lowEligible = len >= MIN_LENGTH_FOR_LOW_ENTROPY;
        String reason = "NONE";
        if (zE >= threshold) {
            reason = "HIGH_ENTROPY";
        } else if (lowEligible && zE <= -threshold) {
            reason = "LOW_ENTROPY";
        } else if (zL >= threshold) {
            reason = "LENGTH_SPIKE";
        }

        double worst = Math.max(zE, zL);
        if (lowEligible) {
            worst = Math.max(worst, -zE);
        }
        return new Analysis(len, h, zE, zL, worst, !reason.equals("NONE"), reason);
    }

    // ==================================================================
    // Shannon entropy
    // ==================================================================

    /**
     * Plain (maximum-likelihood) Shannon entropy in bits per character.
     * 0 for empty or single-symbol text; log2(A) at most. Any UTF-16 char works.
     * Time O(N + A), space O(A).
     */
    public static double shannonEntropy(CharSequence s) {
        return entropyOf(s, false);
    }

    /** Shannon entropy plus the Miller-Madow bias correction (A - 1) / (2 N ln 2). O(N + A). */
    public static double correctedEntropy(CharSequence s) {
        return entropyOf(s, true);
    }

    private static double entropyOf(CharSequence s, boolean correct) {
        int n = (s == null) ? 0 : s.length();
        if (n == 0) {
            return 0.0;
        }
        CharCounter counter = new CharCounter();
        for (int i = 0; i < n; i++) {                       // pass 1: frequencies, O(N)
            counter.add(s.charAt(i));
        }
        double h = counter.entropy(n);                      // pass 2: O(A)
        if (correct) {
            h += (counter.distinct - 1) / (2.0 * n * LN2);
        }
        return h;
    }

    /**
     * Frequency table: a flat int[256] for Latin-1 (the common case, O(1)
     * and cache friendly) plus a tiny open-addressing hash table for rarer
     * characters, so a 64K-entry array never has to be allocated per call.
     */
    private static final class CharCounter {
        private final int[] low = new int[256];
        private char[] highKeys;
        private int[] highCounts;                           // 0 marks an empty slot
        private int highSize = 0;
        int distinct = 0;                                   // set by entropy()

        void add(char c) {
            if (c < 256) {
                low[c]++;
                return;
            }
            if (highKeys == null) {
                highKeys = new char[16];
                highCounts = new int[16];
            }
            int i = slot(c);
            if (highCounts[i] == 0) {                       // new character
                if ((highSize + 1) * 2 > highKeys.length) { // keep load factor <= 0.5
                    grow();
                    i = slot(c);
                }
                highKeys[i] = c;
                highSize++;
            }
            highCounts[i]++;
        }

        /** Linear probing: slot holding c, or the empty slot where c belongs. */
        private int slot(char c) {
            int mask = highKeys.length - 1;
            int i = (c * 0x9E37) & mask;
            while (highCounts[i] != 0 && highKeys[i] != c) {
                i = (i + 1) & mask;
            }
            return i;
        }

        private void grow() {
            char[] oldKeys = highKeys;
            int[] oldCounts = highCounts;
            highKeys = new char[oldKeys.length * 2];
            highCounts = new int[oldKeys.length * 2];
            for (int k = 0; k < oldKeys.length; k++) {
                if (oldCounts[k] != 0) {
                    int i = slot(oldKeys[k]);
                    highKeys[i] = oldKeys[k];
                    highCounts[i] = oldCounts[k];
                }
            }
        }

        double entropy(int n) {
            double h = 0.0;
            distinct = 0;
            for (int count : low) {
                if (count > 0) {
                    distinct++;
                }
                h -= term(count, n);
            }
            if (highCounts != null) {
                for (int count : highCounts) {
                    if (count > 0) {
                        distinct++;
                    }
                    h -= term(count, n);
                }
            }
            return Math.max(0.0, h);                        // removes -0.0 for single-symbol text
        }

        /** p * log2(p) for one symbol; 0 for absent symbols. */
        private static double term(int count, int n) {
            if (count == 0) {
                return 0.0;
            }
            double p = (double) count / n;
            return p * (Math.log(p) / LN2);
        }
    }
}
