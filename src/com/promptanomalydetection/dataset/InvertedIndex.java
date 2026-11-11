package com.promptanomalydetection.dataset;

import com.promptanomalydetection.datastructures.WeightedTrie;

import java.util.Locale;

/**
 * InvertedIndex - a custom dictionary: threat category ID -> array of synonymous terms.
 *
 * Example: CAT_CHEMICAL_DESTRUCTION -> {"dissolve", "liquefy", "corrosive", ...}
 *
 * Implementation: a hand-written hash table (separate chaining, power-of-two
 * capacity, resize at load factor 0.75). Each chain entry owns a growable
 * String[] (capacity doubling), so no java.util collections are used.
 *
 * Complexity (C = number of categories, M = terms in one category):
 *   find / hasCategory      O(1) average, O(C) worst case (all keys collide)
 *   addTerm                 O(1) average to locate the category + O(M) duplicate check
 *                           + O(1) amortised append (array doubling)
 *   getTerms                O(M) (defensive copy)
 *   containsTerm            O(1) average + O(M) scan
 *   resize                  O(C), amortised O(1) per insertion
 *   categoryIds             O(table size + C)
 * Space: O(C + total terms).
 *
 * NOT thread-safe for concurrent writes; populate at startup, then read-only.
 */
public class InvertedIndex {

    private static final int INITIAL_CAPACITY = 16;        // must stay a power of two
    private static final double MAX_LOAD_FACTOR = 0.75;
    private static final int INITIAL_TERM_CAPACITY = 4;

    /** Chain node: one category and its growable term array. */
    private static final class CategoryEntry {
        final String categoryId;
        String[] terms = new String[INITIAL_TERM_CAPACITY];
        int termCount = 0;
        CategoryEntry next;                                  // separate-chaining link

        CategoryEntry(String categoryId) {
            this.categoryId = categoryId;
        }
    }

    private CategoryEntry[] table = new CategoryEntry[INITIAL_CAPACITY];
    private int categoryCount = 0;
    private int totalTerms = 0;

    // ------------------------------------------------------------------
    // Key normalisation and hashing
    // ------------------------------------------------------------------

    /** "cat chemical" / " cat_chemical " -> "CAT_CHEMICAL"; blank -> null. O(L). */
    public static String normalizeCategory(String categoryId) {
        if (categoryId == null) {
            return null;
        }
        String t = categoryId.trim();
        if (t.isEmpty()) {
            return null;
        }
        return t.replaceAll("\\s+", "_").toUpperCase(Locale.ROOT);
    }

    /** Polynomial rolling hash (base 31) with a high-bit spread. O(L). */
    private static int hash(String key) {
        int h = 0;
        for (int i = 0; i < key.length(); i++) {
            h = 31 * h + key.charAt(i);
        }
        return h ^ (h >>> 16);
    }

    /** Bucket index; works because capacity is a power of two. O(1). */
    private static int indexFor(int hash, int capacity) {
        return hash & (capacity - 1);
    }

    // ------------------------------------------------------------------
    // Internal table operations
    // ------------------------------------------------------------------

    /** Walks one bucket chain. O(1) average, O(C) worst case. */
    private CategoryEntry find(String normalizedCategory) {
        CategoryEntry e = table[indexFor(hash(normalizedCategory), table.length)];
        while (e != null) {
            if (e.categoryId.equals(normalizedCategory)) {
                return e;
            }
            e = e.next;
        }
        return null;
    }

    private CategoryEntry findOrCreate(String normalizedCategory) {
        CategoryEntry e = find(normalizedCategory);
        if (e != null) {
            return e;
        }
        if (categoryCount + 1 > table.length * MAX_LOAD_FACTOR) {
            resize();
        }
        int idx = indexFor(hash(normalizedCategory), table.length);
        e = new CategoryEntry(normalizedCategory);
        e.next = table[idx];                                 // insert at chain head, O(1)
        table[idx] = e;
        categoryCount++;
        return e;
    }

    /** Doubles the table and relinks every existing entry. O(C). */
    private void resize() {
        CategoryEntry[] old = table;
        CategoryEntry[] bigger = new CategoryEntry[old.length * 2];
        for (CategoryEntry head : old) {
            CategoryEntry e = head;
            while (e != null) {
                CategoryEntry nextInChain = e.next;
                int idx = indexFor(hash(e.categoryId), bigger.length);
                e.next = bigger[idx];
                bigger[idx] = e;
                e = nextInChain;
            }
        }
        table = bigger;
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Adds a synonymous term under a category (creating the category if needed).
     * Terms are normalised the same way as in WeightedTrie, and duplicates are ignored.
     *
     * @return true if the term was newly added
     */
    public boolean addTerm(String categoryId, String term) {
        String cat = normalizeCategory(categoryId);
        String t = WeightedTrie.normalize(term);
        if (cat == null || t.isEmpty()) {
            return false;
        }
        CategoryEntry e = findOrCreate(cat);
        for (int i = 0; i < e.termCount; i++) {              // O(M) duplicate check
            if (e.terms[i].equals(t)) {
                return false;
            }
        }
        if (e.termCount == e.terms.length) {                 // grow: amortised O(1)
            String[] bigger = new String[e.terms.length * 2];
            System.arraycopy(e.terms, 0, bigger, 0, e.termCount);
            e.terms = bigger;
        }
        e.terms[e.termCount++] = t;
        totalTerms++;
        return true;
    }

    /** Copy of the synonym array for a category (empty array if unknown). O(M). */
    public String[] getTerms(String categoryId) {
        String cat = normalizeCategory(categoryId);
        CategoryEntry e = (cat == null) ? null : find(cat);
        if (e == null) {
            return new String[0];
        }
        String[] copy = new String[e.termCount];
        System.arraycopy(e.terms, 0, copy, 0, e.termCount);
        return copy;
    }

    public boolean hasCategory(String categoryId) {
        String cat = normalizeCategory(categoryId);
        return cat != null && find(cat) != null;
    }

    /** True if the category contains this exact (normalised) term. O(1) avg + O(M). */
    public boolean containsTerm(String categoryId, String term) {
        String cat = normalizeCategory(categoryId);
        CategoryEntry e = (cat == null) ? null : find(cat);
        if (e == null) {
            return false;
        }
        String t = WeightedTrie.normalize(term);
        for (int i = 0; i < e.termCount; i++) {
            if (e.terms[i].equals(t)) {
                return true;
            }
        }
        return false;
    }

    /** All category IDs (unspecified order). O(table size + C). */
    public String[] categoryIds() {
        String[] ids = new String[categoryCount];
        int k = 0;
        for (CategoryEntry head : table) {
            for (CategoryEntry e = head; e != null; e = e.next) {
                ids[k++] = e.categoryId;
            }
        }
        return ids;
    }

    public int categoryCount() { return categoryCount; }
    public int termCount()     { return totalTerms; }
}
