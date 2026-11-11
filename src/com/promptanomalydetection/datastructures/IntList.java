package com.promptanomalydetection.datastructures;

/**
 * IntList - minimal growable array of primitive ints (no boxing, no java.util).
 *
 * Complexity (N = current size):
 *   add       O(1) amortised (capacity doubles; one O(N) copy per doubling)
 *   get       O(1)
 *   size      O(1)
 *   toArray   O(N)
 * Space: O(capacity), at most twice the number of stored values.
 *
 * Not thread-safe; callers synchronise externally.
 */
public final class IntList {

    private int[] data;
    private int size = 0;

    public IntList() {
        this(8);
    }

    public IntList(int initialCapacity) {
        data = new int[Math.max(initialCapacity, 1)];
    }

    public void add(int value) {
        if (size == data.length) {
            int[] bigger = new int[size * 2];
            System.arraycopy(data, 0, bigger, 0, size);
            data = bigger;
        }
        data[size++] = value;
    }

    public int get(int index) {
        if (index < 0 || index >= size) {
            throw new IndexOutOfBoundsException("index " + index + ", size " + size);
        }
        return data[index];
    }

    public int size() {
        return size;
    }

    public boolean isEmpty() {
        return size == 0;
    }

    /** Defensive copy of the stored values. */
    public int[] toArray() {
        int[] copy = new int[size];
        System.arraycopy(data, 0, copy, 0, size);
        return copy;
    }
}
