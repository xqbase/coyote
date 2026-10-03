package com.xqbase.coyote.util;

import java.util.Iterator;
import java.util.LinkedHashMap;

import com.xqbase.metric.common.Metric;

public class TimeoutMap<K, V> {
	class TimeoutEntry {
		V value;
		long expire;
	}

	private long accessed = 0;
	private int timeout, interval;
	private boolean accessOrder;
	private LinkedHashMap<K, TimeoutEntry> map;
	private int size;

	public TimeoutMap(int timeout, int interval) {
		this(timeout, interval, false);
	}

	public TimeoutMap(int timeout, int interval, boolean accessOrder) {
		this.timeout = timeout;
		this.interval = interval;
		this.accessOrder = accessOrder;
		map = new LinkedHashMap<>(16, 0.75f, accessOrder);
	}

	private V get_(K key) {
		TimeoutEntry entry = map.get(key);
		if (entry == null) {
			return null;
		}
		if (accessOrder) {
			entry.expire = System.currentTimeMillis() + timeout;
		}
		return entry.value;
	}

	private void put_(K key, V value) {
		TimeoutEntry entry = new TimeoutEntry();
		entry.value = value;
		entry.expire = System.currentTimeMillis() + timeout;
		int incr = 0;
		if (!accessOrder) {
			incr = map.remove(key) == null ? 0 : -1;
		}
		incr += map.put(key, entry) == null ? 1 : 0;
		size += incr;
		Metric.put("xqbase-coyote.timeout-map.incr", incr, "method", "put");
	}

	private V remove_(K key) {
		TimeoutEntry entry = map.remove(key);
		int incr = entry == null ? 0 : -1;
		size += incr;
		Metric.put("xqbase-coyote.timeout-map.incr", incr, "method", "remove");
		return entry == null ? null : entry.value;
	}

	private void expire() {
		long now = System.currentTimeMillis();
		if (now < accessed + interval) {
			return;
		}
		accessed = now;
		Iterator<TimeoutEntry> i = map.values().iterator();
		int incr = 0;
		while (i.hasNext() && now > i.next().expire) {
			i.remove();
			incr --;
		}
		size += incr;
		Metric.put("xqbase-coyote.timeout-map.incr", incr, "method", "expire");
		Metric.put("xqbase-coyote.timeout-map.size", size, "deviation", "" + (size - map.size()));
	}

	public synchronized V get(K key) {
		return get_(key);
	}

	public synchronized V expireAndGet(K key) {
		expire();
		return get_(key);
	}

	public synchronized void put(K key, V value) {
		put_(key, value);
	}

	public synchronized void expireAndPut(K key, V value) {
		expire();
		put_(key, value);
	}

	public synchronized V remove(K key) {
		return remove_(key);
	}

	public synchronized V expireAndRemove(K key) {
		expire();
		return remove_(key);
	}
}