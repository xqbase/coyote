package com.xqbase.coyote.util;

import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Log {
	private static AtomicReference<Logger> logger_ =
			new AtomicReference<>(Logger.getAnonymousLogger());

	public static Logger getAndSet(Logger logger) {
		return logger_.getAndSet(logger);
	}

	private static void log(Level l, String s, Throwable t) {
		StackTraceElement ste = new Throwable().getStackTrace()[2];
		logger_.get().logp(l, ste.getClassName(), ste.getMethodName(), s, t);
	}

	public static void v(String s) {
		log(Level.FINE, s, null);
	}

	public static void v(Throwable t) {
		log(Level.FINE, "", t);
	}

	public static void v(String s, Throwable t) {
		log(Level.FINE, s, t);
	}

	public static void d(String s) {
		log(Level.CONFIG, s, null);
	}

	public static void d(Throwable t) {
		log(Level.CONFIG, "", t);
	}

	public static void d(String s, Throwable t) {
		log(Level.CONFIG, s, t);
	}

	public static void i(String s) {
		log(Level.INFO, s, null);
	}

	public static void i(Throwable t) {
		log(Level.INFO, "", t);
	}

	public static void i(String s, Throwable t) {
		log(Level.INFO, s, t);
	}

	public static void w(String s) {
		log(Level.WARNING, s, null);
	}

	public static void w(Throwable t) {
		log(Level.WARNING, "", t);
	}

	public static void w(String s, Throwable t) {
		log(Level.WARNING, s, t);
	}

	public static void e(String s) {
		log(Level.SEVERE, s, null);
	}

	public static void e(Throwable t) {
		log(Level.SEVERE, "", t);
	}

	public static void e(String s, Throwable t) {
		log(Level.SEVERE, s, t);
	}
}