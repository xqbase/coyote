package com.xqbase.coyote.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Properties;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class Conf {
	public static boolean DEBUG = false;

	private static String rootDir = null, confDir = null, logDir = null;

	static {
		for (String argument : ManagementFactory.
				getRuntimeMXBean().getInputArguments()) {
			if (argument.startsWith("-agentlib:jdwp")) {
				DEBUG = true;
				break;
			}
		}

		Properties p = load("Conf");
		confDir = p.getProperty("conf_dir");
		logDir = p.getProperty("log_dir");
	}

	private static void load(Properties p, String path) {
		try (FileInputStream in = new FileInputStream(path)) {
			p.load(in);
		} catch (FileNotFoundException e) {
			// Ignored
		} catch (IOException e) {
			Log.w(e.getMessage());
		}
	}

	private static String getConfPath(String name, String confDir_) {
		return confDir_ == null ? locate("conf/" + name + ".properties") :
				(confDir_.endsWith("/") ? confDir_ : confDir_ + "/") +
				name + ".properties";
	}

	private static Class<?> getParentClass() {
		for (StackTraceElement ste : new Throwable().getStackTrace()) {
			String className = ste.getClassName();
			if (!className.equals(Conf.class.getName())) {
				try {
					return Class.forName(className);
				} catch (ReflectiveOperationException e) {
					Log.e(e);
					return Conf.class;
				}
			}
		}
		return Conf.class;
	}

	public static synchronized void setRoot(String absolute) {
		if (absolute != null) {
			rootDir = new File(absolute).getAbsolutePath();
		}
	}

	public static synchronized String locate(String path) {
		try {
			if (rootDir == null) {
				Class<?> parentClass = getParentClass();
				String classFile = parentClass.getName().replace('.', '/') + ".class";
				URL url = parentClass.getResource("/" + classFile);
				if (url == null) {
					return null;
				}
				if (url.getProtocol().equals("jar")) {
					rootDir = url.getPath();
					int i = rootDir.lastIndexOf('!');
					if (i >= 0) {
						rootDir = rootDir.substring(0, i);
					}
					rootDir = new File(new URL(rootDir).toURI()).getParent();
				} else {
					rootDir = new File(url.toURI()).getPath();
					rootDir = rootDir.substring(0, rootDir.length() - classFile.length());
					if (rootDir.endsWith(File.separator)) {
						rootDir = rootDir.substring(0, rootDir.length() - 1);
					}
				}
				rootDir = new File(rootDir).getParent();
			}
			return new File(rootDir + File.separator + path).getCanonicalPath();
		} catch (IOException | URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}

	public static Logger openLogger(String name, int limit, int count) {
		Logger logger = Logger.getAnonymousLogger();
		logger.setLevel(Level.ALL);
		logger.setUseParentHandlers(false);
		if (DEBUG) {
			ConsoleHandler handler = new ConsoleHandler();
			handler.setLevel(Level.ALL);
			logger.addHandler(handler);
		}
		FileHandler handler;
		try {
			String logDir_ = logDir == null ? locate("logs") : logDir;
			new File(logDir_).mkdirs();
			String pattern = (logDir_.endsWith("/") ? logDir_ : logDir_ + "/") +
					name + "%g.log";
			handler = new FileHandler(pattern, limit, count, true);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		handler.setFormatter(new SimpleFormatter());
		handler.setLevel(Level.ALL);
		logger.addHandler(handler);
		return logger;
	}

	public static void closeLogger(Logger logger) {
		for (Handler handler : logger.getHandlers()) {
			logger.removeHandler(handler);
			handler.close();
		}
	}

	public static Properties load(String name) {
		Properties p = new Properties();
		InputStream in = getParentClass().getResourceAsStream("/" + name + ".properties");
		if (in != null) {
			try {
				p.load(in);
			} catch (IOException e) {
				Log.w(e.getMessage());
			}
		}
		load(p, getConfPath(name, null));
		if (confDir != null) {
			load(p, getConfPath(name, confDir));
		}
		return p;
	}
}