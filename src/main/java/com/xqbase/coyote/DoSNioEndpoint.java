package com.xqbase.coyote;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Collections;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.collections.SynchronizedStack;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.SocketStatus;
import org.apache.tomcat.util.net.jsse.JSSESocketFactory;

import com.xqbase.coyote.util.concurrent.Count;
import com.xqbase.coyote.util.concurrent.CountMap;

public class DoSNioEndpoint extends NioEndpoint {
	static final String ALIAS = DoSNioEndpoint.class.getName() + ".ALIAS";
	static final String REMOTE = DoSNioEndpoint.class.getName() + ".REMOTE";

	static Log log = LogFactory.getLog(DoSNioEndpoint.class);

	private static Field pollersField = getField("pollers"),
			// Available until Tomcat 8.0.9
			processorCacheField = getField("processorCache"),
			eventCacheField = getField("eventCache"),
			nioChannelsField = getField("nioChannels"),
			enabledCiphersField = getField("enabledCiphers"),
			enabledProtocolsField = getField("enabledProtocols");

	private static Field getField(String name) {
		try {
			Field field = NioEndpoint.class.getDeclaredField(name);
			field.setAccessible(true);
			return field;
		} catch (ReflectiveOperationException e) {
			log.warn(e.getMessage());
			return null;
		}
	}

	static String getRemoteAddr(SocketChannel socket) {
		try {
			return ((InetSocketAddress) socket.getRemoteAddress()).
					getAddress().getHostAddress();
		} catch (IOException e) {
			log.warn(e.getMessage());
			return "";
		}
	}

	public class DoSPoller extends Poller {
		public DoSPoller() throws IOException {
			super();
		}

		@Override
		public KeyAttachment cancelledKey(SelectionKey key, SocketStatus status) {
			if (key != null) {
				KeyAttachment ka = (KeyAttachment) key.attachment();
				if (ka != null) {
					String ip = getRemoteAddr(ka.getSocket().getIOChannel());
					Count count = connectionsMap.get(ip);
					if (count == null) {
						log.warn("Connection Count Error from " + ip);
					} else {
						connectionsMap.release(ip, count);
					}
				}
			}
			return super.cancelledKey(key, status);
		}
	}

	private ThreadLocal<String> remote = new ThreadLocal<>();

	@Override
	protected boolean setSocketOptions(SocketChannel socket) {
		long now = System.currentTimeMillis();
		long accessed_ = accessed.get();
		if (now > accessed_ + period &&
				accessed.compareAndSet(accessed_, now)) {
			requestsMap.clear();
		}

		String ip = getRemoteAddr(socket);
		Count count = requestsMap.acquire(ip);
		if (count.get() > requests) {
			log.info("DoS Attack from " + ip + ", requests = " + count);
			return false;
		}

		count = connectionsMap.acquire(ip);
		if (count.get() > connections) {
			log.info("DoS Attack from " + ip + ", connections = " + count);
			connectionsMap.release(ip, count);
			return false;
		}

		remote.set(ip);
		return super.setSocketOptions(socket);
	}

	CountMap<String> connectionsMap = new CountMap<>();
	int period = 60, requests = 300, connections = 60;
	HashMap<String, Object[]> hostnameMap = new HashMap<>();
	String defaultHostname = null;

	private CountMap<String> requestsMap = new CountMap<>();
	private AtomicLong accessed = new AtomicLong(System.currentTimeMillis());

	@Override
	public void bind() throws Exception {
		SSLContext sslContext = getSSLContext();
		if (!isSSLEnabled() || sslContext == null) {
			super.bind();
			return;
		}
		setSSLEnabled(false);
		super.bind();
		setSSLEnabled(true);
		JSSESocketFactory sslUtil = new JSSESocketFactory(this);
		enabledCiphersField.set(this, sslUtil.getEnableableCiphers(sslContext));
		enabledProtocolsField.set(this, sslUtil.getEnableableProtocols(sslContext));
	}

	@Override
	public void startInternal() throws Exception {
		if (running) {
			return;
		}
		connectionsMap.clear();
		running = true;
		paused = false;

		if (processorCacheField != null) {
			processorCacheField.set(this,
					new SynchronizedStack<>(SynchronizedStack.DEFAULT_SIZE,
					socketProperties.getProcessorCache()));
		}
		if (eventCacheField != null) {
			eventCacheField.set(this,
					new SynchronizedStack<>(SynchronizedStack.DEFAULT_SIZE,
					socketProperties.getEventCache()));
		}
		if (nioChannelsField != null) {
			nioChannelsField.set(this,
					new SynchronizedStack<>(SynchronizedStack.DEFAULT_SIZE,
					socketProperties.getBufferPool()));
		}

		// Create worker collection
		if (getExecutor() == null) {
			createExecutor();
		}

		initializeConnectionLatch();

		// Start poller threads
		DoSPoller[] pollers = new DoSPoller[getPollerThreadCount()];
		pollersField.set(this, pollers);
		for (int i = 0; i < pollers.length; i ++) {
			pollers[i] = new DoSPoller();
			Thread pollerThread = new Thread(pollers[i],
					getName() + "-ClientPoller-" + i);
			pollerThread.setPriority(threadPriority);
			pollerThread.setDaemon(true);
			pollerThread.start();
		}

		startAcceptorThreads();
	}

	@Override
	protected SSLEngine createSSLEngine() {
		if (hostnameMap.isEmpty()) {
			return super.createSSLEngine();
		}
		SSLEngine ssle = getSSLContext().createSSLEngine();
		SSLSession ssls = ssle.getSession();
		ssls.removeValue(ALIAS);
		ssls.putValue(REMOTE, remote.get());
		ssle.setUseClientMode(false);
		SSLParameters sslp = new SSLParameters();
		sslp.setNeedClientAuth(false);
		sslp.setWantClientAuth(false);
		sslp.setCipherSuites(getCiphersUsed());
		try {
			sslp.setProtocols((String[]) enabledProtocolsField.get(this));
		} catch (ReflectiveOperationException e) {
			throw new RuntimeException(e);
		}
		sslp.setSNIMatchers(Collections.singleton(new SNIMatcher(0) {
			@Override
			public boolean matches(SNIServerName serverName) {
				// Step 1: SNI Matching (Check Client Hello)
				String hostname = new String(serverName.getEncoded());
				String remote_ = (String) ssls.getValue(REMOTE);
				log.debug("1 " + hostname + ", " + remote_);
				if (!hostnameMap.containsKey(hostname)) {
					int dot = hostname.indexOf('.');
					if (dot >= 0) {
						hostname = "*" + hostname.substring(dot);
						if (!hostnameMap.containsKey(hostname)) {
							log.debug("Unmatched serverName: " +
									new String(serverName.getEncoded()) + ", " + remote_);
							hostname = defaultHostname;
						}
					} else {
						log.debug("Unmatched serverName: " + hostname + ", " + remote_);
						hostname = defaultHostname;
					}
					if (hostname == null) {
						return false;
					}
				}
				ssls.putValue(ALIAS, hostname);
				return true;
			}
		}));
		ssle.setSSLParameters(sslp);
		configureUseServerCipherSuitesOrder(ssle);
        return ssle;
	}
}