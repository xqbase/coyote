package com.xqbase.coyote;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.collections.SynchronizedStack;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.SocketStatus;

import com.xqbase.coyote.util.concurrent.Count;
import com.xqbase.coyote.util.concurrent.CountMap;

public class DoSNioEndpoint extends NioEndpoint {
	static Log log = LogFactory.getLog(DoSNioEndpoint.class);

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

	public class DoSPoller extends Poller {
		public DoSPoller() throws IOException {
			super();
		}

		@Override
		public KeyAttachment cancelledKey(SelectionKey key, SocketStatus status) {
			if (key != null) {
				KeyAttachment ka = (KeyAttachment) key.attachment();
				if (ka != null) {
					try {
						countDown((InetSocketAddress)
								ka.getSocket().getIOChannel().getRemoteAddress());
					} catch (IOException e) {
						log.error(e.getMessage(), e);
					}
				}
			}
			return super.cancelledKey(key, status);
		}
	}

	void countDown(InetSocketAddress inetSocketAddress) {
		String ip = inetSocketAddress.getAddress().getHostAddress();
		Count count = connectionsMap.get(ip);
		if (count == null) {
			log.warn("Connection Count Error from " + ip);
		} else {
			connectionsMap.release(ip, count);
		}
		addressMap.remove(ip + ":" + inetSocketAddress.getPort());
	}

	@Override
	protected boolean setSocketOptions(SocketChannel socket) {
		long now = System.currentTimeMillis();
		long accessed_ = accessed.get();
		if (now > accessed_ + period &&
				accessed.compareAndSet(accessed_, now)) {
			requestsMap.clear();
		}

		InetSocketAddress inetSocketAddress;
		try {
			inetSocketAddress = (InetSocketAddress) socket.getRemoteAddress();
		} catch (IOException e) {
			log.error(e.getMessage(), e);
			return false;
		}

		String ip = inetSocketAddress.getAddress().getHostAddress();
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

		address.set(ip + ":" + inetSocketAddress.getPort());
		return super.setSocketOptions(socket);
	}

	CountMap<String> connectionsMap = new CountMap<>();
	int period = 60, requests = 300, connections = 60;
	ThreadLocal<String> address = new ThreadLocal<>();
	Map<String, Object[]> addressMap = new ConcurrentHashMap<>();
	Map<String, Object[]> hostnameMap = new HashMap<>();
	SSLContext sslContext = null;

	private CountMap<String> requestsMap = new CountMap<>();
	private AtomicLong accessed = new AtomicLong(System.currentTimeMillis());

	private static Field pollersField = getField("pollers"),
			// Available until Tomcat 8.0.9
			processorCacheField = getField("processorCache"),
			eventCacheField = getField("eventCache"),
			nioChannelsField = getField("nioChannels"),
			enabledProtocolsField = getField("enabledProtocols");

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
		if (sslContext == null) {
			return super.createSSLEngine();
		}
		SSLEngine engine = sslContext.createSSLEngine();
		engine.setUseClientMode(false);
		SSLParameters sslp = new SSLParameters();
		sslp.setNeedClientAuth(false);
		sslp.setWantClientAuth(false);
		sslp.setCipherSuites(getCiphersUsed());
		try {
			sslp.setProtocols((String[]) enabledProtocolsField.get(this));
		} catch (ReflectiveOperationException e) {
			throw new RuntimeException(e);
		}
		String address_ = address.get();
		sslp.setSNIMatchers(Collections.singleton(new SNIMatcher(0) {
			@Override
			public boolean matches(SNIServerName serverName) {
				Object[] pair = hostnameMap.
						get(new String(serverName.getEncoded()));
				if (pair == null || pair[0] == null || pair[1] == null) {
					return false;
				}
				addressMap.put(address_, pair);
				return true;
			}
		}));
		engine.setSSLParameters(sslp);
		configureUseServerCipherSuitesOrder(engine);
        return engine;
	}
}