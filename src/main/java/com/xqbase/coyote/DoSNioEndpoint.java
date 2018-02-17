package com.xqbase.coyote;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.concurrent.atomic.AtomicLong;

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

		return super.setSocketOptions(socket);
	}

	CountMap<String> connectionsMap = new CountMap<>();
	int period = 60, requests = 300, connections = 60;

	private CountMap<String> requestsMap = new CountMap<>();
	private AtomicLong accessed = new AtomicLong(System.currentTimeMillis());

	private static Field pollersField = getField("pollers"),
			// Available until Tomcat 8.0.9
			processorCacheField = getField("processorCache"),
			eventCacheField = getField("eventCache"),
			nioChannelsField = getField("nioChannels");

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
		if (getExecutor() == null ) {
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
}