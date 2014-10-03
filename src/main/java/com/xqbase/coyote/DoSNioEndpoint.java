package com.xqbase.coyote;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.SocketStatus;

import com.xqbase.util.Conf;
import com.xqbase.util.Log;
import com.xqbase.util.Numbers;
import com.xqbase.util.concurrent.Count;
import com.xqbase.util.concurrent.SimpleCountMap;

public class DoSNioEndpoint extends NioEndpoint {
	static String getRemoteAddr(SocketChannel socket) {
		try {
			return ((InetSocketAddress) socket.getRemoteAddress()).getAddress().getHostAddress();
		} catch (IOException e) {
			Log.e(e);
			return null;
		}
	}

	public class DoSPoller extends Poller {
		public DoSPoller() throws IOException {
			super();
		}

		@Override
		public void cancelledKey(SelectionKey key, SocketStatus status) {
			if (key != null) {
				KeyAttachment ka = (KeyAttachment) key.attachment();
				if (ka != null) {
					String ip = getRemoteAddr(ka.getSocket().getIOChannel());
					Count count = connectionsMap.get(ip);
					if (count == null) {
						Log.w("Connection Count Error from " + ip);
					} else {
						connectionsMap.release(ip, count);
					}
				}
			}
			super.cancelledKey(key, status);
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
			Log.w("DoS Attack from " + ip + ", requests = " + count);
			return false;
		}

		count = connectionsMap.acquire(ip);
		if (count.get() > connections) {
			Log.w("DoS Attack from " + ip + ", connections = " + count);
			connectionsMap.release(ip, count);
			return false;
		}

		return super.setSocketOptions(socket);
	}

	SimpleCountMap<String> connectionsMap = new SimpleCountMap<>();

	private SimpleCountMap<String> requestsMap = new SimpleCountMap<>();
	private AtomicLong accessed = new AtomicLong(System.currentTimeMillis());
	private int period, requests, connections;

	private static int startCount = 0;
	private static Logger logger;
	private static Field pollersField;

	static {
		try {
			pollersField = NioEndpoint.class.getDeclaredField("pollers");
			pollersField.setAccessible(true);
		} catch (ReflectiveOperationException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
    public void startInternal() throws Exception {
		if (running) {
			return;
		}

		synchronized (DoSNioEndpoint.class) {
			if (startCount == 0) {
				logger = Log.getAndSet(Conf.openLogger("DoS.", 16777216, 10));
			}
			startCount ++;
		}

		Properties p = Conf.load("DoS");
		period = Numbers.parseInt(p.getProperty("period")) * 1000;
		requests = Numbers.parseInt(p.getProperty("requests"));
		connections = Numbers.parseInt(p.getProperty("connections"));
		connectionsMap.clear();

		running = true;
		paused = false;

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
			Thread pollerThread = new Thread(pollers[i], getName() + "-ClientPoller-" + i);
			pollerThread.setPriority(threadPriority);
			pollerThread.setDaemon(true);
			pollerThread.start();
		}

		startAcceptorThreads();
    }

	@Override
	public void stopInternal() {
		if (running) {
			synchronized (DoSNioEndpoint.class) {
				startCount --;
				if (startCount == 0) {
					Conf.closeLogger(Log.getAndSet(logger));
				}
			}
		}
		super.stopInternal();
	}
}