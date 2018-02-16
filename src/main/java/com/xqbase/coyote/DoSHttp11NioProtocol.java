package com.xqbase.coyote;

import java.lang.reflect.Field;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.CoyoteAdapter;
import org.apache.coyote.http11.Constants;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.NioEndpoint;

public class DoSHttp11NioProtocol extends Http11NioProtocol {
	private static Log log = LogFactory.getLog(DoSHttp11NioProtocol.class);

	private static int parseInt(String s, int i) {
		if (s == null) {
			return i;
		}
		try {
			return Integer.parseInt(s.trim());
		} catch (NumberFormatException e) {
			return i;
		}
	}

	public DoSHttp11NioProtocol() {
		endpoint = new DoSNioEndpoint();
		((NioEndpoint) endpoint).setHandler((NioEndpoint.Handler) getHandler());
		setSoLinger(Constants.DEFAULT_CONNECTION_LINGER);
		setSoTimeout(Constants.DEFAULT_CONNECTION_TIMEOUT);
		setTcpNoDelay(Constants.DEFAULT_TCP_NO_DELAY);
	}

	@Override
	public void start() throws Exception {
		super.start();
		DoSNioEndpoint dos = (DoSNioEndpoint) endpoint;
		int port = 0;
		try {
			Field field = CoyoteAdapter.class.getDeclaredField("connector");
			field.setAccessible(true);
			Connector connector = (Connector) field.get(adapter);
			dos.period = parseInt((String) connector.
					getProperty("dosPeriod"), 60) * 1000;
			dos.requests = parseInt((String) connector.
					getProperty("dosRequests"), 300);
			dos.connections = parseInt((String) connector.
					getProperty("dosConnections"), 60);
			port = connector.getPort();
		} catch (ReflectiveOperationException e) {
			log.error("Unable to Initialize DoS Parameters " +
					"\"period\", \"requests\" or \"connections\"", e);
		}
		log.info("DoSHttp11NioProtocol Started with period=" +
				dos.period / 1000 + "/requests=" + dos.requests +
				"/connections=" + dos.connections + " on port " + port);
	}

	@Override
	public void stop() throws Exception {
		log.info("DoSHttp11NioProtocol Stopped");
		super.stop();
	}
}