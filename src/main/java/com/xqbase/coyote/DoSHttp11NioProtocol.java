package com.xqbase.coyote;

import org.apache.coyote.http11.Constants;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.NioEndpoint;

public class DoSHttp11NioProtocol extends Http11NioProtocol {
	public DoSHttp11NioProtocol() {
		endpoint = new DoSNioEndpoint();
		((NioEndpoint) endpoint).setHandler((NioEndpoint.Handler) getHandler());
		setSoLinger(Constants.DEFAULT_CONNECTION_LINGER);
		setSoTimeout(Constants.DEFAULT_CONNECTION_TIMEOUT);
		setTcpNoDelay(Constants.DEFAULT_TCP_NO_DELAY);
	}
}