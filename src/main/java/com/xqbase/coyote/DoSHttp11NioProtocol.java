package com.xqbase.coyote;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.CoyoteAdapter;
import org.apache.coyote.http11.Constants;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.NioEndpoint;

public class DoSHttp11NioProtocol extends Http11NioProtocol {
	private static final X509Certificate[] CERTIFICATES = {};
	private static final X509TrustManager[]
			DEFAULT_TRUST_MANAGERS = new X509TrustManager[] {
		new X509TrustManager() {
			@Override
			public void checkClientTrusted(X509Certificate[] certs, String s) {/**/}

			@Override
			public void checkServerTrusted(X509Certificate[] certs, String s) {/**/}

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return new X509Certificate[0];
			}
		}
	};

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

	private static Object[] getPair(Map<String, Object[]> pairMap, String filename) {
		return pairMap.computeIfAbsent(filename.substring(0, filename.length() - 4),
				k -> new Object[] {null, null});
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
		Connector connector;
		try {
			Field field = CoyoteAdapter.class.getDeclaredField("connector");
			field.setAccessible(true);
			connector = (Connector) field.get(adapter);
		} catch (ReflectiveOperationException e) {
			log.error("Unable to Initialize DoS Parameters " +
					"\"period\", \"requests\" or \"connections\"", e);
			return;
		}
		dos.period = parseInt((String) connector.
				getProperty("dosPeriod"), 60) * 1000;
		dos.requests = parseInt((String) connector.
				getProperty("dosRequests"), 300);
		dos.connections = parseInt((String) connector.
				getProperty("dosConnections"), 60);
		port = connector.getPort();
		log.info("DoSHttp11NioProtocol Started with period=" +
				dos.period / 1000 + "/requests=" + dos.requests +
				"/connections=" + dos.connections + " on port " + port);
		String keystorePath = (String) connector.getProperty("keystorePath");
		if (keystorePath == null) {
			return;
		}
		if (keystorePath.endsWith(File.separator)) {
			keystorePath = keystorePath.substring(0, keystorePath.length() - 1);
		}
		File keystoreDir = new File(keystorePath);
		if (!keystoreDir.isDirectory()) {
			return;
		}
		KeyFactory kf = KeyFactory.getInstance("RSA");
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		for (String filename : keystoreDir.list()) {
			// Generate PKCS#8 key from PEM:
			// openssl pkcs8 -in localhost.pem -nocrypt -outform der -out localhost.pkcs8.key
			if (filename.endsWith(".pem")) {
				StringBuilder sb = new StringBuilder();
				try (BufferedReader in = new BufferedReader(new
						FileReader(keystorePath + File.separator + filename))) {
					String line;
					while ((line = in.readLine()) != null) {
						if (!line.equals("-----BEGIN PRIVATE KEY-----") &&
								!line.equals("-----END PRIVATE KEY-----")) {
							sb.append(line);
						}
					}
				}
				getPair(dos.hostnameMap, filename)[0] = kf.
						generatePrivate(new PKCS8EncodedKeySpec(Base64.
						getDecoder().decode(sb.toString())));
			}
			if (filename.endsWith(".crt")) {
				try (FileInputStream in = new FileInputStream(keystorePath +
						File.separator + filename)) {
					getPair(dos.hostnameMap, filename)[1] =
							cf.generateCertificates(in).toArray(CERTIFICATES);
				}
			}
		}
		if (dos.hostnameMap.isEmpty()) {
			return;
		}
		dos.sslContext = SSLContext.getInstance("TLS");
		dos.sslContext.init(new X509ExtendedKeyManager[] {new X509ExtendedKeyManager() {
			private ThreadLocal<Object[]> pair = new ThreadLocal<>();

			@Override
			public String chooseEngineServerAlias(String keyType,
					Principal[] issuers, SSLEngine ssle) {
				if (!"RSA".equals(keyType)) {
					return null;
				}
				// TODO use sessionId?
				Object[] pair_ = dos.addressMap.get(ssle.getPeerHost() +
						":" + ssle.getPeerPort());
				if (pair_ == null) {
					return null;
				}
				pair.set(pair_);
				return "RSA";
			}

			@Override
			public PrivateKey getPrivateKey(String keyType) {
				return (PrivateKey) pair.get()[0];
			}

			@Override
			public X509Certificate[] getCertificateChain(String keyType) {
				return (X509Certificate[]) pair.get()[1];
			}

			@Override
			public String[] getServerAliases(String keyType, Principal[] issuers) {
				throw new UnsupportedOperationException();
			}

			@Override
			public String[] getClientAliases(String keyType, Principal[] issuers) {
				throw new UnsupportedOperationException();
			}

			@Override
			public String chooseServerAlias(String keyType,
					Principal[] issuers, Socket socket) {
				throw new UnsupportedOperationException();
			}

			@Override
			public String chooseClientAlias(String[] keyType,
					Principal[] issuers, Socket socket) {
				throw new UnsupportedOperationException();
			}
		}}, DEFAULT_TRUST_MANAGERS, null);
	}

	@Override
	public void stop() throws Exception {
		log.info("DoSHttp11NioProtocol Stopped");
		super.stop();
	}
}