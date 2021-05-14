package com.xqbase.coyote;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

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

import sun.security.util.DerValue;
import sun.security.x509.DNSName;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.X500Name;

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

	private static KeyFactory kf;
	private static CertificateFactory cf;

	static Log log = LogFactory.getLog(DoSHttp11NioProtocol.class);

	static {
		try {
			kf = KeyFactory.getInstance("RSA");
			cf = CertificateFactory.getInstance("X509");
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	private HashMap<BigInteger, PrivateKey> keyMap = new HashMap<>();
	private HashMap<BigInteger, HashSet<String>> hostnamesMap = new HashMap<>();

	DoSNioEndpoint dos;

	public DoSHttp11NioProtocol() {
		endpoint = new DoSNioEndpoint();
		((NioEndpoint) endpoint).setHandler((NioEndpoint.Handler) getHandler());
		setSoLinger(Constants.DEFAULT_CONNECTION_LINGER);
		setSoTimeout(Constants.DEFAULT_CONNECTION_TIMEOUT);
		setTcpNoDelay(Constants.DEFAULT_TCP_NO_DELAY);
	}

	private Object[] getPair(String hostname) {
		return dos.hostnameMap.computeIfAbsent(hostname,
				k -> new Object[] {null, null, null});
	}

	private void generateCertificates(String filename) {
		try (FileInputStream in = new FileInputStream(filename)) {
			X509Certificate[] chain =
					cf.generateCertificates(in).toArray(CERTIFICATES);
			if (chain.length == 0) {
				log.warn("No certificates in file " + filename);
				return;
			}
			X509Certificate cert = chain[0];
			if (!(cert.getPublicKey() instanceof RSAKey)) {
				log.warn("Not an RSA certificate in file " + filename);
				return;
			}
			HashSet<String> hostnames = new HashSet<>();
			String cn = new X500Name(cert.
					getSubjectX500Principal().getName()).getCommonName();
			if (cn != null) {
				hostnames.add(cn);
				if (dos.defaultHostname == null) {
					dos.defaultHostname = cn;
				}
			}
			byte[] subAltName = cert.getExtensionValue("2.5.29.17");
			if (subAltName != null) {
				DerValue der = new DerValue(subAltName);
				if (der.tag == DerValue.tag_OctetString) {
					for (GeneralName name : new GeneralNames(new
							DerValue(der.getOctetString())).names()) {
						if (!(name.getName() instanceof DNSName)) {
							continue;
						}
						hostnames.add(((DNSName) name.getName()).getName());
					}
				}
			}
			if (hostnames.isEmpty()) {
				return;
			}
			BigInteger modulus = ((RSAKey) cert.getPublicKey()).getModulus();
			PrivateKey key = keyMap.get(modulus);
			if (key == null) {
				hostnamesMap.put(modulus, hostnames);
			}
			for (String hostname : hostnames) {
				Object[] pair = getPair(hostname);
				if (pair[2] == null || ((Date) pair[2]).before(cert.getNotAfter())) {
					if (key != null) {
						pair[0] = key;
					}
					pair[1] = chain;
					pair[2] = cert.getNotAfter();
				}
			}
		} catch (GeneralSecurityException | IOException e) {
			log.error("Failed to read certificate file " + filename, e);
		}
	}

	@Override
	public void init() throws Exception {
		// Load DoS properties
		dos = (DoSNioEndpoint) endpoint;
		int port = 0;
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
		log.info("DoSHttp11NioProtocol Initialized with period=" +
				dos.period / 1000 + "/requests=" + dos.requests +
				"/connections=" + dos.connections + " on port " + port);
		// Load SNI property "keystorePath"
		String keystorePath = (String) connector.getProperty("keystorePath");
		if (keystorePath == null) {
			super.init();
			return;
		}
		if (keystorePath.endsWith(File.separator)) {
			keystorePath = keystorePath.substring(0, keystorePath.length() - 1);
		}
		File keystoreDir = new File(keystorePath);
		if (!keystoreDir.isDirectory()) {
			super.init();
			return;
		}
		log.info("keystorePath = " + keystorePath);
		// First file by name as default certificate
		for (String name : new TreeSet<>(Arrays.asList(keystoreDir.list()))) {
			if (name.length() < 4) {
				continue;
			}
			String filename = keystorePath + File.separator + name;
			switch (name.substring(name.length() - 4).toLowerCase()) {
			case ".cer":
			case ".crt":
			case ".p7b":
			case ".p7c":
			case ".spc":
				generateCertificates(filename);
				break;
			case ".key":
			case ".pem":
				try (BufferedReader in = new BufferedReader(new FileReader(filename))) {
					String head = in.readLine();
					if (head.equals("-----BEGIN CERTIFICATE-----")) {
						generateCertificates(filename);
						break;
					}
					StringBuilder sb = new StringBuilder();
					String line;
					while ((line = in.readLine()) != null) {
						// TODO Skip "Bag Attributes" PEM header
						// TODO Support -----BEGIN RSA PPRIVATE KEY-----
						if (!line.equals("-----BEGIN PRIVATE KEY-----") &&
								!line.equals("-----END PRIVATE KEY-----")) {
							sb.append(line);
						}
					}
					PrivateKey key = kf.
							generatePrivate(new PKCS8EncodedKeySpec(Base64.
							getDecoder().decode(sb.toString())));
					if (!(key instanceof RSAKey)) {
						log.warn("Not an RSA key in file " + filename);
						break;
					}
					BigInteger modulus = ((RSAKey) key).getModulus();
					HashSet<String> hostnames = hostnamesMap.get(modulus);
					if (hostnames == null) {
						keyMap.put(modulus, key);
					} else {
						for (String hostname : hostnames) {
							getPair(hostname)[0] = key;
						}
					}
				} catch (GeneralSecurityException |
						IOException | IllegalArgumentException e) {
					log.error("Failed to read key file " + filename, e);
				}
				break;
			default:
			}
		}
		// Remove unpaired
		Iterator<Map.Entry<String, Object[]>> hostnames =
				dos.hostnameMap.entrySet().iterator();
		while (hostnames.hasNext()) {
			Object[] pair = hostnames.next().getValue();
			if (pair[0] == null || pair[1] == null) {
				hostnames.remove();
			}
		}
		if (dos.hostnameMap.isEmpty()) {
			super.init();
			return;
		}
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(new X509ExtendedKeyManager[] {new X509ExtendedKeyManager() {
			private ThreadLocal<Object[]> pair_ = new ThreadLocal<>();
			private ThreadLocal<AtomicInteger> count_ = new ThreadLocal<AtomicInteger>() {
				@Override
				protected AtomicInteger initialValue() {
					return new AtomicInteger(0);
				}
			};

			@Override
			public String chooseEngineServerAlias(String keyType,
					Principal[] issuers, SSLEngine ssle) {
				// Step 2.1 Handshake: Key Type
				if (!"RSA".equals(keyType)) {
					return null;
				}
				Object[] pair = (Object[]) ssle.getSession().
						getValue(DoSNioEndpoint.PAIR);
				if (pair == null) {
					pair = dos.hostnameMap.get(dos.defaultHostname);
					if (pair == null) {
						return null;
					}
				}
				pair_.set(pair);
				int count = count_.get().getAndAdd(2);
				if (count != 0) {
					log.info("DEBUG-chooseEngineServerAlias: " +
							Thread.currentThread() + " " + count);
				}
				return "RSA";
			}

			@Override
			public PrivateKey getPrivateKey(String keyType) {
				// Step 2.2 Handshake: Private Key, same thread as step 2.1
				int count = count_.get().decrementAndGet();
				if (count != 1) {
					log.info("DEBUG-getPrivateKey: " +
							Thread.currentThread() + " " + count + " " + keyType);
				}
				return (PrivateKey) pair_.get()[0];
			}

			@Override
			public X509Certificate[] getCertificateChain(String keyType) {
				// Step 2.3 Handshake: Certificate Chain, same thread as step 2.1
				int count = count_.get().decrementAndGet();
				if (count != 0) {
					log.info("DEBUG-getCertificateChain: " +
							Thread.currentThread() + " " + count + " " + keyType);
				}
				return (X509Certificate[]) pair_.get()[1];
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
				log.info("DEBUG-chooseServerAlias: " + Thread.currentThread() +
						" " + keyType + " " + socket.getRemoteSocketAddress());
				throw new UnsupportedOperationException();
			}

			@Override
			public String chooseClientAlias(String[] keyType,
					Principal[] issuers, Socket socket) {
				log.info("DEBUG-chooseServerAlias: " + Thread.currentThread() +
						" " + keyType + " " + socket.getRemoteSocketAddress());
				throw new UnsupportedOperationException();
			}
		}}, DEFAULT_TRUST_MANAGERS, null);
		dos.setSSLContext(sslContext);
		super.init();
	}

	@Override
	public void destroy() {
		super.destroy();
		keyMap.clear();
		hostnamesMap.clear();
		dos.hostnameMap.clear();
		dos.defaultHostname = null;
		log.info("DoSHttp11NioProtocol Destroyed");
	}
}