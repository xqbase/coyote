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

import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
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
			for (String hostname : hostnames) {
				Object[] pair = getPair(hostname);
				if (pair[2] == null || ((Date) pair[2]).before(cert.getNotAfter())) {
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
		HashMap<BigInteger, PrivateKey> keyMap = new HashMap<>();
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
					boolean rsa = false;
					StringBuilder sb = new StringBuilder();
					String line = head;
					do {
						// TODO Skip "Bag Attributes" PEM header
						if (line.equals("-----BEGIN RSA PRIVATE KEY-----")) {
							rsa = true;
						} else if (!line.equals("-----END RSA PRIVATE KEY-----") &&
								!line.equals("-----BEGIN PRIVATE KEY-----") &&
								!line.equals("-----END PRIVATE KEY-----")) {
							sb.append(line);
						}
						line = in.readLine();
					} while (line != null);
					byte[] encodedKey = Base64.getDecoder().decode(sb.toString());
					if (rsa) {
						DerOutputStream alg = new DerOutputStream();
						alg.putOID(AlgorithmId.RSAEncryption_oid);
						alg.putNull();
						DerOutputStream seq = new DerOutputStream();
						seq.putInteger(0);
						seq.write(DerValue.tag_Sequence, alg);
						seq.putOctetString(encodedKey);
						try (DerOutputStream pkcs8 = new DerOutputStream()) {
							pkcs8.write(DerValue.tag_Sequence, seq);
							encodedKey = pkcs8.toByteArray();
						}
					}
					PrivateKey key = kf.
							generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
					if (!(key instanceof RSAKey)) {
						log.warn("Not an RSA key in file " + filename);
						break;
					}
					keyMap.put(((RSAKey) key).getModulus(), key);
				} catch (GeneralSecurityException |
						IOException | IllegalArgumentException e) {
					log.error("Failed to read key file " + filename, e);
				}
				break;
			default:
			}
		}
		// Pair
		Iterator<Map.Entry<String, Object[]>> hostnames =
				dos.hostnameMap.entrySet().iterator();
		while (hostnames.hasNext()) {
			Object[] pair = hostnames.next().getValue();
			PrivateKey key = keyMap.get(((RSAKey)
					((X509Certificate[]) pair[1])[0].getPublicKey()).getModulus());
			if (key == null) {
				hostnames.remove();
			} else {
				pair[0] = key;
			}
		}
		log.info("serverNames = " + dos.hostnameMap.keySet());
		if (dos.defaultHostname != null &&
				!dos.hostnameMap.containsKey(dos.defaultHostname)) {
			dos.defaultHostname = null;
		}
		if (dos.hostnameMap.isEmpty()) {
			super.init();
			return;
		}
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(new X509ExtendedKeyManager[] {new X509ExtendedKeyManager() {
			@Override
			public String chooseEngineServerAlias(String keyType,
					Principal[] issuers, SSLEngine ssle) {
				if (!"RSA".equals(keyType)) {
					return null;
				}
				// Step 2.1 Handshake: Alias
				String alias = (String) ssle.getSession().getValue(DoSNioEndpoint.ALIAS);
				return alias == null ? dos.defaultHostname : alias;
			}

			@Override
			public PrivateKey getPrivateKey(String alias) {
				// Step 2.2 Handshake: Private Key
				return (PrivateKey) dos.hostnameMap.get(alias)[0];
			}

			@Override
			public X509Certificate[] getCertificateChain(String alias) {
				// Step 2.3 Handshake: Certificate Chain
				return (X509Certificate[]) dos.hostnameMap.get(alias)[1];
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
		dos.setSSLContext(sslContext);
		super.init();
	}

	@Override
	public void destroy() {
		super.destroy();
		dos.hostnameMap.clear();
		dos.defaultHostname = null;
		log.info("DoSHttp11NioProtocol Destroyed");
	}
}