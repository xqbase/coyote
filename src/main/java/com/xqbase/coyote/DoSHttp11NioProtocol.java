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

	private Object[] getPair(String filename) {
		return dos.hostnameMap.computeIfAbsent(filename.substring(0,
				filename.length() - 4), k -> new Object[] {null, null});
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
				if (dos.defaultHostname != null) {
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
	public void start() throws Exception {
		super.start();
		// Load DoS properties
		dos = (DoSNioEndpoint) endpoint;
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
		// Load SNI property "keystorePath"
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
				} catch (Exception e) {
					log.error("Failed to read key file " + filename, e);
				}
				break;
			default:
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
				// Step 2.1 Handshake: Key Type
				if (!"RSA".equals(keyType)) {
					return null;
				}
				Object[] pair_ = dos.engineMap.get(ssle);
				if (pair_ == null) {
					return null;
				}
				pair.set(pair_);
				return "RSA";
			}

			@Override
			public PrivateKey getPrivateKey(String keyType) {
				// Step 2.2 Handshake: Private Key, same thread as step 2.1
				return (PrivateKey) pair.get()[0];
			}

			@Override
			public X509Certificate[] getCertificateChain(String keyType) {
				// Step 2.3 Handshake: Certificate Chain, same thread as step 2.1
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
		// TODO set keystoreFile
		String keystoreFile = (String) connector.getProperty("keystoreFile");
		if (keystoreFile != null) {
			return;
		}
	}

	@Override
	public void stop() throws Exception {
		keyMap.clear();
		hostnamesMap.clear();
		dos.hostnameMap.clear();
		dos.defaultHostname = null;
		log.info("DoSHttp11NioProtocol Stopped");
		super.stop();
	}
}