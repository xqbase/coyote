import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import com.xqbase.util.Time;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

class TimeoutMap<K, V> {
	class TimeoutEntry {
		V value;
		long expire;
	}

	private long accessed = 0;
	private int timeout, interval;
	private boolean accessOrder;
	private LinkedHashMap<K, TimeoutEntry> map;

	public TimeoutMap(int timeout, int interval) {
		this(timeout, interval, false);
	}

	public TimeoutMap(int timeout, int interval, boolean accessOrder) {
		this.timeout = timeout;
		this.interval = interval;
		this.accessOrder = accessOrder;
		map = new LinkedHashMap<>(16, 0.75f, accessOrder);
	}

	private V get_(K key) {
		TimeoutEntry entry = map.get(key);
		if (entry == null) {
			return null;
		}
		if (accessOrder) {
			entry.expire = System.currentTimeMillis() + timeout;
		}
		return entry.value;
	}

	private void put_(K key, V value) {
		TimeoutEntry entry = new TimeoutEntry();
		entry.value = value;
		entry.expire = System.currentTimeMillis() + timeout;
		map.put(key, entry);
	}

	private V remove_(K key) {
		TimeoutEntry entry = map.remove(key);
		return entry == null ? null : entry.value;
	}

	private void expire() {
		long now = System.currentTimeMillis();
		if (now < accessed + interval) {
			return;
		}
		accessed = now;
		Iterator<TimeoutEntry> i = map.values().iterator();
		while (i.hasNext() && now > i.next().expire) {
			i.remove();
		}
	}

	public synchronized V get(K key) {
		return get_(key);
	}

	public synchronized V expireAndGet(K key) {
		expire();
		return get_(key);
	}

	public synchronized void put(K key, V value) {
		put_(key, value);
	}

	public synchronized void expireAndPut(K key, V value) {
		expire();
		put_(key, value);
	}

	public synchronized V remove(K key) {
		return remove_(key);
	}

	public synchronized V expireAndRemove(K key) {
		expire();
		return remove_(key);
	}
}

public class TestSNI {
	private static final X509TrustManager[] DEFAULT_TRUST_MANAGERS = new X509TrustManager[] {
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

	private static Object[] getPair(String dn, long expire)
			throws IOException, GeneralSecurityException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		long now = System.currentTimeMillis();
		X509CertInfo info = new X509CertInfo();
		info.set("version", new CertificateVersion(2));
		info.set("serialNumber", new CertificateSerialNumber(0));
		info.set("algorithmID",
				new CertificateAlgorithmId(AlgorithmId.get("SHA1withRSA")));
		X500Name x500Name = new X500Name(dn);
		info.set("subject", x500Name);
		KeyPair keyPair = kpg.genKeyPair();
		info.set("key", new CertificateX509Key(keyPair.getPublic()));
		info.set("validity", new CertificateValidity(new Date(now),
				new Date(now + expire)));
		info.set("issuer", x500Name);
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(keyPair.getPrivate(), "SHA1withRSA");
		return new Object[] {keyPair.getPrivate(), new X509Certificate[] {cert}};
	}

	public static void main(String[] args) throws Exception {
		Map<String, Object[]> hostnameMap = new HashMap<>();
		hostnameMap.put("localhost", getPair("CN=localhost", Time.WEEK));
		hostnameMap.put("ns0.xqbase.com", getPair("CN=ns0.xqbase.com", Time.WEEK));
		TimeoutMap<String, Object[]> addressMap = new TimeoutMap<>(10000, 1000, true);
		SSLContext sslc = SSLContext.getInstance("TLS");
		sslc.init(new X509ExtendedKeyManager[] {new X509ExtendedKeyManager() {
			private ThreadLocal<Object[]> pair_ = new ThreadLocal<>();

			@Override
			public String chooseEngineServerAlias(String keyType,
					Principal[] issuers, SSLEngine ssle) {
				if (!"RSA".equals(keyType)) {
					return null;
				}
				Object[] pair = addressMap.expireAndGet(ssle.getPeerHost() +
						":" + ssle.getPeerPort());
				if (pair == null) {
					return null;
				}
				pair_.set(pair);
				return "RSA";
			}

			@Override
			public PrivateKey getPrivateKey(String keyType) {
				return (PrivateKey) pair_.get()[0];
			}

			@Override
			public X509Certificate[] getCertificateChain(String keyType) {
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
				throw new UnsupportedOperationException();
			}

			@Override
			public String chooseClientAlias(String[] keyType,
					Principal[] issuers, Socket socket) {
				throw new UnsupportedOperationException();
			}
		}}, DEFAULT_TRUST_MANAGERS, null);
		HttpsServer server = HttpsServer.create(new InetSocketAddress(443), 0);
		server.setHttpsConfigurator(new HttpsConfigurator(sslc) {
			@Override
			public void configure(HttpsParameters httpsParam) {
				SSLParameters sslp = new SSLParameters();
				sslp.setSNIMatchers(Collections.singleton(new SNIMatcher(0) {
					@Override
					public boolean matches(SNIServerName serverName) {
						Object[] pair = hostnameMap.
								get(new String(serverName.getEncoded()));
						if (pair == null) {
							return false;
						}
						InetSocketAddress addr = httpsParam.getClientAddress();
						addressMap.expireAndPut(addr.getHostString() +
								":" + addr.getPort(), pair);
						return true;
					}
				}));
				httpsParam.setSSLParameters(sslp);
			}
		});
		server.start();
	}
}