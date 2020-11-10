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
import com.xqbase.coyote.util.CertKey;
import com.xqbase.coyote.util.TimeoutMap;
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

	private static CertKey getCertKey(String dn, long expire)
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
		return new CertKey(keyPair.getPrivate(), cert);
	}

	public static void main(String[] args) throws Exception {
		Map<String, CertKey> hostnameMap = new HashMap<>();
		hostnameMap.put("localhost", getCertKey("CN=localhost", Time.WEEK));
		hostnameMap.put("ns0.xqbase.com", getCertKey("CN=ns0.xqbase.com", Time.WEEK));
		TimeoutMap<String, CertKey> addressMap = new TimeoutMap<>(10000, 1000, true);
		SSLContext sslc = SSLContext.getInstance("TLS");
		sslc.init(new X509ExtendedKeyManager[] {new X509ExtendedKeyManager() {
			private ThreadLocal<CertKey> certKey_ = new ThreadLocal<>();

			@Override
			public String chooseEngineServerAlias(String keyType,
					Principal[] issuers, SSLEngine ssle) {
				if (!"RSA".equals(keyType)) {
					return null;
				}
				CertKey certKey = addressMap.expireAndGet(ssle.getPeerHost() +
						":" + ssle.getPeerPort());
				if (certKey == null) {
					return null;
				}
				certKey_.set(certKey);
				return "RSA";
			}

			@Override
			public PrivateKey getPrivateKey(String keyType) {
				return certKey_.get().getPrivateKey();
			}

			@Override
			public X509Certificate[] getCertificateChain(String keyType) {
				return certKey_.get().getCertificateChain();
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
						CertKey certKey = hostnameMap.
								get(new String(serverName.getEncoded()));
						if (certKey == null) {
							return false;
						}
						InetSocketAddress addr = httpsParam.getClientAddress();
						addressMap.expireAndPut(addr.getHostString() +
								":" + addr.getPort(), certKey);
						return true;
					}
				}));
				httpsParam.setSSLParameters(sslp);
			}
		});
		server.start();
	}
}