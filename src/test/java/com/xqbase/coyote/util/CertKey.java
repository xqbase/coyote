package com.xqbase.coyote.util;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class CertKey {
	private PrivateKey privateKey;
	private X509Certificate[] certificateChain;

	public CertKey(PrivateKey privateKey, X509Certificate... certificateChain) {
		this.privateKey = privateKey;
		this.certificateChain = certificateChain;
	}

	public CertKey(KeyStore keyStore, String password) throws GeneralSecurityException {
		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
			if (privateKey == null) {
				continue;
			}
			Certificate[] certs = keyStore.getCertificateChain(alias);
			if (certs == null) {
				certificateChain = new X509Certificate[0];
			} else {
				certificateChain = new X509Certificate[certs.length];
				System.arraycopy(certs, 0, certificateChain, 0, certs.length);
			}
			break;
		}
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public X509Certificate[] getCertificateChain() {
		return certificateChain;
	}
}