import javax.servlet.ServletException;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;

import com.xqbase.coyote.DoSHttp11NioProtocol;
import com.xqbase.util.Conf;
import com.xqbase.util.Log;

public class Startup {
	public static void main(String[] args) {
		Connector connector = new Connector(DoSHttp11NioProtocol.class.getName());
		connector.setPort(443);
		connector.setScheme("https");
		connector.setSecure(true);
		connector.setProperty("SSLEnabled", "true");
		connector.setProperty("sslProtocol", "TLS");
		connector.setProperty("dosPeriod", "60");
		connector.setProperty("dosRequests", "300");
		connector.setProperty("dosConnections", "60");
		connector.setProperty("keystorePath",
				Conf.getAbsolutePath("../src/test/etc/pki/tomcat"));
		Tomcat tomcat = new Tomcat();
		tomcat.setPort(443);
		tomcat.getService().addConnector(connector);
		tomcat.setConnector(connector);
		try {
			tomcat.addWebapp("", Conf.getAbsolutePath("../src/test/webapp"));
			tomcat.start();
			Thread.currentThread().join();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		} catch (ServletException | LifecycleException e) {
			Log.e(e);
		}
	}
}