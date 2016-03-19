import com.xqbase.util.ByteArrayQueue;
import com.xqbase.util.http.HttpUtil;

public class Attack {
	public static void main(String[] args) throws Exception {
		int bytes = 0;
		long t = System.currentTimeMillis();
		for (int i = 0; i < 10000; i ++) {
			ByteArrayQueue baq = new ByteArrayQueue();
			int status = HttpUtil.get("http://localhost/favicon.ico", null, baq, null, 15000);
			bytes += baq.length();
			if (status == 200) {
				System.out.println("OK [" + i + "]: " + baq.length() + ", " +
						bytes / (System.currentTimeMillis() - t) + "K/Sec");
			} else {
				System.out.println("ERROR [" + i + "]: " + status);
			}
		}
	}
}