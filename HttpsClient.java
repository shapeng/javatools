/**
* Simple HTTPS Client which accepts any SSL certificate.
* Reference: http://docs.oracle.com/cd/E19226-01/820-7627/bncbs/index.html
**/

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.codec.binary.Base64;
 
public class HttpsClient {
    private HttpsURLConnection connection;
    private String user = "MyUser";
    private String password = "MyPass";
 
    // Create a trust manager that does not validate certificate chains
    private static TrustManager[] TRUST_ALL_CERTIFICATES = new TrustManager[] {
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) { }
            public void checkServerTrusted(X509Certificate[] certs, String authType) { }
        }
    };
    private static HostnameVerifier HOSTNAME_VERIFIER = new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) { return true; }
    };         
     
    public InputStream getInputStream() throws IOException {
        if (this.connection == null) {
            throw new IOException("Connection is not initialized.");
        }
        return this.connection.getInputStream();
    }
     
    public void connectUsingGet(String url) {
        if (this.connection == null) {
            try {
                // using basic authentication with username and password
                byte[] encoding = Base64.encodeBase64((this.user + ":" + this.password).getBytes());
                this.connection = getConnection(url);
                this.connection.setRequestMethod("GET");
                this.connection.setDoOutput(true);
                this.connection.setRequestProperty("Authorization", "Basic " + new String(encoding));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
     
    public void connectUsingPost(String url) {
        if (this.connection == null) {
            try {
                // using basic authentication with username and password
                byte[] encoding = Base64.encodeBase64((this.user + ":" + this.password).getBytes());
                this.connection = getConnection(url);
                this.connection.setRequestMethod("POST");
                this.connection.setDoOutput(true);
                this.connection.setRequestProperty("Authorization", "Basic " + new String(encoding));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
     
    public HttpsURLConnection getConnection(String urlString) throws NoSuchAlgorithmException, KeyManagementException, IOException {
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, TRUST_ALL_CERTIFICATES, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(HOSTNAME_VERIFIER);
             
        URL url = new URL(urlString);
        return (HttpsURLConnection) url.openConnection();
    }
     
    public void disconnect() {
        if (this.connection != null) {
            this.connection.disconnect();
        }
    }
    public void setUser(String user) { this.user = user; }
    public void setPassword(String password) { this.password = password; }
}
