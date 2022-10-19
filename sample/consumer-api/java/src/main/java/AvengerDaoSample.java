import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

public class AvengerDaoSample {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        // you should provide appId, appSecret and address
        String appId = "000000000000000000000000000000000000000000000000000000000000000001";
        String appSecret = "000000000000000000000000000000000000000000000000000000000000000002";
        String body = "{\"address\":\"0x0000000000000000000000000000000000000003\"}";

        String timeStamp = Long.toString(System.currentTimeMillis());
        String host = "https://avengerdao.org";
        String path = "/api/v1/address-security";
        String data = String.join(";", appId, timeStamp, "nonce", "POST", path, body);

        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(appSecret.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        StringBuilder stringBuilder = new StringBuilder();
        for (byte aByte : mac.doFinal(data.getBytes())) {
            stringBuilder.append(String.format("%02x", aByte));
        }

        String hashInHex = stringBuilder.toString();
        StringEntity requestEntity = new StringEntity(
            body,
            ContentType.APPLICATION_JSON
        );

        HttpPost post = new HttpPost(host + path);
        post.setHeader("Content-Type", "application/json");
        post.setHeader("X-Signature-signature", hashInHex);
        post.setHeader("X-Signature-appid", appId);
        post.setHeader("X-Signature-timestamp", timeStamp);
        post.setHeader("X-Signature-nonce", "nonce");
        post.setEntity(requestEntity);

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(post)) {

            System.out.println(EntityUtils.toString(response.getEntity()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
