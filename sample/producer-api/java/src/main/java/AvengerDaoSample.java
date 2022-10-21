import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AvengerDaoSample {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        //Incoming information from post request
        String body = "{\"address\":\"0x0000000000000000000000000000000000000003\"}"; // Incoming request body
        String incomingSignature = "6d668a3a07ed9b36418c80911184d8981dbf815085f1eb97a1e536282db0b1e2"; // 'X-Signature-signature' header
        String appId = "000000000000000000000000000000000000000000000000000000000000000001"; // 'X-Signature-appid' header
        String timeStamp = "1666255054045"; // 'X-Signature-timestamp' header
        String nonce = "nonce"; // 'X-Signature-nonce' header
        String path = "/api/v1/address-security"; // Provider path
        String method = "POST"; // Provider rest API method
        String data = String.join(";", appId, timeStamp, nonce, method, path, body);

        // Query appSecret using appId
        String appSecret = "000000000000000000000000000000000000000000000000000000000000000002";

        // Generate signature
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(appSecret.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        StringBuilder stringBuilder = new StringBuilder();
        for (byte aByte : mac.doFinal(data.getBytes())) {
            stringBuilder.append(String.format("%02x", aByte));
        }

        String generatedSignature = stringBuilder.toString();

        // Assert signature is valid
        boolean isValidSignature = incomingSignature.equals(generatedSignature);
    }

}
