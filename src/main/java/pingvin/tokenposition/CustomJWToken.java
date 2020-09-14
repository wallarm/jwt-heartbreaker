package pingvin.tokenposition;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;

/*
 * This Class is implemented separately to get raw access to the content of the Tokens.
 * The JWTDecoder class cannot be extended because it is final
 */

public class CustomJWToken extends JWT {
    private String headerJson;
    private String payloadJson;
    private byte[] signature;

    public CustomJWToken(String token) {
        if (token != null) {
            final String[] parts = splitToken(token);
            try {
                headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
                payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
            } catch (NullPointerException e) {
                Output.outputError("The UTF-8 Charset isn't initialized (" + e.getMessage() + ")");
            }
            signature = Base64.decodeBase64(parts[2]);
        }
    }

    public String getHeaderJson() {
        return headerJson;
    }

    public String getPayloadJson() {
        return payloadJson;
    }

    public JsonNode getHeaderJsonNode() {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.readTree(getHeaderJson());
        } catch (IOException e) {
            Output.outputError("IO exception reading json tree (" + e.getMessage() + ")");
            return null;
        }
    }

    private String jsonMinify(String json) {
        try {
            String jsonMinify = new Minify().minify(json);
            return jsonMinify;
        } catch (Exception e) {
            Output.outputError("Could not minify json: " + e.getMessage());
            return null;
        }
    }

    @Override
    public String getToken() {
        if (jsonMinify(getHeaderJson()) != null && jsonMinify(getPayloadJson()) != null) {
            String content = String.format("%s.%s", b64(jsonMinify(getHeaderJson())), b64(jsonMinify((getPayloadJson()))));
            String signatureEncoded = Base64.encodeBase64URLSafeString(this.signature);
            return String.format("%s.%s", content, signatureEncoded);
        }
        return null;
    }

    private String b64(String input) {
        return Base64.encodeBase64URLSafeString(input.getBytes(StandardCharsets.UTF_8));
    }

    public static boolean isValidJWT(String token) {
        if (org.apache.commons.lang.StringUtils.countMatches(token, ".") != 2) {
            return false;
        }
        try {
            JWT.decode(token);
            return true;
        } catch (JWTDecodeException exception) {
        }
        return false;
    }

    // Method copied from:
    // https://github.com/auth0/java-jwt/blob/9148ca20adf679721591e1d012b7c6b8c4913d75/lib/src/main/java/com/auth0/jwt/TokenUtils.java#L14
    // Cannot be reused, it's visibility is protected.
    static String[] splitToken(String token) throws JWTDecodeException {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            // Tokens with alg='none' have empty String as Signature.
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new JWTDecodeException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }

    @Override
    public List<String> getAudience() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Claim getClaim(String arg0) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Map<String, Claim> getClaims() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Date getExpiresAt() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getId() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Date getIssuedAt() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getIssuer() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Date getNotBefore() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getSubject() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getAlgorithm() {
        String algorithm = "";
        try {
            algorithm = getHeaderJsonNode().get("alg").asText();
        } catch (Exception e) {
        }
        return algorithm;
    }

    @Override
    public String getContentType() {
        return getHeaderJsonNode().get("typ").asText();
    }

    @Override
    public Claim getHeaderClaim(String arg0) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getKeyId() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getType() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getSignature() {
        return Base64.encodeBase64URLSafeString(this.signature);
    }

}
