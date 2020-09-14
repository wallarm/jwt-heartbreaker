package pingvin.tokenposition.algorithm;

import com.auth0.jwt.algorithms.Algorithm;
import org.apache.commons.lang.RandomStringUtils;
import org.bouncycastle.util.encoders.Base64;
import pingvin.tokenposition.Output;
import pingvin.tokenposition.PublicKeyBroker;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class AlgorithmLinker {

    public static final String[] keyBeginMarkers = new String[]{"-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----"};
    public static final String[] keyEndMarkers = new String[]{"-----END PUBLIC KEY-----", "-----END CERTIFICATE-----"};

    public static final pingvin.tokenposition.algorithm.AlgorithmWrapper none =
            new pingvin.tokenposition.algorithm.AlgorithmWrapper("none", AlgorithmType.none);
    public static final pingvin.tokenposition.algorithm.AlgorithmWrapper HS256 =
            new pingvin.tokenposition.algorithm.AlgorithmWrapper("HS256", AlgorithmType.symmetric);
    public static final pingvin.tokenposition.algorithm.AlgorithmWrapper HS384 =
            new pingvin.tokenposition.algorithm.AlgorithmWrapper("HS384", AlgorithmType.symmetric);
    public static final pingvin.tokenposition.algorithm.AlgorithmWrapper HS512 =
            new pingvin.tokenposition.algorithm.AlgorithmWrapper("HS512", AlgorithmType.symmetric);
    public static final pingvin.tokenposition.algorithm.AlgorithmWrapper RS256 =
            new pingvin.tokenposition.algorithm.AlgorithmWrapper("RS256", AlgorithmType.asymmetric);
    public static final pingvin.tokenposition.algorithm.AlgorithmWrapper RS384 =
            new pingvin.tokenposition.algorithm.AlgorithmWrapper("RS384", AlgorithmType.asymmetric);
    public static final pingvin.tokenposition.algorithm.AlgorithmWrapper RS512 =
            new pingvin.tokenposition.algorithm.AlgorithmWrapper("RS512", AlgorithmType.asymmetric);
    public static final pingvin.tokenposition.algorithm.AlgorithmWrapper ES256 =
            new pingvin.tokenposition.algorithm.AlgorithmWrapper("ES256", AlgorithmType.asymmetric);
    public static final pingvin.tokenposition.algorithm.AlgorithmWrapper ES384 =
            new pingvin.tokenposition.algorithm.AlgorithmWrapper("ES384", AlgorithmType.asymmetric);
    public static final pingvin.tokenposition.algorithm.AlgorithmWrapper ES512 =
            new pingvin.tokenposition.algorithm.AlgorithmWrapper("ES512", AlgorithmType.asymmetric);

    private static final pingvin.tokenposition.algorithm.AlgorithmWrapper[] supportedAlgorithms = {
            none, HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512};

    private static PublicKey generatePublicKeyFromString(String key, String algorithm) {
        PublicKey publicKey = null;
        if (key.length() > 1) {
            key = cleanKey(key);
            byte[] keyByteArray = java.util.Base64.getDecoder().decode(key);
            try {
                KeyFactory kf = KeyFactory.getInstance(algorithm);
                EncodedKeySpec keySpec = new X509EncodedKeySpec(keyByteArray);
                publicKey = kf.generatePublic(keySpec);
            } catch (Exception e) {
                Output.outputError(e.getMessage());
            }
        }
        return publicKey;
    }

    public static String cleanKey(String key) {
        for (String keyBeginMarker : keyBeginMarkers) {
            key = key.replace(keyBeginMarker, "");
        }
        for (String keyEndMarker : keyEndMarkers) {
            key = key.replace(keyEndMarker, "");
        }
        key = key.replaceAll("\\s+", "").replaceAll("\\r+", "").replaceAll("\\n+", "");

        return key;
    }

    private static PrivateKey generatePrivateKeyFromString(String key, String algorithm) {
        PrivateKey privateKey = null;
        if (key.length() > 1) {
            key = cleanKey(key);
            try {
                byte[] keyByteArray = Base64.decode(key);
                KeyFactory kf = KeyFactory.getInstance(algorithm);
                EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyByteArray);
                privateKey = kf.generatePrivate(keySpec);
            } catch (Exception e) {
                Output.outputError("Error generating private key with input string '" + key + "' and algorithm '" + algorithm + "' - " + e.getMessage() + " - ");
            }
        }
        return privateKey;
    }

    /**
     * @param algo
     * @param key  - either the secret or the private key
     * @return the algorithm element from the library, if nothing matches the
     * none algorithm element is returned
     * @throws IllegalArgumentException
     * @throws UnsupportedEncodingException
     */
    public static Algorithm getVerifierAlgorithm(String algo, String key) throws UnsupportedEncodingException {
        return getAlgorithm(algo, key, false);
    }

    public static Algorithm getSignerAlgorithm(String algo, String key) throws UnsupportedEncodingException {
        return getAlgorithm(algo, key, true);
    }

    private static Algorithm getAlgorithm(String algo, String key, boolean IsKeyASignerKey)
            throws IllegalArgumentException, UnsupportedEncodingException {
        if (algo.equals(HS256.getAlgorithm())) {
            return Algorithm.HMAC256(key);
        }
        if (algo.equals(HS384.getAlgorithm())) {
            return Algorithm.HMAC384(key);
        }
        if (algo.equals(HS512.getAlgorithm())) {
            return Algorithm.HMAC512(key);
        }
        if (algo.equals(ES256.getAlgorithm())) {
            return Algorithm.ECDSA256((ECKey) getKeyInstance(key, "EC", IsKeyASignerKey));
        }
        if (algo.equals(ES384.getAlgorithm())) {
            return Algorithm.ECDSA384((ECKey) getKeyInstance(key, "EC", IsKeyASignerKey));
        }
        if (algo.equals(ES512.getAlgorithm())) {
            return Algorithm.ECDSA512((ECKey) getKeyInstance(key, "EC", IsKeyASignerKey));
        }
        if (algo.equals(RS256.getAlgorithm())) {
            return Algorithm.RSA256((RSAKey) getKeyInstance(key, "RSA", IsKeyASignerKey));
        }
        if (algo.equals(RS384.getAlgorithm())) {
            return Algorithm.RSA384((RSAKey) getKeyInstance(key, "RSA", IsKeyASignerKey));
        }
        if (algo.equals(RS512.getAlgorithm())) {
            return Algorithm.RSA512((RSAKey) getKeyInstance(key, "RSA", IsKeyASignerKey));
        }

        return Algorithm.none();
    }

    private static Key getKeyInstance(String key, String algorithm, boolean isPrivate) {
        return isPrivate ? generatePrivateKeyFromString(key, algorithm) : generatePublicKeyFromString(key, algorithm);
    }

    public static String getRandomKey(String algorithm) {
        String algorithmType = AlgorithmLinker.getTypeOf(algorithm);

        if (algorithmType.equals(AlgorithmType.symmetric)) {
            return RandomStringUtils.randomAlphanumeric(6);
        }
        if (algorithmType.equals(AlgorithmType.asymmetric) && algorithm.startsWith("RS")) {
            try {
                KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
                PublicKeyBroker.publicKey = Base64.toBase64String(keyPair.getPublic().getEncoded());
                return Base64.toBase64String((keyPair.getPrivate().getEncoded()));
            } catch (NoSuchAlgorithmException e) {
                Output.outputError(e.getMessage());
            }
        }
        if (algorithmType.equals(AlgorithmType.asymmetric) && algorithm.startsWith("ES")) {
            try {
                KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
                return Base64.toBase64String(keyPair.getPrivate().getEncoded());
            } catch (NoSuchAlgorithmException e) {
                Output.outputError(e.getMessage());
            }
        }
        throw new RuntimeException("Cannot get random key of provided algorithm as it does not seem valid HS, RS or ES");
    }

    /**
     * @return gets the type (asym, sym, none) of the provided @param algo
     */
    public static String getTypeOf(String algorithm) {
        for (pingvin.tokenposition.algorithm.AlgorithmWrapper supportedAlgorithm : supportedAlgorithms) {
            if (algorithm.equals(supportedAlgorithm.getAlgorithm())) {
                return supportedAlgorithm.getType();
            }
        }
        return AlgorithmType.none;
    }

    public static pingvin.tokenposition.algorithm.AlgorithmWrapper[] getSupportedAlgorithms() {
        return supportedAlgorithms;
    }
}
