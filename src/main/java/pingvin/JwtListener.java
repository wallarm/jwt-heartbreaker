package pingvin;

import burp.*;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import pingvin.tokenposition.CustomJWToken;
import pingvin.tokenposition.ITokenPosition;
import pingvin.tokenposition.Output;
import pingvin.tokenposition.algorithm.AlgorithmLinker;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;

public class JwtListener implements IHttpListener {

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;

    public JwtListener(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
    }

    public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse messageInfo) {
        byte[] content = isRequest ? messageInfo.getRequest() : messageInfo.getResponse();

        final ITokenPosition token = ITokenPosition.findTokenPositionImplementation(content, isRequest, helpers);
        if (token == null) {
            return;
        }

        String tokenWithoutPrefix = lal(token.getToken());

        IScanIssue[] currentIssues = callbacks.getScanIssues(null);
        for (IScanIssue currentIssue : currentIssues) {
            if (currentIssue.getIssueDetail() != null && currentIssue.getIssueDetail().contains(tokenWithoutPrefix)) {
//                messageInfo.setHighlight("blue");
                return;
            }
        }

        String curAlgo = new CustomJWToken(tokenWithoutPrefix).getAlgorithm();
        for (String key : JwtKeyProvider.getKeys()) {
            try {
                JWTVerifier verifier = JWT.require(AlgorithmLinker.getVerifierAlgorithm(curAlgo, key)).build();
                verifier.verify(tokenWithoutPrefix);

//                messageInfo.setComment(String.format("JWT Key: %s", key));
//                messageInfo.setHighlight("blue");

                JwtTokenKeyScannerIssue jwtTokenKeyScannerIssue = new JwtTokenKeyScannerIssue()
                        .setUrl(new URL("https://url"))
                        .setIssueName("Found public JWT secret")
                        .setIssueType(0x00200200)
                        .setSeverity("High")
                        .setConfidence("Certain")
                        .setIssueBackground(null)
                        .setRemediationBackground(null)
                        .setIssueDetail(String.format("Token: %s%nKey: %s", tokenWithoutPrefix, key))
                        .setRemediationDetail("Change JWT sing key")
                        .setHttpMessages(new IHttpRequestResponse[]{messageInfo})
                        .setHttpService(messageInfo.getHttpService());
                callbacks.addScanIssue(jwtTokenKeyScannerIssue);
                return;
            } catch (UnsupportedEncodingException | MalformedURLException e) {
                Output.output("Verification failed (" + e.getMessage() + ")");
            } catch (JWTVerificationException e) {
                // do nothing
            }
        }
    }

    private String lal(String jwts) {
        jwts = jwts.replace("Authorization:", "");
        jwts = jwts.replace("Bearer", "");
        jwts = jwts.replace("Set-Cookie: ", "");
        jwts = jwts.replace("Cookie: ", "");
        jwts = jwts.replaceAll("\\s", "");

        return jwts;
    }
}
