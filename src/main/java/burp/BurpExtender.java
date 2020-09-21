package burp;

import pingvin.JwtKeyProvider;
import pingvin.JwtPublicSecretsTab;
import pingvin.JwtScannerCheck;
import pingvin.tokenposition.Config;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Config.stdout = new PrintWriter(callbacks.getStdout(), true);
        Config.stderr = new PrintWriter(callbacks.getStderr(), true);

        Config.loadConfig();
        JwtKeyProvider.loadKeys();

        callbacks.setExtensionName("JWT heartbreaker");

        JwtPublicSecretsTab jwtPublicSecretsTab = new JwtPublicSecretsTab(callbacks);
        callbacks.addSuiteTab(jwtPublicSecretsTab);

        JwtScannerCheck jwtScannerCheck = new JwtScannerCheck(callbacks);
        callbacks.registerScannerCheck(jwtScannerCheck);
    }
}
