package pingvin.tokenposition;

import org.apache.commons.lang.StringUtils;

import java.util.List;
import java.util.regex.Pattern;

//finds and replaces JWT's in cookies
public class Cookie extends ITokenPosition {

    private boolean found;
    private String token;
    private List<String> headers;

    public Cookie(List<String> headersP, String bodyP) {
        headers = headersP;
    }

    @Override
    public boolean positionFound() {
        String jwt = findJWTInHeaders(headers);
        if (jwt != null) {
            found = true;
            token = jwt;
            return true;
        }
        return false;
    }

    // finds the first jwt in the set-cookie or cookie header(s)
    public String findJWTInHeaders(List<String> headers) {
        for (String header : headers) {
            if (header.startsWith("Set-Cookie: ")) {
                String cookie = header.replace("Set-Cookie: ", "");
                if (cookie.length() > 1 && cookie.contains("=")) {
                    String value = cookie.split(Pattern.quote("="))[1];
                    int flagMarker = value.indexOf(";");
                    if (flagMarker != -1) {
                        value = value.substring(0, flagMarker);
                    }
                    TokenCheck.isValidJWT(value);
                    if (TokenCheck.isValidJWT(value)) {
                        found = true;
                        token = value;
                        return value;
                    }
                }
            }
            if (header.startsWith("Cookie: ")) {
                String cookieHeader = header.replace("Cookie: ", "");
                cookieHeader = cookieHeader.endsWith(";") ? cookieHeader : cookieHeader + ";";
                int from = 0;
                int index = cookieHeader.indexOf(";");
                int cookieCount = StringUtils.countMatches(cookieHeader, ";");
                for (int i = 0; i < cookieCount; i++) {
                    String cookie = cookieHeader.substring(from, index);
                    cookie = cookie.replace(";", "");
                    String[] cvp = cookie.split(Pattern.quote("="));
                    String value = cvp.length == 2 ? cvp[1] : "";
                    if (TokenCheck.isValidJWT(value)) {
                        found = true;
                        token = value;
                        return value;
                    }
                    from = index;
                    index = cookieHeader.indexOf(";", index + 1);
                    if (index == -1) {
                        index = cookieHeader.length();
                    }
                }
            }
        }
        return null;
    }

    @Override
    public String getToken() {
        return found ? token : "";
    }

}
