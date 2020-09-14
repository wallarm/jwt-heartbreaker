package pingvin.tokenposition;

import java.util.List;

// finds and replaces JWT's in authorization headers
public class AuthorizationBearerHeader extends ITokenPosition {
    private String selectedKeyword;
    private Integer headerIndex;
    private final List<String> headers;

    public AuthorizationBearerHeader(List<String> headers, String bodyP) {
        this.headers = headers;
    }

    public boolean positionFound() {
        for (int counter = 0; counter < headers.size(); counter++) {
            if (headerContainsaKeyWordAndIsJWT(headers.get(counter), Config.jwtKeywords)) {
                this.headerIndex = counter;
                return true;
            }
        }
        return false;
    }

    private boolean headerContainsaKeyWordAndIsJWT(String header, List<String> jwtKeywords) {
        for (String keyword : jwtKeywords) {
            if (header.startsWith(keyword)) {
                String jwt = header.replace(keyword, "").trim();
                if (CustomJWToken.isValidJWT(jwt)) {
                    this.selectedKeyword = keyword;
                    return true;
                }
            }
        }
        return false;
    }

    public String getToken() {
        if (this.headerIndex == null) {
            return "";
        }
        return headers.get(this.headerIndex).substring(this.selectedKeyword.length() + 1);
    }

}
