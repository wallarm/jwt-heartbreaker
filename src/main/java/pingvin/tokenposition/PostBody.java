package pingvin.tokenposition;

import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class PostBody extends ITokenPosition {
    private String token;
    private boolean found = false;
    private String body;


    public PostBody(List<String> headersP, String bodyP) {
        body = bodyP;
    }

    @Override
    public boolean positionFound() {
        if (isRequest) {
            KeyValuePair postJWT = getJWTFromPostBody();
            if (postJWT != null) {
                found = true;
                token = postJWT.getValue();
                return true;
            }
        }
        return false;
    }

    public KeyValuePair getJWTFromPostBody() {
        int from = 0;
        int index = body.indexOf("&") == -1 ? body.length() : body.indexOf("&");
        int parameterCount = StringUtils.countMatches(body, "&") + 1;

        List<KeyValuePair> postParameterList = new ArrayList<KeyValuePair>();
        for (int i = 0; i < parameterCount; i++) {
            String parameter = body.substring(from, index);
            parameter = parameter.replace("&", "");

            String[] parameterSplit = parameter.split(Pattern.quote("="));
            if (parameterSplit.length > 1) {
                String name = parameterSplit[0];
                String value = parameterSplit[1];
                postParameterList.add(new KeyValuePair(name, value));
                from = index;
                index = body.indexOf("&", index + 1);
                if (index == -1) {
                    index = body.length();
                }
            }
        }
        for (String keyword : Config.tokenKeywords) {
            for (KeyValuePair postParameter : postParameterList) {
                if (keyword.equals(postParameter.getName())
                        && TokenCheck.isValidJWT(postParameter.getValue())) {
                    return postParameter;
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
