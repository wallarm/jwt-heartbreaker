package pingvin.tokenposition;

import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.util.Arrays;
import java.util.List;

public abstract class ITokenPosition {

    protected IExtensionHelpers helpers;
    protected byte[] message;
    protected boolean isRequest;

    public abstract boolean positionFound();

    public abstract String getToken();

    public void setMessage(byte[] message, boolean isRequest) {
        this.message = message;
        this.isRequest = isRequest;
    }

    public void setHelpers(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    public static ITokenPosition findTokenPositionImplementation(byte[] content, boolean isRequest, IExtensionHelpers helpers) {
        List<Class<? extends ITokenPosition>> implementations = Arrays.asList(AuthorizationBearerHeader.class, PostBody.class, Cookie.class, Body.class);
        if (content == null) {
            return new Dummy();
        }
        for (Class<? extends ITokenPosition> implClass : implementations) {
            try {
                List<String> headers;
                int bodyOffset;
                if (isRequest) {
                    IRequestInfo requestInfo = helpers.analyzeRequest(content);
                    headers = requestInfo.getHeaders();
                    bodyOffset = requestInfo.getBodyOffset();
                } else {
                    IResponseInfo responseInfo = helpers.analyzeResponse(content);
                    headers = responseInfo.getHeaders();
                    bodyOffset = responseInfo.getBodyOffset();
                }
                String body = new String(Arrays.copyOfRange(content, bodyOffset, content.length));
                ITokenPosition impl = (ITokenPosition) implClass.getConstructors()[0].newInstance(headers, body);

                impl.setHelpers(helpers);
                impl.setMessage(content, isRequest);
                if (impl.positionFound()) {
                    return impl;
                }
            } catch (Exception e) {
                // sometimes 'isEnabled' is called in order to build the views
                // before an actual request / response passes through - in that case
                // it is not worth reporting
                if (!e.getMessage().equals("Request cannot be null") && !e.getMessage().equals("1")) {
                    Output.outputError(e.getMessage());
                }
                return null;
            }
        }
        return null;
    }

}
