package pingvin;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;
import lombok.Data;
import lombok.experimental.Accessors;

import java.net.URL;

@Data
@Accessors(chain = true)
public class JwtTokenKeyScannerIssue implements IScanIssue {

    private URL url;
    private String issueName;
    private int issueType;
    private String severity;
    private String confidence;
    private String issueBackground;
    private String remediationBackground;
    private String issueDetail;
    private String remediationDetail;
    private IHttpRequestResponse[] httpMessages;
    private IHttpService httpService;

}
