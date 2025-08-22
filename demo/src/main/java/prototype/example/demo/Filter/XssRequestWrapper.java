package prototype.example.demo.Filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import java.util.regex.Pattern;


public class XssRequestWrapper extends HttpServletRequestWrapper {

    private static final PolicyFactory POLICY_FACTORY = new HtmlPolicyBuilder().toFactory();
    private static final Pattern HTML_TAG_PATTERN = Pattern.compile("<[^>]*>", Pattern.CASE_INSENSITIVE);

    public XssRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    private String sanitize(String name, String value) {
        if (value == null || value.trim().isEmpty()) {
            return value;
        }
        // 'email' 파라미터는 정화하지 않음
        if ("email".equalsIgnoreCase(name)) {
            return value;
        }
        return POLICY_FACTORY.sanitize(value);
    }

    // 파라미터 값 정화
    @Override
    public String getParameter(String name) {
        String value = super.getParameter(name);
        return value == null ? null : sanitize(name, value);
    }

    // 파라미터 값 배열 정화
    @Override
    public String[] getParameterValues(String name) {
        String[] values = super.getParameterValues(name);
        if (values == null) {
            return null;
        }
        String[] sanitizedValues = new String[values.length];
        for (int i = 0; i < values.length; i++) {
            sanitizedValues[i] = sanitize(name, values[i]);
        }
        return sanitizedValues;
    }

    // 헤더 정화
    @Override
    public String getHeader(String name) {
        String value = super.getHeader(name);
        return value == null ? null : sanitize(name, value);
    }

    // OWASP Sanitizer를 사용하여 문자열을 정화하는 메서드
    private String sanitize(String value) {
        if (value == null || value.trim().isEmpty()) {
            return value;
        }
        return POLICY_FACTORY.sanitize(value);
    }
}