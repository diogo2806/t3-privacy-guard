package br.com.privacyguard.runtime.egress;

import br.com.privacyguard.runtime.store.PrivateProfileStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.SortedMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class HttpProtectedEgress implements ProtectedEgress {
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{([^{}]*)}}");
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;

    private final PrivateProfileStore profiles;
    private final ObjectMapper mapper;
    private final HttpClient client;
    private final Duration timeout;

    public HttpProtectedEgress(
        PrivateProfileStore profiles,
        ObjectMapper mapper,
        @Value("${guard-runtime.egress.timeout-ms:15000}") long timeoutMs
    ) {
        this.profiles = profiles;
        this.mapper = mapper;
        this.timeout = Duration.ofMillis(timeoutMs);
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    }

    @Override
    public Response post(String url, Map<String, String> headers, SortedMap<String, String> body) {
        byte[] payload = serialize(resolvePlaceholders(body));
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
            .timeout(timeout)
            .POST(HttpRequest.BodyPublishers.ofByteArray(payload));
        headers.forEach(request::header);
        try {
            HttpResponse<InputStream> response = client.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = response.body()) {
                return new Response(response.statusCode(), in.readNBytes(MAX_RESPONSE_BYTES));
            }
        } catch (IOException ex) {
            throw new EgressException(EgressException.Kind.UPSTREAM_ERROR, ex.getClass().getSimpleName());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new EgressException(EgressException.Kind.UPSTREAM_ERROR, "interrupted");
        }
    }

    /** Placeholders are replaced inside JSON string values, so a private value can never alter the JSON structure. */
    ObjectNode resolvePlaceholders(SortedMap<String, String> body) {
        ObjectNode resolved = mapper.createObjectNode();
        body.forEach((key, value) -> resolved.put(key, resolve(value)));
        return resolved;
    }

    private String resolve(String value) {
        Matcher matcher = PLACEHOLDER.matcher(value);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String path = matcher.group(1);
            String replacement = profiles.resolve(path)
                .orElseThrow(() -> new EgressException(EgressException.Kind.PLACEHOLDER_UNKNOWN, "unresolved placeholder"));
            matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    private byte[] serialize(ObjectNode body) {
        try {
            return mapper.writeValueAsBytes(body);
        } catch (IOException ex) {
            throw new EgressException(EgressException.Kind.UPSTREAM_ERROR, "encoding failed");
        }
    }
}
