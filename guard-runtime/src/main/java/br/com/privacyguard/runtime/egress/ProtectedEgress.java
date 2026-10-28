package br.com.privacyguard.runtime.egress;

import java.util.Map;
import java.util.SortedMap;

/**
 * Replaces T3N's http-with-placeholders host call: the body may contain {{profile.*}} markers, which are resolved
 * against the private profile only here, right before the bytes leave the runtime.
 */
public interface ProtectedEgress {
    Response post(String url, Map<String, String> headers, SortedMap<String, String> body);

    record Response(int code, byte[] payload) {
        public Response {
            payload = payload.clone();
        }

        @Override
        public byte[] payload() {
            return payload.clone();
        }
    }
}
