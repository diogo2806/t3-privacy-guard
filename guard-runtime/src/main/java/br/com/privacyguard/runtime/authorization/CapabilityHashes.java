package br.com.privacyguard.runtime.authorization;

import br.com.privacyguard.runtime.contract.CanonicalJson;
import br.com.privacyguard.runtime.contract.ContractText;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;

/** Request bindings hashed into the capability; must equal what the backend signer and the gateway compute. */
public final class CapabilityHashes {
    private CapabilityHashes() {}

    /** list_hash: trimmed values, sorted, compact JSON array, SHA-256 hex. */
    public static String listHash(List<String> values) {
        List<String> canonical = new ArrayList<>(values.size());
        for (String value : values) canonical.add(ContractText.trim(value));
        canonical.sort(ContractText.CODE_POINT_ORDER);
        return sha256Hex(CanonicalJson.stringArray(canonical));
    }

    /** normal_payload_hash: "<key bytes>:<key>=<value bytes>:<value>\n" per entry in key order, SHA-256 hex. */
    public static String normalPayloadHash(SortedMap<String, String> payload) {
        StringBuilder canonical = new StringBuilder();
        for (Map.Entry<String, String> entry : payload.entrySet()) {
            canonical.append(ContractText.utf8Length(entry.getKey())).append(':').append(entry.getKey())
                .append('=').append(ContractText.utf8Length(entry.getValue())).append(':').append(entry.getValue())
                .append('\n');
        }
        return sha256Hex(canonical.toString().getBytes(StandardCharsets.UTF_8));
    }

    static String sha256Hex(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }
}
