package br.com.privacyguard.runtime.policy;

import br.com.privacyguard.runtime.contract.CanonicalJson;
import br.com.privacyguard.runtime.contract.ContractText;
import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import br.com.privacyguard.runtime.contract.StrictJson;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Port of policy.rs parse_policy_document: validation, canonicalization and hash. */
public final class PolicyDocumentParser {
    public static final int MAX_POLICY_BYTES = 32 * 1024;
    private static final int MAX_ACTIONS = 16;
    private static final int MAX_FIELDS = 64;
    private static final int MAX_HOSTS = 16;
    private static final int MAX_PRIVATE_REFS = 8;
    private static final int MAX_VERSION_LEN = 64;
    private static final int MAX_NAME_LEN = 80;
    static final int MAX_HOST_LEN = 253;

    static final Set<String> FORBIDDEN_SECRET_FIELDS = Set.of(
        "api_key", "card_number", "credential", "cpf", "password", "private_key", "secret", "ssn", "token"
    );
    static final Set<String> KNOWN_PRIVATE_REFS = Set.of("verified_email");

    private static final Set<String> DOCUMENT_FIELDS = Set.of("version", "actions");
    private static final Set<String> ACTION_FIELDS = Set.of(
        "purpose", "allowed_fields", "allowed_hosts", "allowed_private_refs", "requires_host", "requires_human_authorization"
    );

    private PolicyDocumentParser() {}

    public static AppliedPolicy parse(byte[] bytes) {
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_POLICY_BYTES) {
            throw new PolicyDocumentException("policy document is missing or exceeds the maximum size");
        }
        RawDocument parsed = readShape(bytes);
        String version = ContractText.trim(parsed.version());
        if (!isValidVersion(version)) throw new PolicyDocumentException("policy version is missing or invalid");
        if (parsed.actions().isEmpty() || parsed.actions().size() > MAX_ACTIONS) {
            throw new PolicyDocumentException("policy action count is invalid");
        }

        TreeMap<String, PolicyDocument.ActionPolicy> canonicalActions = new TreeMap<>(ContractText.CODE_POINT_ORDER);
        for (Map.Entry<String, RawAction> entry : parsed.actions().entrySet()) {
            String rawAction = entry.getKey();
            RawAction rule = entry.getValue();
            String action = ContractText.normalized(rawAction);
            if (action.isEmpty() || ContractText.utf8Length(action) > MAX_NAME_LEN || !action.equals(ContractText.trim(rawAction))) {
                throw new PolicyDocumentException("policy action name is not canonical");
            }
            if (canonicalActions.containsKey(action)) throw new PolicyDocumentException("policy contains duplicate normalized actions");
            String purpose = ContractText.normalized(rule.purpose());
            if (purpose.isEmpty() || ContractText.utf8Length(purpose) > MAX_NAME_LEN) {
                throw new PolicyDocumentException("policy purpose is invalid");
            }
            List<String> allowedFields = canonicalList(rule.allowedFields(), MAX_FIELDS, MAX_NAME_LEN, "allowed_fields");
            if (allowedFields.stream().anyMatch(FORBIDDEN_SECRET_FIELDS::contains)) {
                throw new PolicyDocumentException("policy attempts to allow a contract-forbidden secret field");
            }
            List<String> allowedHosts = canonicalList(rule.allowedHosts(), MAX_HOSTS, MAX_HOST_LEN, "allowed_hosts");
            if (allowedHosts.stream().anyMatch(host -> !validHost(host))) {
                throw new PolicyDocumentException("policy contains an invalid destination host");
            }
            if (!rule.requiresHost() && !allowedHosts.isEmpty()) {
                throw new PolicyDocumentException("policy cannot declare hosts for an action without egress");
            }
            if (rule.requiresHost() && allowedHosts.isEmpty()) {
                throw new PolicyDocumentException("policy requires a host but declares no allowed hosts");
            }
            List<String> allowedPrivateRefs = canonicalList(rule.allowedPrivateRefs(), MAX_PRIVATE_REFS, MAX_NAME_LEN, "allowed_private_refs");
            if (allowedPrivateRefs.stream().anyMatch(value -> !KNOWN_PRIVATE_REFS.contains(value))) {
                throw new PolicyDocumentException("policy attempts to enable an unknown private-data reference");
            }
            canonicalActions.put(action, new PolicyDocument.ActionPolicy(
                purpose, allowedFields, allowedHosts, allowedPrivateRefs, rule.requiresHost(), rule.requiresHumanAuthorization()
            ));
        }

        PolicyDocument document = new PolicyDocument(version, canonicalActions);
        return new AppliedPolicy(document, version, sha256Hex(canonicalBytes(document)));
    }

    /** serde_json::to_vec of the Rust PolicyDocument: compact, struct field order, actions in code point order. */
    public static byte[] canonicalBytes(PolicyDocument document) {
        StringBuilder out = new StringBuilder(1024);
        out.append("{\"version\":");
        CanonicalJson.appendString(out, document.version());
        out.append(",\"actions\":{");
        boolean first = true;
        for (Map.Entry<String, PolicyDocument.ActionPolicy> entry : document.actions().entrySet()) {
            if (!first) out.append(',');
            first = false;
            PolicyDocument.ActionPolicy rule = entry.getValue();
            CanonicalJson.appendString(out, entry.getKey());
            out.append(":{\"purpose\":");
            CanonicalJson.appendString(out, rule.purpose());
            out.append(",\"allowed_fields\":");
            CanonicalJson.appendStringArray(out, rule.allowedFields());
            out.append(",\"allowed_hosts\":");
            CanonicalJson.appendStringArray(out, rule.allowedHosts());
            out.append(",\"allowed_private_refs\":");
            CanonicalJson.appendStringArray(out, rule.allowedPrivateRefs());
            out.append(",\"requires_host\":").append(rule.requiresHost());
            out.append(",\"requires_human_authorization\":").append(rule.requiresHumanAuthorization());
            out.append('}');
        }
        out.append("}}");
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    static boolean validHost(String host) {
        return !host.isEmpty()
            && ContractText.utf8Length(host) <= MAX_HOST_LEN
            && !host.contains("/")
            && !host.contains(":")
            && !host.contains("@")
            && !ContractText.containsWhitespace(host);
    }

    /** Canonical version string: 1-64 ASCII letters, digits, ".", "-", "_" or ":". */
    public static boolean isValidVersion(String version) {
        if (version == null || version.isEmpty() || ContractText.utf8Length(version) > MAX_VERSION_LEN) return false;
        for (int i = 0; i < version.length(); i++) {
            char current = version.charAt(i);
            boolean asciiAlphanumeric = (current >= 'a' && current <= 'z') || (current >= 'A' && current <= 'Z') || (current >= '0' && current <= '9');
            if (!asciiAlphanumeric && current != '.' && current != '-' && current != '_' && current != ':') return false;
        }
        return true;
    }

    private static List<String> canonicalList(List<String> values, int maxItems, int maxLen, String label) {
        if (values.size() > maxItems) throw new PolicyDocumentException("policy " + label + " exceeds item limit");
        TreeSet<String> normalizedValues = new TreeSet<>(ContractText.CODE_POINT_ORDER);
        for (String raw : values) {
            String value = ContractText.normalized(raw);
            if (value.isEmpty() || ContractText.utf8Length(value) > maxLen) {
                throw new PolicyDocumentException("policy " + label + " contains an invalid value");
            }
            if (!normalizedValues.add(value)) {
                throw new PolicyDocumentException("policy " + label + " contains a duplicate normalized value");
            }
        }
        return List.copyOf(normalizedValues);
    }

    /** serde deserializes the whole document before any validation, so shape errors always win. */
    private static RawDocument readShape(byte[] bytes) {
        try {
            ObjectNode root = StrictJson.parseObject(bytes);
            StrictJson.rejectUnknownFields(root, DOCUMENT_FIELDS);
            String version = StrictJson.requiredString(root, "version");
            ObjectNode actionsNode = StrictJson.requiredObject(root, "actions");
            TreeMap<String, RawAction> actions = new TreeMap<>(ContractText.CODE_POINT_ORDER);
            Iterator<Map.Entry<String, JsonNode>> entries = actionsNode.fields();
            while (entries.hasNext()) {
                Map.Entry<String, JsonNode> entry = entries.next();
                if (!entry.getValue().isObject()) throw new InvalidContractInputException("action rule must be an object");
                ObjectNode rule = (ObjectNode) entry.getValue();
                StrictJson.rejectUnknownFields(rule, ACTION_FIELDS);
                actions.put(StrictJson.key(entry.getKey()), new RawAction(
                    StrictJson.requiredString(rule, "purpose"),
                    StrictJson.stringList(rule, "allowed_fields"),
                    StrictJson.stringList(rule, "allowed_hosts"),
                    StrictJson.stringList(rule, "allowed_private_refs"),
                    StrictJson.requiredBoolean(rule, "requires_host"),
                    StrictJson.booleanOrFalse(rule, "requires_human_authorization")
                ));
            }
            return new RawDocument(version, actions);
        } catch (InvalidContractInputException ex) {
            throw new PolicyDocumentException("policy document is not valid JSON");
        }
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    private record RawDocument(String version, TreeMap<String, RawAction> actions) {}

    private record RawAction(
        String purpose,
        List<String> allowedFields,
        List<String> allowedHosts,
        List<String> allowedPrivateRefs,
        boolean requiresHost,
        boolean requiresHumanAuthorization
    ) {}
}
