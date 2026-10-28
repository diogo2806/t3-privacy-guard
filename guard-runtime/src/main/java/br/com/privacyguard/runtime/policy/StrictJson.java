package br.com.privacyguard.runtime.policy;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * JSON reading with serde_json's strictness: UTF-8 only, no trailing tokens, no type coercion ("true" is not a
 * boolean, 42 is not a string). Duplicate keys are rejected everywhere, which is stricter than serde (serde lets
 * the last duplicate win inside maps and ignores duplicated unknown fields).
 */
final class StrictJson {
    private static final ObjectMapper MAPPER = JsonMapper.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
        .build();

    private StrictJson() {}

    static ObjectNode parseObject(byte[] bytes) {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
        } catch (CharacterCodingException ex) {
            throw new InvalidContractInputException("input is not valid UTF-8");
        }
        JsonNode node;
        try {
            node = MAPPER.readTree(text);
        } catch (IOException ex) {
            throw new InvalidContractInputException("input is not valid JSON");
        }
        if (node == null || !node.isObject()) throw new InvalidContractInputException("input must be a JSON object");
        return (ObjectNode) node;
    }

    static void rejectUnknownFields(ObjectNode object, Set<String> allowed) {
        Iterator<String> names = object.fieldNames();
        while (names.hasNext()) {
            if (!allowed.contains(names.next())) throw new InvalidContractInputException("input contains an unknown field");
        }
    }

    static String requiredString(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || !value.isTextual()) throw new InvalidContractInputException(field + " must be a string");
        return text(value);
    }

    /** Rust Option<String>: missing or null is None. */
    static String optionalString(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || value.isNull()) return null;
        if (!value.isTextual()) throw new InvalidContractInputException(field + " must be a string");
        return text(value);
    }

    /** Rust #[serde(default)] Vec<String>: missing is empty, null is an error. */
    static List<String> stringList(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null) return List.of();
        if (!value.isArray()) throw new InvalidContractInputException(field + " must be an array");
        List<String> result = new ArrayList<>(value.size());
        for (JsonNode item : value) {
            if (!item.isTextual()) throw new InvalidContractInputException(field + " must contain strings");
            result.add(text(item));
        }
        return List.copyOf(result);
    }

    static boolean requiredBoolean(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || !value.isBoolean()) throw new InvalidContractInputException(field + " must be a boolean");
        return value.booleanValue();
    }

    /** Rust #[serde(default)] bool: missing is false, null is an error. */
    static boolean booleanOrFalse(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null) return false;
        if (!value.isBoolean()) throw new InvalidContractInputException(field + " must be a boolean");
        return value.booleanValue();
    }

    static ObjectNode requiredObject(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || !value.isObject()) throw new InvalidContractInputException(field + " must be an object");
        return (ObjectNode) value;
    }

    static String key(String name) {
        if (ContractText.hasUnpairedSurrogate(name)) throw new InvalidContractInputException("input contains invalid Unicode");
        return name;
    }

    private static String text(JsonNode value) {
        String text = value.textValue();
        if (ContractText.hasUnpairedSurrogate(text)) throw new InvalidContractInputException("input contains invalid Unicode");
        return text;
    }
}
