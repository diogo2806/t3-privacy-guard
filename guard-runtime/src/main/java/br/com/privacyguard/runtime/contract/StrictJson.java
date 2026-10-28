package br.com.privacyguard.runtime.contract;

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
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * JSON reading with serde_json's strictness: UTF-8 only, no trailing tokens, no type coercion ("true" is not a
 * boolean, 42 is not a string, 1.0 is not an integer). Duplicate keys are rejected everywhere, which is stricter
 * than serde (serde lets the last duplicate win inside maps and ignores duplicated unknown fields).
 */
public final class StrictJson {
    private static final ObjectMapper MAPPER = JsonMapper.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
        .build();

    private StrictJson() {}

    public static ObjectNode parseObject(byte[] bytes) {
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

    /** Lenient read of an untrusted upstream body: any parse failure is simply "no JSON object". */
    public static ObjectNode parseObjectOrNull(byte[] bytes) {
        try {
            return parseObject(bytes);
        } catch (InvalidContractInputException ex) {
            return null;
        }
    }

    public static void rejectUnknownFields(ObjectNode object, Set<String> allowed) {
        Iterator<String> names = object.fieldNames();
        while (names.hasNext()) {
            if (!allowed.contains(names.next())) throw new InvalidContractInputException("input contains an unknown field");
        }
    }

    public static String requiredString(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || !value.isTextual()) throw new InvalidContractInputException(field + " must be a string");
        return text(value);
    }

    /** Rust Option<String>: missing or null is None. */
    public static String optionalString(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || value.isNull()) return null;
        if (!value.isTextual()) throw new InvalidContractInputException(field + " must be a string");
        return text(value);
    }

    /** Rust #[serde(default)] Vec<String>: missing is empty, null is an error. */
    public static List<String> stringList(ObjectNode object, String field) {
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

    /** Rust #[serde(default)] BTreeMap<String, String>: missing is empty, null is an error, keys in code point order. */
    public static SortedMap<String, String> stringMap(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        TreeMap<String, String> result = new TreeMap<>(ContractText.CODE_POINT_ORDER);
        if (value == null) return result;
        if (!value.isObject()) throw new InvalidContractInputException(field + " must be an object");
        Iterator<Map.Entry<String, JsonNode>> entries = value.fields();
        while (entries.hasNext()) {
            Map.Entry<String, JsonNode> entry = entries.next();
            if (!entry.getValue().isTextual()) throw new InvalidContractInputException(field + " must contain string values");
            result.put(key(entry.getKey()), text(entry.getValue()));
        }
        return result;
    }

    public static boolean requiredBoolean(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || !value.isBoolean()) throw new InvalidContractInputException(field + " must be a boolean");
        return value.booleanValue();
    }

    /** Rust #[serde(default)] bool: missing is false, null is an error. */
    public static boolean booleanOrFalse(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null) return false;
        if (!value.isBoolean()) throw new InvalidContractInputException(field + " must be a boolean");
        return value.booleanValue();
    }

    /** Rust u64: a non-negative JSON integer that fits; floats such as 1.0 are rejected. */
    public static long requiredUnsignedLong(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || !value.isIntegralNumber() || !value.canConvertToLong() || value.longValue() < 0) {
            throw new InvalidContractInputException(field + " must be a non-negative integer");
        }
        return value.longValue();
    }

    public static ObjectNode requiredObject(ObjectNode object, String field) {
        JsonNode value = object.get(field);
        if (value == null || !value.isObject()) throw new InvalidContractInputException(field + " must be an object");
        return (ObjectNode) value;
    }

    public static String key(String name) {
        if (ContractText.hasUnpairedSurrogate(name)) throw new InvalidContractInputException("input contains invalid Unicode");
        return name;
    }

    private static String text(JsonNode value) {
        String text = value.textValue();
        if (ContractText.hasUnpairedSurrogate(text)) throw new InvalidContractInputException("input contains invalid Unicode");
        return text;
    }
}
