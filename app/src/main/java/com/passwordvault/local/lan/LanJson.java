package com.passwordvault.local.lan;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small JSON codec for LAN envelopes. It accepts only the JSON types used by this protocol. */
final class LanJson {
    private LanJson() { }

    static Object parse(String input) {
        if (input == null) throw new IllegalArgumentException("JSON body is required");
        Parser parser = new Parser(input);
        Object value = parser.value();
        parser.space();
        if (!parser.end()) throw new IllegalArgumentException("Unexpected JSON trailing data");
        return value;
    }

    static String stringify(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value);
        return out.toString();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(Object value) {
        if (!(value instanceof Map)) throw new IllegalArgumentException("JSON object required");
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    static List<Object> array(Object value) {
        if (!(value instanceof List)) throw new IllegalArgumentException("JSON array required");
        return (List<Object>) value;
    }

    static String string(Map<String, Object> object, String name) {
        Object value = object.get(name);
        if (!(value instanceof String)) throw new IllegalArgumentException("String field required: " + name);
        return (String) value;
    }

    static String nullableString(Map<String, Object> object, String name) {
        Object value = object.get(name);
        if (value == null) return null;
        if (!(value instanceof String)) throw new IllegalArgumentException("String field required: " + name);
        return (String) value;
    }

    static long number(Map<String, Object> object, String name) {
        Object value = object.get(name);
        if (!(value instanceof Long)) throw new IllegalArgumentException("Integer field required: " + name);
        return ((Long) value).longValue();
    }

    private static void write(StringBuilder out, Object value) {
        if (value == null) { out.append("null"); return; }
        if (value instanceof String) { quote(out, (String) value); return; }
        if (value instanceof Number || value instanceof Boolean) { out.append(value); return; }
        if (value instanceof Map) {
            out.append('{'); boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!(entry.getKey() instanceof String)) throw new IllegalArgumentException("JSON object keys must be strings");
                if (!first) out.append(','); first = false; quote(out, (String) entry.getKey()); out.append(':'); write(out, entry.getValue());
            }
            out.append('}'); return;
        }
        if (value instanceof List) {
            out.append('['); boolean first = true;
            for (Object item : (List<?>) value) { if (!first) out.append(','); first = false; write(out, item); }
            out.append(']'); return;
        }
        throw new IllegalArgumentException("Unsupported JSON value");
    }

    private static void quote(StringBuilder out, String value) {
        out.append('"');
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            switch (c) {
                case '"': out.append("\\\""); break; case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break; case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break; case '\r': out.append("\\r"); break; case '\t': out.append("\\t"); break;
                default: if (c < 0x20) out.append(String.format("\\u%04x", (int) c)); else out.append(c);
            }
        }
        out.append('"');
    }

    private static final class Parser {
        private final String text; private int position; private int depth;
        Parser(String text) { this.text = text; }
        boolean end() { return position == text.length(); }
        void space() { while (!end() && Character.isWhitespace(text.charAt(position))) position++; }
        Object value() {
            if (++depth > 32) throw new IllegalArgumentException("JSON nesting too deep");
            try { return valueAtDepth(); } finally { depth--; }
        }
        Object valueAtDepth() {
            space(); if (end()) throw new IllegalArgumentException("JSON value required"); char c = text.charAt(position);
            if (c == '{') return object(); if (c == '[') return array(); if (c == '"') return string();
            if (c == 't' && take("true")) return Boolean.TRUE; if (c == 'f' && take("false")) return Boolean.FALSE;
            if (c == 'n' && take("null")) return null; if (c == '-' || (c >= '0' && c <= '9')) return integer();
            throw new IllegalArgumentException("Invalid JSON value");
        }
        Map<String, Object> object() {
            Map<String, Object> out = new LinkedHashMap<String, Object>(); takeChar('{'); space();
            if (optional('}')) return out;
            while (true) { space(); String key = string(); space(); takeChar(':'); Object value = value();
                if (out.containsKey(key)) throw new IllegalArgumentException("Duplicate JSON field"); out.put(key, value); space();
                if (optional('}')) return out; takeChar(','); }
        }
        List<Object> array() {
            List<Object> out = new ArrayList<Object>(); takeChar('['); space(); if (optional(']')) return out;
            while (true) { out.add(value()); space(); if (optional(']')) return out; takeChar(','); }
        }
        String string() {
            takeChar('"'); StringBuilder out = new StringBuilder();
            while (!end()) { char c = text.charAt(position++); if (c == '"') return out.toString();
                if (c < 0x20) throw new IllegalArgumentException("Control character in JSON string");
                if (c != '\\') { out.append(c); continue; } if (end()) throw new IllegalArgumentException("Invalid JSON escape");
                char escaped = text.charAt(position++); switch (escaped) {
                    case '"': case '\\': case '/': out.append(escaped); break; case 'b': out.append('\b'); break; case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break; case 'r': out.append('\r'); break; case 't': out.append('\t'); break;
                    case 'u': if (position + 4 > text.length()) throw new IllegalArgumentException("Invalid JSON unicode escape");
                        try { out.append((char) Integer.parseInt(text.substring(position, position + 4), 16)); position += 4; } catch (NumberFormatException ex) { throw new IllegalArgumentException("Invalid JSON unicode escape"); } break;
                    default: throw new IllegalArgumentException("Invalid JSON escape"); }
            } throw new IllegalArgumentException("Unterminated JSON string");
        }
        Long integer() {
            int start = position; if (text.charAt(position) == '-') position++; if (end()) throw new IllegalArgumentException("Invalid JSON number");
            if (text.charAt(position) == '0') position++; else { if (text.charAt(position) < '1' || text.charAt(position) > '9') throw new IllegalArgumentException("Invalid JSON number"); while (!end() && Character.isDigit(text.charAt(position))) position++; }
            if (!end() && (text.charAt(position) == '.' || text.charAt(position) == 'e' || text.charAt(position) == 'E')) throw new IllegalArgumentException("JSON integer required");
            try { return Long.valueOf(text.substring(start, position)); } catch (NumberFormatException ex) { throw new IllegalArgumentException("Invalid JSON integer"); }
        }
        boolean take(String value) { if (!text.regionMatches(position, value, 0, value.length())) return false; position += value.length(); return true; }
        boolean optional(char expected) { if (!end() && text.charAt(position) == expected) { position++; return true; } return false; }
        void takeChar(char expected) { space(); if (end() || text.charAt(position++) != expected) throw new IllegalArgumentException("Invalid JSON syntax"); }
    }
}
