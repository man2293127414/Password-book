package com.passwordvault.local.lan;

import com.passwordvault.local.core.crypto.EncryptedPayload;
import com.passwordvault.local.core.lan.LanEnvelope;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** Version 1 HTTP wire codec. Outer JSON never carries vault plaintext. */
public final class LanWireCodec {
    private LanWireCodec() { }

    public static String envelopeJson(String sessionId, LanEnvelope envelope) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("v", 1L); out.put("sessionId", sessionId); out.put("counter", envelope.getCounter()); out.put("ciphertext", encode(envelope.getCiphertext()));
        return LanJson.stringify(out);
    }
    public static EnvelopeRequest parseEnvelopeRequest(String json) {
        Map<String, Object> input = LanJson.object(LanJson.parse(json)); requireVersion(input);
        return new EnvelopeRequest(LanJson.string(input, "sessionId"), new LanEnvelope(LanJson.number(input, "counter"), decode(LanJson.string(input, "ciphertext"))));
    }
    public static LanEnvelope parseEnvelope(String json) { return parseEnvelopeRequest(json).getEnvelope(); }

    public static String pairingInfoJson(byte[] runId, byte[] serverPublicKey) {
        Map<String, Object> out = new LinkedHashMap<String, Object>(); out.put("v", 1L); out.put("runId", encode(runId)); out.put("serverPublicKey", encode(serverPublicKey)); return LanJson.stringify(out);
    }
    public static PairingInfo parsePairingInfo(String json) {
        Map<String, Object> input = LanJson.object(LanJson.parse(json)); requireVersion(input);
        return new PairingInfo(decode(LanJson.string(input, "runId")), decode(LanJson.string(input, "serverPublicKey")));
    }
    public static String pairingSubmitJson(byte[] clientPublicKey, EncryptedPayload encryptedCode) {
        Map<String, Object> out = new LinkedHashMap<String, Object>(); out.put("v", 1L); out.put("clientPublicKey", encode(clientPublicKey)); out.put("nonce", encode(encryptedCode.getNonce())); out.put("ciphertext", encode(encryptedCode.getCiphertext())); return LanJson.stringify(out);
    }
    public static PairingSubmit parsePairingSubmit(String json) {
        Map<String, Object> input = LanJson.object(LanJson.parse(json)); requireVersion(input);
        return new PairingSubmit(decode(LanJson.string(input, "clientPublicKey")), new EncryptedPayload(decode(LanJson.string(input, "nonce")), decode(LanJson.string(input, "ciphertext"))));
    }
    public static String pairingReplyJson(EncryptedPayload encryptedReply) {
        Map<String, Object> out = new LinkedHashMap<String, Object>(); out.put("v", 1L); out.put("nonce", encode(encryptedReply.getNonce())); out.put("ciphertext", encode(encryptedReply.getCiphertext())); return LanJson.stringify(out);
    }
    public static EncryptedPayload parsePairingReply(String json) {
        Map<String, Object> input = LanJson.object(LanJson.parse(json)); requireVersion(input);
        return new EncryptedPayload(decode(LanJson.string(input, "nonce")), decode(LanJson.string(input, "ciphertext")));
    }
    public static String pairingSuccessJson(String sessionId) { Map<String, Object> out = new LinkedHashMap<String, Object>(); out.put("sessionId", sessionId); return LanJson.stringify(out); }
    public static String parsePairingSuccess(String plaintext) { return LanJson.string(LanJson.object(LanJson.parse(plaintext)), "sessionId"); }

    private static void requireVersion(Map<String, Object> input) { if (LanJson.number(input, "v") != 1L) throw new IllegalArgumentException("Unsupported LAN protocol version"); }
    private static String encode(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static byte[] decode(String value) { try { return Base64.getUrlDecoder().decode(value); } catch (IllegalArgumentException exception) { throw new IllegalArgumentException("Invalid base64url field"); } }

    public static final class EnvelopeRequest { private final String sessionId; private final LanEnvelope envelope; EnvelopeRequest(String sessionId, LanEnvelope envelope) { this.sessionId=sessionId; this.envelope=envelope; } public String getSessionId(){return sessionId;} public LanEnvelope getEnvelope(){return envelope;} }
    public static final class PairingInfo { private final byte[] runId; private final byte[] serverPublicKey; PairingInfo(byte[] runId, byte[] serverPublicKey){this.runId=runId;this.serverPublicKey=serverPublicKey;} public byte[] getRunId(){return runId.clone();} public byte[] getServerPublicKey(){return serverPublicKey.clone();} }
    public static final class PairingSubmit { private final byte[] clientPublicKey; private final EncryptedPayload encryptedCode; PairingSubmit(byte[] clientPublicKey, EncryptedPayload encryptedCode){this.clientPublicKey=clientPublicKey;this.encryptedCode=encryptedCode;} public byte[] getClientPublicKey(){return clientPublicKey.clone();} public EncryptedPayload getEncryptedCode(){return encryptedCode;} }
}
