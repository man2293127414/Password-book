package com.passwordvault.local.lan;

import com.passwordvault.local.core.crypto.CryptoException;
import com.passwordvault.local.core.crypto.EncryptedPayload;
import com.passwordvault.local.core.lan.LanCrypto;
import com.passwordvault.local.core.lan.LanKeyAgreement;
import com.passwordvault.local.core.lan.LanReplayException;
import com.passwordvault.local.core.lan.LanSessionKeys;
import com.passwordvault.local.core.lan.LanSessionManager;
import com.passwordvault.local.core.lan.LanUnauthorizedException;
import com.passwordvault.local.core.lan.LanVaultAccessGate;
import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.CredentialDraft;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.repository.ConflictException;
import com.passwordvault.local.core.repository.NotFoundException;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.validation.ValidationException;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/** Serial, authenticated implementation of the LAN v1 routes. */
public final class LanApiDispatcher {
    private final VaultService vault; private final LanSessionManager sessions; private final SecureRandom random;
    private final LanCrypto crypto; private final LanKeyAgreement agreement = new LanKeyAgreement();
    private final LanVaultAccessGate vaultAccessGate; private final LongSupplier clock;
    private byte[] runId; private KeyPair serverPair; private LanSessionKeys keys; private String connectedSessionId;
    private long lastPairAttemptMillis = Long.MIN_VALUE;

    public LanApiDispatcher(VaultService vault, LanSessionManager sessions, SecureRandom random) {
        this(vault, sessions, random, new LanVaultAccessGate(), new LongSupplier() { @Override public long getAsLong() { return System.nanoTime() / 1_000_000L; } });
    }
    public LanApiDispatcher(VaultService vault, LanSessionManager sessions, SecureRandom random, LanVaultAccessGate vaultAccessGate) {
        this(vault, sessions, random, vaultAccessGate, new LongSupplier() { @Override public long getAsLong() { return System.nanoTime() / 1_000_000L; } });
    }
    public LanApiDispatcher(VaultService vault, LanSessionManager sessions, SecureRandom random, LongSupplier clock) {
        this(vault, sessions, random, new LanVaultAccessGate(), clock);
    }
    public LanApiDispatcher(VaultService vault, LanSessionManager sessions, SecureRandom random, LanVaultAccessGate vaultAccessGate, LongSupplier clock) {
        if (vault == null || sessions == null || random == null || vaultAccessGate == null || clock == null) throw new IllegalArgumentException("LAN dependencies must not be null");
        this.vault=vault; this.sessions=sessions; this.random=random; this.crypto=new LanCrypto(random); this.vaultAccessGate=vaultAccessGate; this.clock=clock;
    }

    public synchronized void startRun() { clearRun(); runId=new byte[32]; random.nextBytes(runId); serverPair=agreement.generateKeyPair(random); sessions.start(); }
    public synchronized void stopRun() { clearRun(); sessions.stop(); }

    /** One monitor is sufficient: one PC session means every request is serialized through this method. */
    public synchronized OuterResponse handle(String method, String path, String body) {
        try {
            if ("/api/v1/pairing-info".equals(path)) return pairingInfo(method, body);
            if ("/api/v1/pairing-submit".equals(path)) return pairingSubmit(method, body);
            if ("/api/v1/vault".equals(path)) return encryptedVault(method, body);
            return OuterResponse.plain(404, "NOT_FOUND");
        } catch (IllegalArgumentException exception) { return OuterResponse.plain(400, "BAD_REQUEST");
        } catch (RuntimeException exception) { return OuterResponse.plain(500, "INTERNAL"); }
    }

    private OuterResponse pairingInfo(String method, String body) {
        if (!"GET".equals(method) || body != null) return OuterResponse.plain(405, "METHOD_NOT_ALLOWED");
        if (!isStarted()) return OuterResponse.plain(401, "DISCONNECTED"); return OuterResponse.json(200, LanWireCodec.pairingInfoJson(runId, agreement.publicKeyToSec1(serverPair.getPublic())));
    }
    private OuterResponse pairingSubmit(String method, String body) {
        if (!"POST".equals(method) || body == null) return OuterResponse.plain(405, "METHOD_NOT_ALLOWED"); if (!isStarted()) return OuterResponse.plain(401, "DISCONNECTED");
        long now = clock.getAsLong(); if (lastPairAttemptMillis != Long.MIN_VALUE && now - lastPairAttemptMillis < 500L) return OuterResponse.plain(429, "RATE_LIMITED"); lastPairAttemptMillis = now;
        LanWireCodec.PairingSubmit submit=LanWireCodec.parsePairingSubmit(body); byte[] clientPublic=submit.getClientPublicKey(); byte[] serverPublic=agreement.publicKeyToSec1(serverPair.getPublic()); byte[] shared=null;
        LanSessionKeys candidateKeys = null;
        boolean sessionEstablished = false;
        try {
            shared=agreement.deriveSharedSecret(serverPair.getPrivate(), agreement.publicKeyFromSec1(clientPublic));
            String code=crypto.decryptAccessCode(shared, runId, serverPublic, clientPublic, submit.getEncryptedCode());
            com.passwordvault.local.core.lan.PairingResult result=sessions.submitAccessCode(code);
            if (!result.isSuccess()) return OuterResponse.plain(401, "UNAUTHORIZED");
            sessionEstablished = true;
            String candidateSessionId = result.getSessionId();
            candidateKeys = crypto.deriveSessionKeys(shared, runId);
            EncryptedPayload reply=crypto.encryptAccessCode(shared, runId, serverPublic, clientPublic, LanWireCodec.pairingSuccessJson(candidateSessionId));
            OuterResponse response=OuterResponse.json(200, LanWireCodec.pairingReplyJson(reply));
            connectedSessionId=candidateSessionId;
            keys=candidateKeys;
            candidateKeys=null;
            return response;
        } catch (CryptoException exception) {
            if (sessionEstablished) {
                abortRun();
                return OuterResponse.plain(500, "INTERNAL");
            }
            return OuterResponse.plain(401, "UNAUTHORIZED");
        } catch (RuntimeException exception) {
            if (sessionEstablished) {
                abortRun();
                return OuterResponse.plain(500, "INTERNAL");
            }
            throw exception;
        } finally {
            if (candidateKeys != null) candidateKeys.destroy();
            if (shared != null) Arrays.fill(shared, (byte) 0);
        }
    }
    private OuterResponse encryptedVault(String method, String body) {
        if (!"POST".equals(method) || body == null) return OuterResponse.plain(405, "METHOD_NOT_ALLOWED");
        LanWireCodec.EnvelopeRequest request;
        try { request=LanWireCodec.parseEnvelopeRequest(body); } catch (IllegalArgumentException exception) { return OuterResponse.plain(400, "BAD_REQUEST"); }
        if (!isStarted()) return OuterResponse.plain(401, "DISCONNECTED");
        if (keys == null || connectedSessionId == null
                || !connectedSessionId.equals(request.getSessionId())) {
            return OuterResponse.plain(401, "UNAUTHORIZED");
        }
        final LanWireCodec.EnvelopeRequest candidateRequest = request;
        return vaultAccessGate.runLanRequest(new Supplier<OuterResponse>() {
            @Override public OuterResponse get() {
                return processEncryptedVault(method, candidateRequest);
            }
        });
    }
    private OuterResponse processEncryptedVault(String method, LanWireCodec.EnvelopeRequest request) {
        long counter=request.getEnvelope().getCounter();
        byte[] plaintext = null;
        try {
            plaintext=crypto.decryptClientRequest(keys, connectedSessionId, method, "/api/v1/vault", request.getEnvelope());
            sessions.beginRequest(connectedSessionId, counter); // consumes only authenticated requests, before any possible write
            Map<String,Object> command=LanJson.object(LanJson.parse(new String(plaintext, StandardCharsets.UTF_8)));
            Map<String,Object> response=execute(command);
            sessions.recordSuccessfulOperation(connectedSessionId, counter);
            return encrypted(counter, response);
        } catch (ValidationException exception) { return encrypted(counter, error("VALIDATION"));
        } catch (NotFoundException exception) { return encrypted(counter, error("NOT_FOUND"));
        } catch (ConflictException exception) { return encrypted(counter, error("STALE_VERSION"));
        } catch (LanReplayException exception) { return OuterResponse.plain(401, "UNAUTHORIZED");
        } catch (LanUnauthorizedException exception) { return OuterResponse.plain(401, sessions.getState().getStatus() == com.passwordvault.local.core.lan.LanSessionState.Status.CONNECTED ? "UNAUTHORIZED" : "DISCONNECTED");
        } catch (CryptoException exception) { return OuterResponse.plain(401, "UNAUTHORIZED");
        } catch (IllegalArgumentException exception) { return encrypted(counter, error("BAD_REQUEST"));
        } catch (RuntimeException exception) { return encrypted(counter, error("INTERNAL"));
        } finally { if (plaintext != null) Arrays.fill(plaintext, (byte) 0); }
    }
    private Map<String,Object> execute(Map<String,Object> command) {
        String op=LanJson.string(command,"op"); Map<String,Object> out=new LinkedHashMap<String,Object>(); out.put("ok",Boolean.TRUE);
        if ("snapshot".equals(op)) { out.put("snapshot", snapshot(vault.getSnapshot())); return out; }
        if ("credential.create".equals(op)) { out.put("credential", credential(vault.createCredential(draft(command)))); return out; }
        if ("credential.update".equals(op)) { out.put("credential", credential(vault.updateCredential(LanJson.string(command,"id"), version(command), draft(command)))); return out; }
        if ("credential.delete".equals(op)) { vault.deleteCredential(LanJson.string(command,"id"), version(command)); return out; }
        if ("category.create".equals(op)) { out.put("category", category(vault.createCategory(LanJson.string(command,"name")))); return out; }
        if ("category.rename".equals(op)) { out.put("category", category(vault.renameCategory(LanJson.string(command,"id"), version(command), LanJson.string(command,"name")))); return out; }
        if ("category.delete".equals(op)) { vault.deleteCategory(LanJson.string(command,"id"), version(command)); return out; }
        if ("tag.create".equals(op)) { out.put("tag", tag(vault.createTag(LanJson.string(command,"name")))); return out; }
        if ("tag.rename".equals(op)) { out.put("tag", tag(vault.renameTag(LanJson.string(command,"id"), version(command), LanJson.string(command,"name")))); return out; }
        if ("tag.delete".equals(op)) { vault.deleteTag(LanJson.string(command,"id"), version(command)); return out; }
        throw new IllegalArgumentException("Unknown operation");
    }
    private OuterResponse encrypted(long counter, Map<String,Object> value) { byte[] plaintext = LanJson.stringify(value).getBytes(StandardCharsets.UTF_8); try { return OuterResponse.json(200, LanWireCodec.envelopeJson(connectedSessionId, crypto.encryptServerResponse(keys, connectedSessionId, counter, "POST", "/api/v1/vault", plaintext))); } finally { Arrays.fill(plaintext, (byte) 0); } }
    private static Map<String,Object> error(String code) { Map<String,Object> out=new LinkedHashMap<String,Object>(); out.put("ok",Boolean.FALSE); out.put("error",code); return out; }
    private static int version(Map<String,Object> input) { long value=LanJson.number(input,"expectedVersion"); if(value<1 || value>Integer.MAX_VALUE) throw new IllegalArgumentException("Invalid expectedVersion"); return (int)value; }
    private static CredentialDraft draft(Map<String,Object> input) { Set<String> tags=new LinkedHashSet<String>(); Object tagIds=input.get("tagIds"); if(tagIds != null) for(Object id:LanJson.array(tagIds)) { if(!(id instanceof String)) throw new IllegalArgumentException("tagIds must contain strings"); tags.add((String)id); } return new CredentialDraft(LanJson.string(input,"name"),LanJson.nullableString(input,"account"),LanJson.string(input,"password"),LanJson.nullableString(input,"url"),LanJson.nullableString(input,"categoryId"),tags,LanJson.nullableString(input,"notes")); }
    private static Map<String,Object> snapshot(VaultSnapshot source) { Map<String,Object> out=new LinkedHashMap<String,Object>(); out.put("revision",source.getRevision()); List<Object> cs=new ArrayList<Object>(); for(Credential item:source.getCredentials())cs.add(credential(item)); List<Object> cats=new ArrayList<Object>();for(Category item:source.getCategories())cats.add(category(item)); List<Object> tags=new ArrayList<Object>();for(Tag item:source.getTags())tags.add(tag(item));out.put("credentials",cs);out.put("categories",cats);out.put("tags",tags);return out; }
    private static Map<String,Object> credential(Credential item) { Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("id",item.getId());out.put("name",item.getName());out.put("account",item.getAccount());out.put("password",item.getPassword());out.put("url",item.getUrl());out.put("categoryId",item.getCategoryId());out.put("tagIds",new ArrayList<String>(item.getTagIds()));out.put("notes",item.getNotes());out.put("version",(long)item.getVersion());out.put("createdAt",item.getCreatedAtEpochMillis());out.put("updatedAt",item.getUpdatedAtEpochMillis());return out; }
    private static Map<String,Object> category(Category item) { Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("id",item.getId());out.put("name",item.getName());out.put("version",(long)item.getVersion());return out; }
    private static Map<String,Object> tag(Tag item) { Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("id",item.getId());out.put("name",item.getName());out.put("version",(long)item.getVersion());return out; }
    private boolean isStarted() { return runId != null && serverPair != null; }
    private void abortRun() { clearRun(); sessions.stop(); }
    private void clearRun() { if(runId!=null)Arrays.fill(runId,(byte)0);runId=null;serverPair=null;if(keys!=null)keys.destroy();keys=null;connectedSessionId=null;lastPairAttemptMillis=Long.MIN_VALUE; }
    public static final class OuterResponse { private final int status;private final String body;private final boolean json; private OuterResponse(int status,String body,boolean json){this.status=status;this.body=body;this.json=json;} static OuterResponse plain(int status,String body){return new OuterResponse(status,body,false);}static OuterResponse json(int status,String body){return new OuterResponse(status,body,true);} public int getStatus(){return status;}public String getBody(){return body;}public boolean isJson(){return json;} }
}
