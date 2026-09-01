package com.passwordvault.local.core.lan;

import com.passwordvault.local.core.crypto.CryptoException;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

public final class LanKeyAgreement {
    private static final int COORDINATE_BYTES = 32;
    private static final int PUBLIC_KEY_BYTES = 65;

    public KeyPair generateKeyPair(SecureRandom secureRandom) {
        if (secureRandom == null) throw new IllegalArgumentException("secureRandom must not be null");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), secureRandom);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new CryptoException("Unable to generate LAN ECDH key pair", exception);
        }
    }

    public PrivateKey privateKeyFromScalar(byte[] scalar) {
        if (scalar == null || scalar.length != COORDINATE_BYTES) {
            throw new IllegalArgumentException("P-256 private scalar must contain 32 bytes");
        }
        try {
            BigInteger value = new BigInteger(1, scalar);
            ECParameterSpec parameters = parameters();
            if (value.signum() <= 0 || value.compareTo(parameters.getOrder()) >= 0) {
                throw new IllegalArgumentException("P-256 private scalar is outside the curve order");
            }
            return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(value, parameters));
        } catch (GeneralSecurityException exception) {
            throw new CryptoException("Unable to decode LAN ECDH private key", exception);
        }
    }

    public PublicKey publicKeyFromSec1(byte[] encoded) {
        if (encoded == null || encoded.length != PUBLIC_KEY_BYTES || encoded[0] != 4) {
            throw new IllegalArgumentException("P-256 public key must use 65-byte uncompressed SEC1 form");
        }
        try {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(encoded, 33, 65));
            ECParameterSpec parameters = parameters();
            requirePointOnCurve(x, y, parameters);
            return KeyFactory.getInstance("EC").generatePublic(
                    new ECPublicKeySpec(new ECPoint(x, y), parameters)
            );
        } catch (GeneralSecurityException exception) {
            throw new CryptoException("Unable to decode LAN ECDH public key", exception);
        }
    }

    public byte[] publicKeyToSec1(PublicKey publicKey) {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("publicKey must be an EC public key");
        }
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        requireP256(ecPublicKey);
        byte[] encoded = new byte[PUBLIC_KEY_BYTES];
        encoded[0] = 4;
        copyUnsigned(ecPublicKey.getW().getAffineX(), encoded, 1);
        copyUnsigned(ecPublicKey.getW().getAffineY(), encoded, 33);
        return encoded;
    }

    public byte[] deriveSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
        if (privateKey == null || publicKey == null) {
            throw new IllegalArgumentException("ECDH keys must not be null");
        }
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(privateKey);
            agreement.doPhase(publicKey, true);
            return normalizeSecret(agreement.generateSecret());
        } catch (GeneralSecurityException exception) {
            throw new CryptoException("Unable to derive LAN ECDH shared secret", exception);
        }
    }

    private static ECParameterSpec parameters() throws GeneralSecurityException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    private static void requirePointOnCurve(BigInteger x, BigInteger y, ECParameterSpec parameters) {
        BigInteger fieldPrime = ((java.security.spec.ECFieldFp) parameters.getCurve().getField()).getP();
        if (x.signum() < 0 || x.compareTo(fieldPrime) >= 0 || y.signum() < 0 || y.compareTo(fieldPrime) >= 0) {
            throw new IllegalArgumentException("P-256 public point is outside the field");
        }
        BigInteger left = y.multiply(y).mod(fieldPrime);
        BigInteger right = x.multiply(x).multiply(x)
                .add(parameters.getCurve().getA().multiply(x))
                .add(parameters.getCurve().getB())
                .mod(fieldPrime);
        if (!left.equals(right)) {
            throw new IllegalArgumentException("P-256 public point is not on the curve");
        }
    }

    private static void requireP256(ECPublicKey publicKey) {
        try {
            ECParameterSpec expected = parameters();
            ECParameterSpec actual = publicKey.getParams();
            if (actual == null
                    || !expected.getOrder().equals(actual.getOrder())
                    || expected.getCofactor() != actual.getCofactor()
                    || !expected.getGenerator().equals(actual.getGenerator())
                    || !expected.getCurve().equals(actual.getCurve())) {
                throw new IllegalArgumentException("publicKey must use the P-256 curve");
            }
        } catch (GeneralSecurityException exception) {
            throw new CryptoException("Unable to validate LAN ECDH public key", exception);
        }
    }

    private static void copyUnsigned(BigInteger value, byte[] destination, int offset) {
        byte[] source = value.toByteArray();
        if (source.length > COORDINATE_BYTES + 1
                || (source.length == COORDINATE_BYTES + 1 && source[0] != 0)) {
            throw new IllegalArgumentException("EC coordinate is too large");
        }
        int sourceOffset = source.length == COORDINATE_BYTES + 1 ? 1 : 0;
        int length = source.length - sourceOffset;
        if (length > COORDINATE_BYTES) {
            throw new IllegalArgumentException("EC coordinate is too large");
        }
        System.arraycopy(source, sourceOffset, destination, offset + COORDINATE_BYTES - length, length);
    }

    private static byte[] normalizeSecret(byte[] secret) {
        if (secret.length == COORDINATE_BYTES) return secret;
        if (secret.length > COORDINATE_BYTES) {
            return Arrays.copyOfRange(secret, secret.length - COORDINATE_BYTES, secret.length);
        }
        byte[] normalized = new byte[COORDINATE_BYTES];
        System.arraycopy(secret, 0, normalized, COORDINATE_BYTES - secret.length, secret.length);
        Arrays.fill(secret, (byte) 0);
        return normalized;
    }
}
