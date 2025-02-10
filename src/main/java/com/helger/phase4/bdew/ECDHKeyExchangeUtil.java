package com.helger.phase4.bdew;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;

/**
 * Utility class to perform an ephemeral-static ECDH key agreement and AES key wrap,
 * as required by the BDEW AS4 profile.
 */
public class ECDHKeyExchangeUtil
{
    /**
     * Result container for the key exchange
     */
    public static class ECDHKeyExchangeResult
    {
        private final byte[] ephemeralPublicKey;
        private final byte[] wrappedSessionKey;

        public ECDHKeyExchangeResult(final byte[] ephemeralPublicKey, final byte[] wrappedSessionKey)
        {
            this.ephemeralPublicKey = ephemeralPublicKey;
            this.wrappedSessionKey = wrappedSessionKey;
        }

        public byte[] getEphemeralPublicKey()
        {
            return ephemeralPublicKey;
        }

        public byte[] getWrappedSessionKey()
        {
            return wrappedSessionKey;
        }
    }

    /**
     * Performs the ECDH-ES key exchange.
     *
     * @param recipientCert
     *        The recipient's encryption certificate (must contain an EC public key on the required curve)
     * @param sessionKey
     *        The symmetric session key (e.g. an AES key) that you wish to wrap.
     * @return an {@link ECDHKeyExchangeResult} containing the ephemeral public key (to be sent with the message)
     *         and the wrapped session key.
     * @throws Exception if any cryptographic operation fails.
     */
    public static ECDHKeyExchangeResult performECDHKeyExchange(X509Certificate recipientCert, SecretKey sessionKey) throws Exception {
        // Extract the recipient's public key and curve parameters
        ECPublicKey recipientPubKey = (ECPublicKey) recipientCert.getPublicKey();
        ECParameterSpec recipientParams = recipientPubKey.getParams();

        // Generate ephemeral key pair using the same curve parameters
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(recipientParams);
        KeyPair ephemeralKeyPair = keyGen.generateKeyPair();

        // Perform key agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
        keyAgreement.init(ephemeralKeyPair.getPrivate());
        keyAgreement.doPhase(recipientPubKey, true);

        // Generate shared secret
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Use shared secret to wrap the session key
        SecretKeyFactory kdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", BouncyCastleProvider.PROVIDER_NAME);
        PBEKeySpec spec = new PBEKeySpec(Base64.getEncoder().encodeToString(sharedSecret).toCharArray(), 
                                       sharedSecret, 65536, 256);
        SecretKey wrappingKey = kdf.generateSecret(spec);
        
        Cipher cipher = Cipher.getInstance("AESWrap", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.WRAP_MODE, wrappingKey);
        byte[] wrappedKey = cipher.wrap(sessionKey);

        return new ECDHKeyExchangeResult(wrappedKey, ephemeralKeyPair.getPublic().getEncoded());
    }

//    // For testing purposes:
//    public static void main(final String[] args) throws Exception
//    {
//        // Example: load a recipient certificate (your implementation should load it from the recipient's keystore)
//        // For this example, we assume recipientCert is obtained appropriately.
//        X509Certificate recipientCert = ...; // load your recipient certificate
//
//        // Example: generate a random AES session key that you want to wrap.
//        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//        keyGen.init(128); // for AES-128
//        SecretKey sessionKey = keyGen.generateKey();
//
//        ECDHKeyExchangeResult result = performECDHKeyExchange(recipientCert, sessionKey);
//
//        System.out.println("Ephemeral Public Key (Base64): " +
//                java.util.Base64.getEncoder().encodeToString(result.getEphemeralPublicKey()));
//        System.out.println("Wrapped Session Key (Base64): " +
//                java.util.Base64.getEncoder().encodeToString(result.getWrappedSessionKey()));
//    }
}
