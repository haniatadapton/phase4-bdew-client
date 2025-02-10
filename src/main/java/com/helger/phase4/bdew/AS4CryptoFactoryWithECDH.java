//package com.helger.phase4.bdew;
//
//import java.security.cert.X509Certificate;
//import javax.crypto.SecretKey;
//
//import com.helger.phase4.crypto.AS4CryptoFactoryInMemoryKeyStore;
//import com.helger.security.keystore.KeyStoreAndKeyDescriptor;
//import com.helger.security.keystore.TrustStoreDescriptor;
//
//public class AS4CryptoFactoryWithECDH extends AS4CryptoFactoryInMemoryKeyStore
//{
//    public AS4CryptoFactoryWithECDH(final KeyStoreAndKeyDescriptor aKSD,
//                                    final TrustStoreDescriptor aTSD)
//    {
//        super(aKSD, aTSD);
//    }
//
//    @Override
//    protected byte[] encryptSessionKey(final SecretKey sessionKey, final X509Certificate aRecipientCert) throws Exception
//    {
//        // Instead of the default key wrapping,
//        // call our ECDH key exchange utility to wrap the session key.
//        ECDHKeyExchangeUtil.ECDHKeyExchangeResult result =
//                ECDHKeyExchangeUtil.performECDHKeyExchange(aRecipientCert, sessionKey);
//
//        // You now have:
//        // result.getEphemeralPublicKey() -> this must be included in your security header
//        // result.getWrappedSessionKey()   -> this is the wrapped session key
//
//        // Here you need to store or inject the ephemeral public key into the message (for example,
//        // by setting a property on the message builder so that later when the XML is built, the
//        // <xenc:AgreementMethod> element is filled in accordingly).
//
//        // For now, simply return the wrapped session key.
//        return result.getWrappedSessionKey();
//    }
//}
