package com.helger.phase4.bdew;

import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import com.helger.phase4.attachment.AS4OutgoingAttachment;
import com.helger.phase4.attachment.WSS4JAttachment;
import com.helger.phase4.crypto.AS4CryptoFactoryInMemoryKeyStore;
import com.helger.phase4.util.AS4ResourceHelper;
import com.helger.phase4.bdew.ECDHKeyExchangeUtil;
import com.helger.phase4.bdew.ECDHKeyExchangeUtil.ECDHKeyExchangeResult;
import com.helger.phase4.sender.AbstractAS4UserMessageBuilderMIMEPayload;
import com.helger.phase4.sender.EAS4UserMessageSendResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.helger.phase4.crypto.IAS4CryptoFactory;
import java.security.cert.Certificate;
import java.security.KeyStore;

/**
 * A custom builder that injects the ECDH-ES key exchange logic.
 */
public class BDEWUserMessageBuilderWithECDH extends Phase4BDEWSender.BDEWUserMessageBuilder
{
    private static final Logger LOGGER = LoggerFactory.getLogger(BDEWUserMessageBuilderWithECDH.class);
    private IAS4CryptoFactory cryptoFactory;

    public BDEWUserMessageBuilderWithECDH (@Nonnull final IAS4CryptoFactory cryptoFactory)
    {
        super();
        this.cryptoFactory = cryptoFactory;
    }

    /**
     * Override the method that creates the main attachment.
     * This is where we perform the ECDH key exchange and store the wrapped session key
     * and ephemeral public key in custom properties.
     */
    @Override
    @Nullable
    protected WSS4JAttachment createMainAttachment(@Nonnull final AS4OutgoingAttachment aPayload,
                                                   @Nonnull final AS4ResourceHelper aResHelper) throws IOException
    {
        // First, create the default attachment
        final WSS4JAttachment aPayloadAttachment = WSS4JAttachment.createOutgoingFileAttachment(aPayload, aResHelper);

        try
        {
            // For demonstration, generate a random AES session key to encrypt your payload.
            // In your real application, this may be generated as part of the message encryption process.
            final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128); // 128-bit AES key
            final SecretKey sessionKey = keyGen.generateKey();

            // Obtain the recipient's encryption certificate.
            // How you do this depends on your application. For example, you might retrieve it from your
            // crypto factory or trust store. Here we assume you have a helper method:
            final X509Certificate recipientCert = getRecipientEncryptionCertificate();
            if (recipientCert == null)
                throw new IllegalStateException("Recipient encryption certificate is not available");

            // Perform the ECDH key exchange to wrap the session key.
            final ECDHKeyExchangeResult ecdhResult = ECDHKeyExchangeUtil.performECDHKeyExchange(recipientCert, sessionKey);

            // Store the wrapped session key in a custom property.
            aPayloadAttachment.customPartProperties().put("WrappedSessionKey",
                    Base64.getEncoder().encodeToString(ecdhResult.getWrappedSessionKey()));
            // Store the ephemeral public key so that it can be inserted into the WS-Security header.
            aPayloadAttachment.customPartProperties().put("EphemeralPublicKey",
                    Base64.getEncoder().encodeToString(ecdhResult.getEphemeralPublicKey()));

            LOGGER.info("Inserted ECDH key exchange values into attachment custom properties");
        }
        catch (final Exception ex)
        {
            throw new IOException("Error performing ECDH key exchange", ex);
        }
        return aPayloadAttachment;
    }

    /**
     * Dummy helper: implement this method to return the recipient's encryption certificate.
     * In a real implementation, you might look it up from your trust store or via configuration.
     */
    @Nullable
    private X509Certificate getRecipientEncryptionCertificate()
    {
        try
        {
            final KeyStore trustStore = cryptoFactory.getTrustStore();
            if (trustStore == null)
            {
                LOGGER.warn("No TrustStore found in CryptoFactory. Cannot retrieve recipient certificate.");
                return null;
            }

            final String recipientCertAlias = "cert2"; //  Alias for the recipient's certificate
            final Certificate recipientCert = trustStore.getCertificate(recipientCertAlias);
            if (recipientCert instanceof X509Certificate)
            {
                LOGGER.info("Successfully retrieved recipient certificate with alias '{}' from trust store.", recipientCertAlias);
                return (X509Certificate) recipientCert;
            }
            else
            {
                LOGGER.warn("No X509Certificate found in trust store with alias '{}'.", recipientCertAlias);
                return null;
            }
        }
        catch (final Exception ex)
        {
            LOGGER.error("Error retrieving recipient encryption certificate from trust store", ex);
            return null;
        }
    }
}
