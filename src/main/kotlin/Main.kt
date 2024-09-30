package jar.us

import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.util.Passphrase
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets


// Generate a key pair for Alice. This key pair includes both the private and public keys.
// The private key (secretKeys) is used for decryption and the public key (certificate) is used for encryption.
val secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>")
val certificate = PGPainless.extractCertificate(secretKeys)

// Create a protector with the passphrase for the private key.
val protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("password"))


fun main() {
    val message = "Hello, World!"

    // Encrypt the message using Alice's public key.
    val encryptedMessage = encryptMessage(message)

    // Decrypt the message using Alice's private key.
    val decryptedMessage = decryptMessage(encryptedMessage, "password")

    println("Original Message: $message")
    println("Decrypted Message: $decryptedMessage")
}


/**
 * Encrypts the given message using the public key.
 *
 * @param message The message to be encrypted.
 * @return The encrypted message.
 */
fun encryptMessage(message: String): String {

    val ciphertextOut = ByteArrayOutputStream()

    // Create an encryption stream using the public key (certificate).
    val encryptionStream = PGPainless.encryptAndOrSign()
        .onOutputStream(ciphertextOut)
        .withOptions(
            ProducerOptions.encrypt(
                EncryptionOptions().addRecipient(certificate)
            )
        )

    // Write the message to the encryption stream.
    encryptionStream.use {
        it.write(message.toByteArray(StandardCharsets.UTF_8))
    }

    return ciphertextOut.toString(StandardCharsets.UTF_8)
}


/**
 * Decrypts the given encrypted message using the private key.
 *
 * @param encryptedMessage The encrypted message to be decrypted.
 * @param password The password for the private key.
 * @return The decrypted message.
 */
fun decryptMessage(encryptedMessage: String, password: String): String {

    val ciphertextIn = ByteArrayInputStream(encryptedMessage.toByteArray(StandardCharsets.UTF_8))

    // Create a decryption stream using the private key (secretKeys) and the protector.
    val decryptionStream = PGPainless.decryptAndOrVerify()
        .onInputStream(ciphertextIn)
        .withOptions(
            ConsumerOptions().addDecryptionKey(secretKeys, protector)
        )

    val plaintextOut = ByteArrayOutputStream()

    // Write the decrypted message to the output stream.
    decryptionStream.use {
        Streams.pipeAll(it, plaintextOut)
    }

    return plaintextOut.toString(StandardCharsets.UTF_8)
}
