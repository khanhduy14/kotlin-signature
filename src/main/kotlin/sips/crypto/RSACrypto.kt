package sips.crypto;

import sips.crypto.constant.SignatureAlgorithm
import sips.crypto.extension.sha256WithRSASigned
import sips.crypto.extension.sha512WithRSASigned
import sips.crypto.extension.verifySha256WithRSASigned
import sips.crypto.extension.verifySha512WithRSASigned
import java.security.KeyPairGenerator
import java.security.Security
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.system.measureTimeMillis

object RSACrypto {
    private lateinit var privateKey: RSAPrivateKey
    private lateinit var publicKey: RSAPublicKey
    private lateinit var message256: ByteArray
    private lateinit var message512: ByteArray
    var messageData = "Hello World".toByteArray()


    @JvmStatic
    fun main(args: Array<String>) {
        setUp()

        message256 = shaWithRSA(SignatureAlgorithm.SHA256_WITH_RSA)!!
        message512 = shaWithRSA(SignatureAlgorithm.SHA512_WITH_RSA)!!
        val timeInMillisSign512 = measureTimeMillis {
            for (i in 0..20000) {
                shaWithRSA(SignatureAlgorithm.SHA512_WITH_RSA)
            }
        }

        val timeInMillisVerify512 = measureTimeMillis {
            for (i in 0..20000) {
                verify(SignatureAlgorithm.SHA512_WITH_RSA)
            }
        }


        println("Time execute 512 sign: $timeInMillisSign512")
        println("Time execute 512 verify: $timeInMillisVerify512")

        val timeInMillisSign256 = measureTimeMillis {
            for (i in 0..20000) {
                shaWithRSA(SignatureAlgorithm.SHA256_WITH_RSA)
            }
        }

        val timeInMillisVerify256 = measureTimeMillis {
            for (i in 0..20000) {
                verify(SignatureAlgorithm.SHA512_WITH_RSA)
            }
        }


        println("Time execute 256 sign: $timeInMillisSign256")
        println("Time execute 256 verify: $timeInMillisVerify256")
    }


    fun setUp() {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        val keyPair = keyPairGenerator.genKeyPair()

        privateKey = keyPair.private as RSAPrivateKey
        publicKey = keyPair.public as RSAPublicKey


        val keyPairGenerators = mutableListOf<String>()
        val signatures = mutableListOf<String>()
        val messageDigests = mutableListOf<String>()
        val ciphers = mutableListOf<String>()

        Security.getProviders().forEach {
            it.services.forEach { service ->
                when (service.type) {
                    "KeyPairGenerator" -> keyPairGenerators.add(service.algorithm)
                    "Signature" -> signatures.add(service.algorithm)
                    "MessageDigest" -> messageDigests.add(service.algorithm)
                    "Cipher" -> ciphers.add(service.algorithm)
                }
            }
        }
    }

    fun shaWithRSA(signatureAlgorithm: SignatureAlgorithm): ByteArray? {
        var signatured: ByteArray? = null
        if (signatureAlgorithm == SignatureAlgorithm.SHA512_WITH_RSA) {
            signatured = messageData.sha512WithRSASigned(privateKey)
        }

        if (signatureAlgorithm == SignatureAlgorithm.SHA256_WITH_RSA) {
            signatured = messageData.sha256WithRSASigned(privateKey)
        }

        return signatured

    }

    fun verify(signatureAlgorithm: SignatureAlgorithm) {
        if (signatureAlgorithm == SignatureAlgorithm.SHA512_WITH_RSA) {
            messageData.verifySha512WithRSASigned(publicKey, message512)
        }

        if (signatureAlgorithm == SignatureAlgorithm.SHA256_WITH_RSA) {
            messageData.verifySha256WithRSASigned(publicKey, message256)
        }
    }
}
