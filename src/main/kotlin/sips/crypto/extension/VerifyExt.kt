package sips.crypto.extension

import sips.crypto.constant.SignatureAlgorithm
import java.security.PublicKey
import java.security.Signature

fun ByteArray.verify(signature: ByteArray, signatureAlgorithm: SignatureAlgorithm, publicKey: PublicKey): Boolean =
    Signature.getInstance(signatureAlgorithm.rawValue).apply {
        initVerify(publicKey)
        update(this@verify)
    }.verify(signature)

fun ByteArray.verifyNoneWithRSASigned(publicKey: PublicKey, signature: ByteArray): Boolean =
    this.verify(signature, SignatureAlgorithm.NONE_WITH_RSA, publicKey)

fun ByteArray.verifyMd2WithRSASigned(publicKey: PublicKey, signature: ByteArray): Boolean =
    this.verify(signature, SignatureAlgorithm.MD2_WITH_RSA, publicKey)

fun ByteArray.verifyMd5WithRSASigned(publicKey: PublicKey, signature: ByteArray): Boolean =
    this.verify(signature, SignatureAlgorithm.MD5_WITH_RSA, publicKey)

fun ByteArray.verifySha1WithRSASigned(publicKey: PublicKey, signature: ByteArray): Boolean =
    this.verify(signature, SignatureAlgorithm.SHA1_WITH_RSA, publicKey)

fun ByteArray.verifySha224WithRSASigned(publicKey: PublicKey, signature: ByteArray): Boolean =
    this.verify(signature, SignatureAlgorithm.SHA224_WITH_RSA, publicKey)

fun ByteArray.verifySha256WithRSASigned(publicKey: PublicKey, signature: ByteArray): Boolean =
    this.verify(signature, SignatureAlgorithm.SHA256_WITH_RSA, publicKey)

fun ByteArray.verifySha384WithRSASigned(publicKey: PublicKey, signature: ByteArray): Boolean =
    this.verify(signature, SignatureAlgorithm.SHA384_WITH_RSA, publicKey)

fun ByteArray.verifySha512WithRSASigned(publicKey: PublicKey, signature: ByteArray): Boolean =
    this.verify(signature, SignatureAlgorithm.SHA512_WITH_RSA, publicKey)

fun ByteArray.verifyMd5AndSHA1WithRSASigned(publicKey: PublicKey, signature: ByteArray): Boolean =
    this.verify(signature, SignatureAlgorithm.MD5_AND_SHA1_WITH_RSA, publicKey)
