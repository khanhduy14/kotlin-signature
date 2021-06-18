package sips.crypto.extension

import java.security.MessageDigest

fun ByteArray.toSHA256Digest(): ByteArray = MessageDigest.getInstance("SHA-512").apply {
    update(this@toSHA256Digest)
}.digest()

fun ByteArray.toHexString(): String =
    StringBuffer().apply {
        this@toHexString.forEach {
            val hex = Integer.toHexString(0xFF and it.toInt())

            if (hex.length == 1) {
                append('0')
            }

            append(hex)
        }
    }.toString()
