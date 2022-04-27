package com.koch

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemReader
import java.io.File
import java.io.FileReader
import java.security.*
import java.security.spec.X509EncodedKeySpec

//TODO: Pfade zu den Keys entgegennehmen und laden
class ECHelper() {
    fun generateECSignature(ecPrivate: PrivateKey, input: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA", MyBenchmark.SetupClass.provider)
        signature.initSign(ecPrivate)
        signature.update(input)
        return signature.sign()
    }

    fun generateSHA256Hash(input: ByteArray): ByteArray {
        val messageDigest = MessageDigest.getInstance("SHA-256", MyBenchmark.SetupClass.provider)
        messageDigest.update(input)
        return messageDigest.digest()
    }

    fun readPrivateKey(path: String): PrivateKey {
        val privKeyFile = File(path)
        return try {
            val keyReader = FileReader(privKeyFile)
            val pemParser = PEMParser(keyReader)
            val converter = JcaPEMKeyConverter()
            val privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject())
            converter.getPrivateKey(privateKeyInfo)
        } catch (e: Exception) {
            throw Exception("Unable to read PrivateKey: $e")
        }
    }

    fun readPublicKey(path: String): PublicKey {
        val pubKeyFile = File(path)
        val keyFactory = KeyFactory.getInstance("EC", MyBenchmark.SetupClass.provider)
        return try {
            val keyReader = FileReader(pubKeyFile)
            val pemReader = PemReader(keyReader)
            val pemObject = pemReader.readPemObject()
            val content = pemObject.content
            val pubKeySpec = X509EncodedKeySpec(content)
            keyFactory.generatePublic(pubKeySpec)
        } catch (e: Exception) {
            throw Exception("Unable to read PublicKey: $e")
        }
    }

}