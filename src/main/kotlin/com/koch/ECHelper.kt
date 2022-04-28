package com.koch

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemReader
import java.io.File
import java.io.FileReader
import java.nio.file.Paths
import java.security.*
import java.security.spec.X509EncodedKeySpec

class ECHelper(privKeyPath: String, pubKeyPath: String) {

    val publicKey = readPublicKey(pubKeyPath)
    val privateKey = readPrivateKey(privKeyPath)

    fun generateECSignature(input: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA", MyBenchmark.SetupClass.provider)
        signature.initSign(privateKey)
        signature.update(input)
        return signature.sign()
    }

    fun generateSHA256Hash(input: ByteArray): ByteArray {
        val messageDigest = MessageDigest.getInstance("SHA-256", MyBenchmark.SetupClass.provider)
        messageDigest.update(input)
        return messageDigest.digest()
    }

    fun readPrivateKey(path: String): PrivateKey {
        //TODO: Fix key reading
        //val privKeyFile = File(ResourceUtil.loadResource(path).toString())
        val privKeyFile = File(this::class.java.getResource(path)!!.toString())
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
        //TODO: Fix key reading
        //val pubKeyFile = File(ResourceUtil.loadResource(path).toString())
        val pubKeyFile = File(this::class.java.getResource(path)!!.toString())
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