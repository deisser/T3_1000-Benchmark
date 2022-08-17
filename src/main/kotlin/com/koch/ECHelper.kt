package com.koch

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.security.*
import java.security.spec.X509EncodedKeySpec

class ECHelper(privKeyPath: String, pubKeyPath: String) {

    private val supplier = Supplier.getInstance()

    val publicKey = readPublicKey(pubKeyPath)
    val privateKey = readPrivateKey(privKeyPath)

    fun generateECSignature(input: ByteArray): ByteArray {
        val signature = Signature.getInstance(supplier.hashSignatureAlgorithm, supplier.provider)
        signature.initSign(privateKey)
        signature.update(input)
        return signature.sign()
    }

    fun generateSHA256Hash(input: ByteArray): ByteArray {
        val messageDigest = MessageDigest.getInstance(supplier.hashAlgorithm, supplier.provider)
        messageDigest.update(input)
        return messageDigest.digest()
    }

    fun readPrivateKey(path: String): PrivateKey {
        val privKeyFile = InputStreamReader(ByteArrayInputStream(ResourceUtil.loadResource(path).readBytes()))
        return try {
            val pemParser = PEMParser(privKeyFile)
            val converter = JcaPEMKeyConverter()
            val privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject())
            converter.getPrivateKey(privateKeyInfo)
        } catch (e: Exception) {
            throw Exception("Unable to read PrivateKey: $e")
        }
    }

    fun readPublicKey(path: String): PublicKey {
        val pubKeyFile = InputStreamReader(ByteArrayInputStream(ResourceUtil.loadResource(path).readBytes()))
        val keyAlgorithm = if (supplier.provider == "BC") "EC" else "ECDSA"
        val keyFactory = KeyFactory.getInstance(keyAlgorithm, supplier.provider)
        /*val bcBenchmarkProvider = BenchmarkProvider("BC","EC")
        val nCipherBenchmarkProvider = BenchmarkProvider("nCipherKM", "ECDSA")
        KeyFactory.getInstance(bcBenchmarkProvider.keyAlgorithm, bcBenchmarkProvider.provider)*/

        return try {
            val pemReader = PemReader(pubKeyFile)
            val pemObject = pemReader.readPemObject()
            val content = pemObject.content
            val pubKeySpec = X509EncodedKeySpec(content)
            keyFactory.generatePublic(pubKeySpec)
        } catch (e: Exception) {
            throw Exception("Unable to read PublicKey: $e")
        }
    }

}

data class BenchmarkProvider(val provider: String, val keyAlgorithm: String)