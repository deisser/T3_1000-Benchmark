package com.koch

class Supplier private constructor(private val providerInput: String, private val curveInput: String) {

    var c: String? = null

    private val ecHelper: ECHelper
            by lazy {
                if (curveInput == "p256") {
                    ECHelper("/secp256k1_pkcs8_prv.pem", "/secp256k1_pub.pem")
                } else if (curveInput == "p384") {
                    ECHelper("/secp384r1_pkcs8_prv.pem", "/secp384r1_pub.pem")
                } else if (curveInput == "p521") {
                    ECHelper("/secp521r1_pkcs8_private.pem", "/secp521r1_public.pem")
                } else {
                    throw RuntimeException("Unexpected Error at curve: ${curveInput}")
                }
            }

    private val benchmarker: Benchmarker by lazy {
        if (providerInput == "bc") {
            BCBenchmarker()
        } else if (providerInput == "ncipher") {
            NCipherBenchmarker()
        } else {
            throw RuntimeException("Unexpected Error at provider: ${providerInput}")
        }
    }

    val provider by lazy { benchmarker.provider }
    val hashSignatureAlgorithm by lazy { benchmarker.hashSignatureAlgorithm }
    val signatureAlgorithm by lazy { benchmarker.signatureAlgorithm }
    //for bc : SHA256
    val hashAlgorithm = "SHA256"
    val privateKey by lazy { ecHelper.privateKey }
    val publicKey by lazy { ecHelper.publicKey }

    fun generateECSignature(input: ByteArray): ByteArray {
        return ecHelper.generateECSignature(input)
    }

    fun generateHash(input: ByteArray): ByteArray {
        return ecHelper.generateSHA256Hash(input)
    }


    companion object {
        private var instance: Supplier? = null
        fun getInstance(providerInput: String = "", curveInput: String = ""): Supplier {
            if (instance == null) {
                instance = Supplier(providerInput, curveInput)
                instance!!.c = curveInput
            }
            return instance!!
        }

    }
}