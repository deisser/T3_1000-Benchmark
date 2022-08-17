package com.koch

import com.ncipher.provider.km.nCipherKM
import java.security.Security

class NCipherBenchmarker() : Benchmarker() {
    init {
        Security.addProvider(nCipherKM())
    }
    override val provider: String
        get() = "nCipherKM"
    override val hashSignatureAlgorithm: String
        get() = "SHA256withECDSA"
    override val signatureAlgorithm: String
        get() = "SHA256WithECDSA"
}