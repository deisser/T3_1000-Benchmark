package com.koch

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class BCBenchmarker() : Benchmarker() {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    override val provider: String
        get() = "BC"
    override val hashSignatureAlgorithm: String
        get() = "SHA256withECDSA"
    override val signatureAlgorithm: String
        get() = "NoneWithECDSA"
}