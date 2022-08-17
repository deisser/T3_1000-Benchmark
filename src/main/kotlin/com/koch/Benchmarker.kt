package com.koch

abstract class Benchmarker {
    abstract val provider: String
    abstract val hashSignatureAlgorithm: String
    abstract val signatureAlgorithm: String
}