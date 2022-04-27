/*
 * Copyright (c) 2014, Oracle America, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * Neither the name of Oracle nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.koch

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.openjdk.jmh.annotations.*
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import java.security.Security
import java.security.Signature
import java.util.concurrent.TimeUnit

open class MyBenchmark {

    @State(Scope.Thread)
    open class SetupClass {

        init {
            Security.addProvider(BouncyCastleProvider())
        }

        private val ecHelper = ECHelper(this)
        val provider = "BC"

        //read all keys
        val publicKey = ecHelper.readPublicKey("src/main/kotlin/com/koch/resources/secp521r1_public.pem")
        val privateKey = ecHelper.readPrivateKey("src/main/kotlin/com/koch/resources/secp521r1_pkcs8_private.pem")

        //read input file
        private val inputPath: Path = Paths.get("sampledata/myfile.txt")
        val input: ByteArray = Files.readAllBytes(inputPath)

        //sample signature
        val samplesig = ecHelper.generateECSignature(privateKey, input)

        //sample input hash
        val inputHash = ecHelper.generateSHA256Hash(input)

        //sample signature object
        val sigobj: Signature = Signature.getInstance("SHA256withECDSA", provider)
        val sigobjnohash: Signature = Signature.getInstance("NoneWithECDSA", provider)
    }


    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 3, time = 10000, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 30, time = 200, timeUnit = TimeUnit.MILLISECONDS)
    @Fork(value = 1)
    fun baseline() {
    }


    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 3, time = 10000, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 30, time = 200, timeUnit = TimeUnit.MILLISECONDS)
    @Fork(value = 1)
    fun hashBenchmark(state: SetupClass): ByteArray {
        val messageDigest = MessageDigest.getInstance("SHA-256", state.provider)
        messageDigest.update(state.input)
        return messageDigest.digest()
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 3, time = 10000, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 30, time = 200, timeUnit = TimeUnit.MILLISECONDS)
    @Fork(value = 1)
    fun signBenchmark(state: SetupClass): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA", state.provider)
        signature.initSign(state.privateKey)
        signature.update(state.input)
        return signature.sign()
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 3, time = 10000, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 30, time = 200, timeUnit = TimeUnit.MILLISECONDS)
    @Fork(value = 1)
    fun signBenchmark_preSignObj(state: SetupClass): ByteArray {
        state.sigobj.initSign(state.privateKey)
        state.sigobj.update(state.input)
        return state.sigobj.sign()
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 3, time = 10000, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 30, time = 200, timeUnit = TimeUnit.MILLISECONDS)
    @Fork(value = 1)
    fun signWithoutHashBenchmark(state: SetupClass): ByteArray {
        val signature = Signature.getInstance("NoneWithECDSA", state.provider)
        signature.initSign(state.privateKey)
        signature.update(state.inputHash)
        return signature.sign()
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 3, time = 10000, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 30, time = 200, timeUnit = TimeUnit.MILLISECONDS)
    @Fork(value = 1)
    fun signWithoutHashBenchmark_preSigObj(state: SetupClass): ByteArray {
        state.sigobjnohash.initSign(state.privateKey)
        state.sigobjnohash.update(state.inputHash)
        return state.sigobjnohash.sign()
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 3, time = 10000, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 30, time = 200, timeUnit = TimeUnit.MILLISECONDS)
    @Fork(value = 1)
    fun verifyBenchmark(state: SetupClass): Boolean {
        val signature = Signature.getInstance("SHA256withECDSA", state.provider)
        signature.initVerify(state.publicKey)
        signature.update(state.input)
        return signature.verify(state.samplesig)
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 3, time = 10000, timeUnit = TimeUnit.MILLISECONDS)
    @Measurement(iterations = 30, time = 200, timeUnit = TimeUnit.MILLISECONDS)
    @Fork(value = 1)
    fun verifyBenchmark_preSigObj(state: SetupClass): Boolean {
        state.sigobj.initVerify(state.publicKey)
        state.sigobj.update(state.input)
        return state.sigobj.verify(state.samplesig)
    }
}