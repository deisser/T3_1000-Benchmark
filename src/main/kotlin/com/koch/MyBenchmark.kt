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

import com.ncipher.provider.km.nCipherKM
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.openjdk.jmh.annotations.*
import java.security.MessageDigest
import java.security.Security
import java.security.Signature
import java.util.concurrent.TimeUnit

@State(Scope.Benchmark) //Ganzer Benchmark benutzt eine Instanz der Klasse. Mehrere Instanzen nicht notwendig, weil in der Klasse nichts überschrieben wird o.ä.
@BenchmarkMode(Mode.Throughput) //Misst den Umsatz an Methodenaufrufen
@OutputTimeUnit(TimeUnit.SECONDS)   //Misst die Methodenaufrufe in Sekunden
@Warmup(iterations = 2, time = 10000, timeUnit = TimeUnit.MILLISECONDS) //Notwendig, da die JVM mit mehrfachem Ausführen von Prozessen schneller wird; siehe Favorit "T1000/JVMWarmup"
@Measurement(iterations = 1, time = 10000, timeUnit = TimeUnit.MILLISECONDS)
@Fork(value = 1)    //Jeder Benchmark wird einmal ausgeführt
open class MyBenchmark {

    init {
        Security.addProvider(BouncyCastleProvider())
        Security.addProvider(nCipherKM())
    }

    companion object {
        //const val PROVIDER = "BC"
        const val PROVIDER = "nCipherKM"
    }

   /* val obj;
    if(provider == ...) {
        obj = dataclass("..." ":::")
    } else {
        obj = dataclass("___" "+++")
    }*/

    val ecHelper =
        ECHelper("/secp521r1_pkcs8_private.pem", "/secp521r1_public.pem")

    //read input file
    val input: ByteArray = ResourceUtil.loadResource("/myfile.txt").readBytes()

    //sample signature
    val samplesig = ecHelper.generateECSignature(input)

    //sample input hash
    val inputHash = ecHelper.generateSHA256Hash(input)

    //sample signature object
    val sigobj: Signature = Signature.getInstance("SHA256withECDSA", PROVIDER)
    val sigobjnohash: Signature = Signature.getInstance("NoneWithECDSA", PROVIDER)



    @Benchmark  //Sorgt dafür, dass diese Methode gebenchmarkt wird
    fun hashBenchmark(state: MyBenchmark): ByteArray {
        val messageDigest = MessageDigest.getInstance("SHA-256", PROVIDER)
        messageDigest.update(state.input)
        return messageDigest.digest()
    }

    @Benchmark
    fun signBenchmark(state: MyBenchmark): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA", PROVIDER)
        signature.initSign(state.ecHelper.privateKey)
        signature.update(state.input)
        return signature.sign()
    }

    @Benchmark
    fun signBenchmark_preSignObj(state: MyBenchmark): ByteArray {
        state.sigobj.initSign(state.ecHelper.privateKey)
        state.sigobj.update(state.input)
        return state.sigobj.sign()
    }

    @Benchmark
    fun signWithoutHashBenchmark(state: MyBenchmark): ByteArray {
        val signature = Signature.getInstance("NoneWithECDSA", PROVIDER)
        signature.initSign(state.ecHelper.privateKey)
        signature.update(state.inputHash)
        return signature.sign()
    }

    @Benchmark
    fun signWithoutHashBenchmark_preSigObj(state: MyBenchmark): ByteArray {
        state.sigobjnohash.initSign(state.ecHelper.privateKey)
        state.sigobjnohash.update(state.inputHash)
        return state.sigobjnohash.sign()
    }

    @Benchmark
    fun verifyBenchmark(state: MyBenchmark): Boolean {
        val signature = Signature.getInstance("SHA256withECDSA", PROVIDER)
        signature.initVerify(state.ecHelper.publicKey)
        signature.update(state.input)
        return signature.verify(state.samplesig)
    }

    @Benchmark
    fun verifyBenchmark_preSigObj(state: MyBenchmark): Boolean {
        state.sigobj.initVerify(state.ecHelper.publicKey)
        state.sigobj.update(state.input)
        return state.sigobj.verify(state.samplesig)
    }

    @Benchmark
    fun baseline() {
    }
}