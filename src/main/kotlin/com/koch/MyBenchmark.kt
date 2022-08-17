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
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.openjdk.jmh.annotations.*
import java.security.MessageDigest
import java.security.Security
import java.security.Signature
import java.util.concurrent.TimeUnit

var pickedProvider = "ncipher"
var pickedCurve = "p256"
//var info = InformationSupplier("bc", "p256")

fun main(args: Array<String>) {
    val validCurves = listOf("p256", "p384", "p521")
    val validProviders = listOf("bc", "ncipher")
    val parser = ArgParser("ECCBenchmark")
    val curve by parser.option(
        ArgType.Choice(validCurves, { it }),
        "curve",
        "c",
        description = "Name of the curve to be benchmarked"
    ).default("p256")
    val provider by parser.option(
        ArgType.Choice(validProviders, { it }),
        "provider",
        "p",
        description = "Name of provider to be used"
    ).default("bc")

    parser.parse(args)
    if (!validCurves.contains(curve) || !validProviders.contains(provider)) {
        println("Invalid options. Use one of valid curves and one of valid providers.")
        println("Valid options can be seen at \"benchmarks.jar -h\"")
        return
    }

    pickedCurve = curve
    pickedProvider = provider

    Supplier.getInstance(provider, curve)

    // Supplier.providerInput = provider
    // Supplier.curveInput = curve

    println(Supplier.getInstance().provider)
    // println(Supplier.getInstance().curveInput)

    //info = InformationSupplier(provider, curve)

    org.openjdk.jmh.Main.main(arrayOf<String>())
}

@State(Scope.Benchmark) //Ganzer Benchmark benutzt eine Instanz der Klasse. Mehrere Instanzen nicht notwendig, weil in der Klasse nichts überschrieben wird o.ä.
@BenchmarkMode(Mode.Throughput) //Misst den Umsatz an Methodenaufrufen
@OutputTimeUnit(TimeUnit.SECONDS) //Misst die Methodenaufrufe in Sekunden
@Warmup(
    iterations = 1,
    time = 2000,
    timeUnit = TimeUnit.MILLISECONDS
) //Notwendig, da die JVM mit mehrfachem Ausführen von Prozessen schneller wird; siehe Favorit "T1000/JVMWarmup"
@Measurement(iterations = 1, time = 2000, timeUnit = TimeUnit.MILLISECONDS)
@Fork(value = 1)    //Jeder Benchmark wird einmal ausgeführt
open class MyBenchmark {

    //init {
    //    Security.addProvider(BouncyCastleProvider())
        // Security.addProvider(nCipherKM())
    //}


    //companion object {
    //
    //}

    private val supplier = Supplier.getInstance(pickedProvider, pickedCurve)

    //read input file
    private val input: ByteArray = ResourceUtil.loadResource("/myfile.txt").readBytes()

    //sample signature
    private val sampleSig = supplier.generateECSignature(input)

    //sample input hash
    private val inputHash = supplier.generateHash(input)

    //sample signature object
    private val sigObj: Signature = Signature.getInstance(supplier.hashSignatureAlgorithm, supplier.provider)
    private val sigObjNoHash: Signature = Signature.getInstance(supplier.signatureAlgorithm, supplier.provider)

    /*@Setup
    fun init() {
        info = InformationSupplier(pickedProvider, pickedCurve)
    }*/

    @Benchmark  //Sorgt dafür, dass diese Methode gebenchmarkt wird
    fun hashBenchmark(state: MyBenchmark): ByteArray {
        val messageDigest = MessageDigest.getInstance(supplier.hashAlgorithm, supplier.provider)
        messageDigest.update(state.input)
        return messageDigest.digest()
    }

    @Benchmark
    fun signBenchmark(state: MyBenchmark): ByteArray {
        val signature = Signature.getInstance(supplier.hashSignatureAlgorithm, supplier.provider)
        signature.initSign(supplier.privateKey)
        signature.update(state.input)
        return signature.sign()
    }

    @Benchmark
    fun signBenchmark_preSignObj(state: MyBenchmark): ByteArray {
        state.sigObj.initSign(supplier.privateKey)
        state.sigObj.update(state.input)
        return state.sigObj.sign()
    }

    @Benchmark
    fun signWithoutHashBenchmark(state: MyBenchmark): ByteArray {
        val signature = Signature.getInstance(supplier.signatureAlgorithm, supplier.provider)
        signature.initSign(supplier.privateKey)
        signature.update(state.inputHash)
        return signature.sign()
    }

    @Benchmark
    fun signWithoutHashBenchmark_preSigObj(state: MyBenchmark): ByteArray {
        state.sigObjNoHash.initSign(supplier.privateKey)
        state.sigObjNoHash.update(state.inputHash)
        return state.sigObjNoHash.sign()
    }

    @Benchmark
    fun verifyBenchmark(state: MyBenchmark): Boolean {
        val signature = Signature.getInstance(supplier.hashSignatureAlgorithm, supplier.provider)
        signature.initVerify(supplier.publicKey)
        signature.update(state.input)
        return signature.verify(state.sampleSig)
    }

    @Benchmark
    fun verifyBenchmark_preSigObj(state: MyBenchmark): Boolean {
        state.sigObj.initVerify(supplier.publicKey)
        state.sigObj.update(state.input)
        return state.sigObj.verify(state.sampleSig)
    }

    @Benchmark
    fun baseline() {
    }
}