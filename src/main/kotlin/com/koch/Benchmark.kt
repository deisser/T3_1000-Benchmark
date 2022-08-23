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

import com.ncipher.provider.CoreECKey
import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import org.openjdk.jmh.annotations.*
import java.security.Signature
import java.util.concurrent.TimeUnit

/**
 * In den Variablen "pickedProvider" und "pickedCurve" müssen Provider und Kurve eingestellt werden.
 * Mögliche Optionen:
 * - Provider: "bc", "ncipher"
 * - Kurven: "p256", "p384", "p521"
 *
 * Warum ist das so unschön gelöst?
 *
 * Mit jmh ist das problematisch. In jedem Benchmark wird das Singleton (InformationSupplier) zurückgesetzt, wodurch wegen
 * des default-Strings "" immer in die RuntimeException reingelaufen wird, weil "" eine nicht zulässige
 * Kurve bzw. Provider ist. Das kann in der Main beim Argument-parsen nicht abgefangen werden, weil es beim ersten Durchlauf
 * ein legales Argument ist, wie in den Defaults des Parsens hinterlegt. Aber eben nur beim ersten Durchlauf.
 *
 * Das tut zur reinen Messung allerdings nichts zur Sache. Man muss Kurve und Provider nur händisch im Code einstellen.
 */
var pickedProvider = "bc"
var pickedCurve = "p256"

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
    if (!validCurves.contains(pickedCurve) || !validProviders.contains(pickedProvider)) {
        println("Invalid options. Use one of valid curves and one of valid providers.")
        println("Valid options can be seen at \"benchmarks.jar -h\"")
        return
    }
    pickedCurve = curve
    pickedProvider = provider
    Supplier.getInstance(provider, curve)
    org.openjdk.jmh.Main.main(arrayOf<String>())
}

@State(Scope.Benchmark) //Ganzer Benchmark benutzt eine Instanz der Klasse. Mehrere Instanzen nicht notwendig, weil in der Klasse nichts überschrieben wird o.ä.
@BenchmarkMode(Mode.Throughput) //Misst den Umsatz an Methodenaufrufen
@OutputTimeUnit(TimeUnit.SECONDS) //Misst die Methodenaufrufe in Sekunden
@Warmup(iterations = 1, time = 1000, timeUnit = TimeUnit.MILLISECONDS) //Notwendig, da die JVM mit mehrfachem Ausführen von Prozessen schneller wird; siehe Favorit "T1000/JVMWarmup"
@Measurement(iterations = 10, time = 1000, timeUnit = TimeUnit.MILLISECONDS)
@Fork(value = 1)    //Jeder Benchmark wird einmal ausgeführt
open class LowWarmup {

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

    @Benchmark
    fun signBenchmark(state: LowWarmup): ByteArray {
        val signature = Signature.getInstance(supplier.hashSignatureAlgorithm, supplier.provider)
        signature.initSign(supplier.privateKey)
        signature.update(state.input)
        return signature.sign()
    }

    @Benchmark
    fun signBenchmark_preSignObj(state: LowWarmup): ByteArray {
        state.sigObj.initSign(supplier.privateKey)
        state.sigObj.update(state.input)
        return state.sigObj.sign()
    }

    @Benchmark
    fun signWithoutHashBenchmark(state: LowWarmup): ByteArray {
        return if (pickedProvider == "bc") {
            val signature = Signature.getInstance(supplier.signatureAlgorithm, supplier.provider)
            signature.initSign(supplier.privateKey)
            signature.update(state.inputHash)
            signature.sign()
        } else {
            NCipherPreHashSignProvider.sign(supplier.privateKey as CoreECKey, state.inputHash)
        }
    }

    @Benchmark
    fun verifyBenchmark(state: LowWarmup): Boolean {
        val signature = Signature.getInstance(supplier.hashSignatureAlgorithm, supplier.provider)
        signature.initVerify(supplier.publicKey)
        signature.update(state.input)
        return signature.verify(state.sampleSig)
    }

    @Benchmark
    fun verifyBenchmark_preSigObj(state: LowWarmup): Boolean {
        state.sigObj.initVerify(supplier.publicKey)
        state.sigObj.update(state.input)
        return state.sigObj.verify(state.sampleSig)
    }
}

@State(Scope.Benchmark) //Ganzer Benchmark benutzt eine Instanz der Klasse. Mehrere Instanzen nicht notwendig, weil in der Klasse nichts überschrieben wird o.ä.
@BenchmarkMode(Mode.Throughput) //Misst den Umsatz an Methodenaufrufen
@OutputTimeUnit(TimeUnit.SECONDS) //Misst die Methodenaufrufe in Sekunden
@Warmup(iterations = 4, time = 1000, timeUnit = TimeUnit.MILLISECONDS) //Notwendig, da die JVM mit mehrfachem Ausführen von Prozessen schneller wird; siehe Favorit "T1000/JVMWarmup"
@Measurement(iterations = 10, time = 1000, timeUnit = TimeUnit.MILLISECONDS)
@Fork(value = 1)    //Jeder Benchmark wird einmal ausgeführt
open class MediumWarmup {

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


    @Benchmark
    fun signBenchmark(state: MediumWarmup): ByteArray {
        val signature = Signature.getInstance(supplier.hashSignatureAlgorithm, supplier.provider)
        signature.initSign(supplier.privateKey)
        signature.update(state.input)
        return signature.sign()
    }

    @Benchmark
    fun signBenchmark_preSignObj(state: MediumWarmup): ByteArray {
        state.sigObj.initSign(supplier.privateKey)
        state.sigObj.update(state.input)
        return state.sigObj.sign()
    }

    @Benchmark
    fun signWithoutHashBenchmark(state: MediumWarmup): ByteArray {
        return if (pickedProvider == "bc") {
            val signature = Signature.getInstance(supplier.signatureAlgorithm, supplier.provider)
            signature.initSign(supplier.privateKey)
            signature.update(state.inputHash)
            signature.sign()
        } else {
            NCipherPreHashSignProvider.sign(supplier.privateKey as CoreECKey, state.inputHash)
        }

    }

    @Benchmark
    fun verifyBenchmark(state: MediumWarmup): Boolean {
        val signature = Signature.getInstance(supplier.hashSignatureAlgorithm, supplier.provider)
        signature.initVerify(supplier.publicKey)
        signature.update(state.input)
        return signature.verify(state.sampleSig)
    }

    @Benchmark
    fun verifyBenchmark_preSigObj(state: MediumWarmup): Boolean {
        state.sigObj.initVerify(supplier.publicKey)
        state.sigObj.update(state.input)
        return state.sigObj.verify(state.sampleSig)
    }
}

@State(Scope.Benchmark) //Ganzer Benchmark benutzt eine Instanz der Klasse. Mehrere Instanzen nicht notwendig, weil in der Klasse nichts überschrieben wird o.ä.
@BenchmarkMode(Mode.Throughput) //Misst den Umsatz an Methodenaufrufen
@OutputTimeUnit(TimeUnit.SECONDS) //Misst die Methodenaufrufe in Sekunden
@Warmup(iterations = 10, time = 1000, timeUnit = TimeUnit.MILLISECONDS) //Notwendig, da die JVM mit mehrfachem Ausführen von Prozessen schneller wird; siehe Favorit "T1000/JVMWarmup"
@Measurement(iterations = 10, time = 1000, timeUnit = TimeUnit.MILLISECONDS)
@Fork(value = 1)    //Jeder Benchmark wird einmal ausgeführt
open class HighWarmup {

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

    @Benchmark
    fun signBenchmark(state: HighWarmup): ByteArray {
        val signature = Signature.getInstance(supplier.hashSignatureAlgorithm, supplier.provider)
        signature.initSign(supplier.privateKey)
        signature.update(state.input)
        return signature.sign()
    }

    @Benchmark
    fun signBenchmark_preSignObj(state: HighWarmup): ByteArray {
        state.sigObj.initSign(supplier.privateKey)
        state.sigObj.update(state.input)
        return state.sigObj.sign()
    }

    @Benchmark
    fun signWithoutHashBenchmark(state: HighWarmup): ByteArray {
        return if (pickedProvider == "bc") {
            val signature = Signature.getInstance(supplier.signatureAlgorithm, supplier.provider)
            signature.initSign(supplier.privateKey)
            signature.update(state.inputHash)
            signature.sign()
        } else {
            NCipherPreHashSignProvider.sign(supplier.privateKey as CoreECKey, state.inputHash)
        }

    }

    @Benchmark
    fun verifyBenchmark(state: HighWarmup): Boolean {
        val signature = Signature.getInstance(supplier.hashSignatureAlgorithm, supplier.provider)
        signature.initVerify(supplier.publicKey)
        signature.update(state.input)
        return signature.verify(state.sampleSig)
    }

    @Benchmark
    fun verifyBenchmark_preSigObj(state: HighWarmup): Boolean {
        state.sigObj.initVerify(supplier.publicKey)
        state.sigObj.update(state.input)
        return state.sigObj.verify(state.sampleSig)
    }
}