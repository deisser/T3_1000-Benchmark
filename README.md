# Benchmark for elliptic Curve operations with BouncyCastle and nCipher

This benchmark is the practical part of the T3_1000 thesis of Maris Koch from August/September 2022.

### Title: 

> Performancevergleich von den opensource Kryptobibliotheken OpenSSL und BouncyCastle zu einem Hardware Security Module
> beim Ausführen von Kryptooperationen mit elliptischen Kurven

### Build and Run the Benchmark

**Disclaimer**: nCipherKM library is required for the build. License needs to be purchased from enTrust.

- Use `mvm clean install` to build the project
- The artifact is named `benchmarks.jar` and is located at `./target/benchmarks.jar`
- To run the benchmarks use `java -jar benchmarks.jar` or the corresponding path to the artifact

### Where are the Benchmarks

The Benchmarks are all in `./src/main/kotlin/com/koch/Benchmark.kt`. Every Method with `@Benchmark` annotation
will be benchmarked.

### Choose what to benchmark

Since the CLI interaction is not working at the moment, the way to pick a provider and a curve is through
`./src/main/kotlin/com/koch/Benchmark.kt`. Insert one of the options listed above for provider and curve into the
variables `pickedProvider` and `pickedCurve` at the top of the file.

### Libraries

- jmh (Java Microbenchmark Harness)

[jmh](https://github.com/openjdk/jmh) provides the benchmark framework. Every method with `@Benchmark` annotation will
be benchmarked. Further information as well
as [examples for jmh](https://github.com/openjdk/jmh/tree/master/jmh-samples/src/main/java/org/openjdk/jmh/samples) can
be taken from the jmh repository.

### Note for nCipherKM Provider

A tunnel to the HSM must be active. Use Putty. Otherwise, there will be an error of the form `ServerNotRunning`.

Submission date of thesis: 05.09.2022
