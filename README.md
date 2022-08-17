# Benchmark for elliptic Curve operations with BouncyCastle and nCipher

This benchmark is the practical part of the T3_1000 thesis of Maris Koch from August/September 2022.

### Title:

> Performancevergleich von den opensource Kryptobibliotheken OpenSSL und BouncyCastle zu einem Hardware Security Module
> beim Ausführen von Kryptooperationen mit elliptischen Kurven

### Build and Run the Benchmark

- Use `mvm clean install` to build the project
- The artifact is named `benchmarks.jar` and is located at `./target/benchmarks.jar`
- To run the benchmarks use `java -jar benchmarks.jar`

### Libraries

- jmh (Java Microbenchmark Harness)

[jmh](https://github.com/openjdk/jmh) provides the benchmark framework. Every method with `@Benchmark` annotation will
be benchmarked. Further information as well as [examples for jmh](https://github.com/openjdk/jmh/tree/master/jmh-samples/src/main/java/org/openjdk/jmh/samples) can be taken from the jmh repository.

- kotlinx-cli (implemented, but has no effect)

[kotlinx-cli](https://github.com/Kotlin/kotlinx-cli) is used to have a command line interaction on what to benchmark. Further documentation can be taken from the kotlinx-cli repository. 

### CLI interaction

- `--curve` or `-c` to choose curve. Currently 
- `--provider` or `-p`

Submission Date: 05.09.2022