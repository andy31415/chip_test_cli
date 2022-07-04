# How to run afl fuzzing

## Build the fuzzer

```
cargo afl build
```

## Run the fuzzer

```
cargo afl fuzz -i . -o out target/debug/fuzz-afl
```
