![banner](https://github.com/androguard/goauld/blob/344d57215176e8f072262b0c208044a00b765cd1/assets/web/goauld.jpeg)

# Goauld

> Dynamic injection tool for Linux/Android process via /proc/pid/mem, for the [Androguard Project](https://github.com/androguard/androguard).

Goauld is a simple tool that will allow you to inject a piece of code (a shared libary) in a process without using Ptrace syscall, directly via /proc/pid/mem.

It is a mix between multiple nice projects, like [intruducer](https://github.com/vfsfitvnm/intruducer/tree/master), [linjector-rs](https://github.com/erfur/linjector-rs), and many others,
where I tried to take the best parts and add new features. This project has been created for educational purpose, and as a first debugging tool for Androguard.

Instead of directly hijacking the current flow of a binary, Goauld will create 2 payloads and will hijack a libc function (default: malloc), and wait a call to this function from the binary to start
the injection.

Basically, the design of Goauld is the following:
 * Find three addresses, A1: one of a libc function, A2: a variable in the libc, A3: the dlopen function from the libc
 * Create two payloads in memory, P1 and P2
 * Open /proc/pid/mem in order to inject P1 at A1
 * Wait a trigger of the libc function to execute P1 in order to allocate some space in N1
 * Execute P1, and use A2 as a mechanism for threads synchronizations and as a way to communicate with the command line tool
 * Inject at N1 the P2 payload and jump on it
 * Load the shared library via P2
 * Jump back to the A1 libc function to return to the original flow


 P1 payload (@A1):
 * sync other threads with the A2 variable
 * call the mmap syscall for the P2 payload
 * write the new allocated address N1 into the A2 variable
 * write a loop jump in the N1 address
 * write P2 in N1
 * jump to the N1 address

 P2 payload (@N1):
 * call A3 the dlopen function from the libc to load the shared library
 * Restore the original context
 * Jump back to the A1 address

## Features

* Shared Library injection
* `Linux`/`Android`
* `x86`, `x86_64`, `aarch64`


## Build

You can build it and run it via cargo directly.

```sh
cargo build --release --bin goauld-cli
```


Or you can compile some shared library:
```sh
rustc ./examples/evil.rs --crate-type cdylib --out-dir ./target/debug/examples
```

### Android

Build (via cargo-ndk) and copy the cli binary on the Android Phone:
```sh
cargo ndk -t arm64-v8a build --release --bin goauld-cli
adb push target/aarch64-linux-android/release/goauld-cli /data/local/tmp
adb shell chmod 755 /data/local/tmp/goauld-cli
```


## Examples

Be sure you have the right to write into /proc/PID/mem (defined in this following variable):
```sh
sudo sysctl kernel.yama.ptrace_scope=0
```

On one terminal, you can run the example victim binary (it is a specific program with a forced alloc to trigger the malloc function):
```sh
cargo build --example victim_alloc
./target/debug/examples/victim_alloc
```


And in another terminal, you can inject a shared libary into this binary (you need to find out the PID):
```sh
cargo run --release --bin goauld-cli -- --pid PID --file target/debug/examples/libevil.so --debug
```


### Linux

#### With Frida

You can inject [Frida Gadget](https://frida.re/docs/gadget/) shared library directly in a remote process to perform any advance hooks with Javascript.

```sh
cargo run --release --bin goauld-cli -- --pid PID --file ~/frida/binaries/frida-gadget-16.3.3-linux-x86_64.so --debug
frida -H localhost Gadget -l examples/frida_gadget/test.js
```

### Android

Find out the application to infect and use the cli binary to inject and run the frida gadget shared library for example:
```sh
ps -A |grep package_name

You can copy and change the context of the shared library (but the tool will do it):
```sh
adb push frida-gadget-16.3.3-android-arm64.so /data/local/tmp/frida-gadget-android-arm64.so
chcon -v u:object_r:apk_data_file:s0 f/data/local/tmp/frida-gadget-android-arm64.so
```

If you have injected the frida gadget library, in another terminal, you can connect with the frida command line to the Android Phone to the infected process,
like for example to display a tiny message, but you can also start to hijack any functions:
```sh
frida -U -f re.frida.Gadget -l toast.js
```

```sh
x:/data/local/tmp # cat frida-gadget-android-arm64.config
{
        "interaction" : {
                "type": "script",
                "path": "/data/local/tmp/test.js"
        }
}
```

```sh
x:/data/local/tmp # cat test.js
Java.perform(function () {
    var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();

    Java.scheduleOnMainThread(function() {
            var toast = Java.use("android.widget.Toast");
            toast.makeText(Java.use("android.app.ActivityThread").currentApplication().getApplicationContext(), Java.use("java.lang.String").$new("Hello from your Goauld !"), 1).show();
    });
});
```

```sh
x:/data/local/tmp # ./goauld-cli --pid PID --file frida-gadget-android-arm64.so
```

## Caveats

The tool has been tested on all supported architectures, but if you encounter any bugs, please create a new [issue](https://github.com/androguard/goauld/issues) to fix it.
