# What is it?

Jlsca is a toolbox in Julia to do the computational part (DPA) of a side channel attack. It supports:

* Conditional averaging
* Conditional sample reduction
* Incremental correlation statistics
* Parallelization of the above
* Correlation power analysis (CPA) and non-profiled Linear regression analysis (LRA)
* AES128/192/256 enc/dec, backward/forward S-box attacks
* AES128 enc/dec chosen input MixColumn attack
* DES/TDES1/TDES2/TDES3 enc/dec, backward/forward attack
* Known key analysis + key rank evolution CSV output
* Inspector trace set input
* Split sample and data raw binary (Daredevil) input
* I've been playing with a Picoscope, and there is an example in `piposcope.jl` that does (a quite fast, if I may say so myself) acquisition on Riscure's Pinata board using the scope's rapid block mode. Check the file header of `piposcope.jl` for more information.

# Why would I want it?

It runs standalone or inside Riscure's Inspector as a module, so you would want this if:

* You don't have Inspector but you want to do DPA or understand how it works.

* You have Inspector but you want to play with features that are currently (4.10) not in Inspector, like:
	* [non-profiled LRA](https://eprint.iacr.org/2013/794.pdf)
 	* [Conditional averaging](https://eprint.iacr.org/2013/794.pdf)
	* Conditional sample reduction for attacking whiteboxes (see conditional-bitwisereduction.jl for what that means)

# Who wrote it?

It's written for fun by me (Cees-Bart Breunesse), and Ilya Kizhvatov contributed some python example code I shamelessly copied and adapted. It's not a Riscure product, and Riscure does not support or maintain this code. If it crashes or you have feature requests, Github allows you to contact the authors, or you do a pull request ;-)

# Installation

0. Git clone this repo

1. Install Julia (0.5.0 is tested) and make sure the `julia` executable is in your path (for Windows users).

2. Start a shell or cmd shell (Windows users), and install an additional required package ProgressMeter like this:
	`julia -e 'Pkg.add("ProgressMeter")'`

# Running from cmd line

There are a few example *main* files (i.e. files that import the Jlsca library) that, except for one, can run *all* the example AES and DES traces in the `aestraces` and `destraces` directories. The attack parameters and "known key" used in these main files are extracted from the file name, and some hard coded attack defaults are used (i.e. CPA, single bit0 or HW attack). You can change all this by editing the main files only: the library code (everything referenced by `sca.jl`) need not be touched for that.

## `main-noninc.jl`

This file performs vanilla correlation statistics on an input trace set. Vanilla meaning that it will compute correlation with the entire sample and hypothesis matrices present in memory. This is a good starting point for playing and implementing new statistics or attacks. This main does not do parallelization, so it will complain when you specify multiple processes (`-pX`) on the `julia` command line. For example:
```
julia -Lsca.jl main-noninc.jl destraces/tdes2_enc_9084b0087a1a1270587c146ccc60a252.trs
```

## `main-condavg.jl`

This file performs vanilla correlation statistics but will first run the conditional averager over the trace set input. This can be parallelized, for example the following will use three local processes to perform the conditional averaging.
```
julia -p3 -Lsca.jl main-condavg.jl aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs
```

## `main-condred.jl`

This file perform vanilla correlation statistics over conditionally sample reduced trace sets. Check the source of `conditional-bitwisereduction.jl` if you want to know more; this is only useful for whiteboxes, since it works on bit vector sample data, not on floating points. This process can be parallelized, for example on three processes as demonstrated here:
```
julia -p3 -Lsca.jl main-condred.jl destraces/des_enc_1c764a2af6e0322e.trs
```
## `main-condred-wbaes.jl`

This file combines Klemsa's [leakage models](https://eprint.iacr.org/2013/794.pdf) for tackling Dual AES with the conditional bit wise reduction. Can be parallelized. In `main-condred-wbaes.jl` the attack params are hardcoded for AES128 trace sets, so you'll need to edit the main file if you want pass it something else, like AES192 or 256. If you want to apply this on your own whitebox data make sure the `params.dataOffset` in `main-condred-wbaes.jl` point to the input (if `params.direction == FORWARD`) or output (if `params.direction == BACKWARD`). Can parallelized, for example:
```
julia -p3 -Lsca.jl main-condred-wbaes.jl aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs
```

## `main-inccpa.jl`

Last but not least, this file will perform a correlation attack using incremental correlation statistics. This is what Inspector also implements in its "first order" attack modules. You can parallelize this attack. For example:
```
julia -p3 -Lsca.jl main-inccpa.jl aestraces/aes128_mc_invciph_da6339e783ee690017b8604aaeed3a6d.trs
```

# Interactive

XXX shell stuff

# Hacking stuff

By all means take a look at the `main-xxx.jl` files, pick one that matches what you want to do closest, copy and change accordingly. Below are some more details on how to set parameters, data and sample passes.

## Attack parameters

There are three supported attacks: AesSboxAttack(), AesMCAttack() and DesSboxAttack(), defined in attackaes-core.jl and attackdes-core.jl. For example, the following creates a forward AES128 attack attack on all 8 bits of the intermediate state with vanilla CPA:

```julia
params = AesSboxAttack()
params.mode = CIPHER
params.keyLength = KL128
params.direction = FORWARD
params.analysis = DPA()
params.analysis.statistic = cor
params.analysis.leakageFunctions = [x -> ((x .>> i) & 1) for i in 0:7 ]
```
If you'd like to attack with HW instead, write this:
```julia
params.analysis.leakageFunctions = [hw]
```
If you want all bits, do this:
```julia
params.analysis.leakageFunctions = [x -> ((x .>> i) & 1) for i in 0:7]
```
If you want to attack the HD between S-box in and out, set this:
```julia
params.xor = true
```
Since we're configuring a forward attack, we need to tell Jlsca what the offset of the input in the trace data is:
```julia
params.dataOffset = 1
```
This means that the input data is the start of the trace data: Julia offsets are 1-based!! If you'd rather run the attack backwards, and the output data is located after the input, you'd type this:
```julia
params.direction = BACKWARD
params.dataOffset = 17
```
If we want to attack all key bytes, we write this:
```julia
params.keyByteOffsets = collect(1:16)
```
If we only want the first and last key bytes we write this:
```julia
params.keyByteOffsets = [1,16]
```
If we want LRA instead of CPA, we do this:
```julia
params.analysis = LRA()
params.analysis.basisModel = basisModelSingleBits
```
Big fat disclaimer: currently LRA only supports only a 9 bit model, even if you do a AES MC attack! I need to understand some more about this attack, since choosing a 33 bit basis model results in non-invertible matrices (and a crash).

## Passing attack phase data

To attack inner rounds you need to use key material you recovered earlier. Jlsca does all this automagically by default. For example, AES192 consists of two separate attacks. If you want to attack AES192 you can tell Jlsca to do both phases sequentially without user interaction by setting the attack parameter:
```julia
params.phases = [PHASE1, PHASE2]
```
Jlsca will then run the two attacks, combine the results, and spits out the full key.

If you want to control the two phases explicitly (if you run the Jlsca module in Inspector, for example) you can do so too. Again, for AES192, you'd first run the attack with:
```julia
params.phases = [PHASE1]
```
which gives you the first round key, printed as a hex string labeled "next phase input" on the console. You cut and paste that information into the next phase like this:
```julia
params.phases = [PHASE2]
params.phaseInput = Nullable(hex2bytes("00112233445566778899aabbccddeeff")))
```

## Passing attack phase data from Inspector

If you run the Jlsca Inspector module, you'll have to paste this data (only the hex string) into a GUI text field yourself since I'm to lazy to parse the Jlsca output and feed it back into the module.

## Passes and processors

Attacks in Jlsca work on instances of the `Trace` type. There are two implementations of this type in Jlsca: `InspectorTrace` representing an Inspector trace set, and `SplitBinary` representing the completely flat and split data and samples used in, for example, Daredevil. These types are not simply providing access to the trace data in files, they come with addition functionality.

Suppose for example we open an Inspector trace set as follows. This reads the meta data corresponding to the trace set on disk, but does not read all the data in the file.
```julia
trs = InspectorTrace("bla.trs")
```
We can now read a the first trace (i.e. a tuple of the data and corresponding samples) like this.
```julia
(data, sample) = trs[1]
```
Suppose now that we would like to take the absolute of all samples, each time we read one trace. You can of course simply run `abs(samples)`, but if you pass the `trs` instance into the Jlsca library that, for example, performs a DPA attack on that file, you'd have to modify this code to call `abs(samples)`. Instead, you can add a "sample pass" to the `trs` object. A pass is simply a function, that will be run over the trace at the moment it's read.
```julia
# add function abs to the trs objet
addSamplePass(trs, abs)
# read a trace
(data, samples) = trs[1]
# samples now contain the absolute
```
You can add as many passes as you want, and they will be executed in the order you add them. For example:
```julia
# only get the first 2048 samples
addSamplePass(trs, x -> x[1:2047])
# then, compute the spectrum over that
addSamplePass(trs, real(fft(x)))
```
A similar mechanism exists for the data in a trace set by means of the function `addDataPass`. Internally in Jlsca this function is used to add cipher round functions 	during an attack. From a users perspective you only really need a data pass for filtering traces. For example, consider a trace set with TVLA traces where the first byte of the data field is set to 0x01 for a random input, and 0x00 for a semi-constant input. Then, if we want to attack using on the random traces we'd write:

```julia
# return only the traces with the first data byte set to 0x1
addDataPass(trs, x -> x[1] == 0x1 ? x : Vector{UInt8}())
```

Once you push a sample or data pass on the stack of passes, you can pop the last one you added by calling popSamplePass() or popDataPass().

## Conditional averaging and potential other post processors

Conditional averaging [Conditional averaging](https://eprint.iacr.org/2013/794.pdf) is implemented as a trace post processor that is configured in the "trs" object as follows:
```julia
setPostProcessor(trs, CondAvg, getNumberOfAverages(params))
```
For AES, there are max 256 averages per key byte offset. For DES SBOX out there are 64, and for DES ROUNDOUT there are 1024. This is returned by getNumberOfAverages(). See type CondAvg in conditional-average.jl how the averager works: it uses Julia's newly added Threads module. By default only a single thread is used. If you set the JULIA_NUM_THREADS=2 environment variable it will use 2 threads, making it quite much faster if the input has many samples. Using more than 2 threads doesn't currently speed up the process (on my laptop at least), but I haven't profiled it.

The data passes that are configured with addDataPass determine the data on which conditional averaging operates: for AES this is simply the input or the output. For DES it is not since the input or output data gets bit picked from all over the place before it is recombined with a key, and therefore we cannot simply average on individual input bytes. See function round1 in attackdes-core.jl, for example, to see how data is preprocessed before being fed into the conditional averager.

## Parallelization

What's currently parallelized are the post processors:
* Conditional sample reduction
* Conditional averaging
* Incremental correlation statistics

All the provided main-xxx.jl files can be run with -pX to run on X processors (local or not, as long as the trace set input is available for all processes). 

There are currently 3 different ways to parallelize each post processor:
* SplitByData: This means that each process will visit each trace, but do only a part of the work for each trace, split by data. For example, for conditional averaging each process only keeps the averages for which it is responsible. If there are N processes, and the total amount of memory for all averages is M, each process uses M/N memory. 
* SplitByTracesBlock: This means that each process will visit a subset of traces, but do all the work required for that trace. For conditional averaging this means that each process needs M memory but less trace data needs to be moved around and interpreted. Traces are split in blocks, i.e. the first N go to process 1, the second N to process 2 etc.
* SplitByTracesSliced: Same as SplitByTracesBLock, but process 1 takes trace 1, process 2 takes trace 2, etc.

Since parallelization is tightly coupled to post processors, you need to pass the SplitXXX instance to the post processor instance, see main-xxx.jl.

## Test runs

If you hack stuff and you want to verify stuff is still working, you can run all the tests:

```
#!/bin/bash

# AES cipher implementation tests
julia aes-tests.jl && \
# DES cipher implementation tests
julia des-tests.jl && \
# incremental statistics tests
julia incremental-statistics-tests.jl && \
# some work split related sanity checks
julia distributed-tests.jl && \
# trs testing
julia trs-tests.jl && \

# AES attack tests, all modes and directions. Can be called with -pX too.
julia -Lsca.jl attackaes-tests.jl && \
# DES attack tests, all modes and directions. Can be called with -pX too.
julia -Lsca.jl attackdes-tests.jl && \


# Parallelization tests for conditional averaging
julia -p3 -Lsca.jl conditional-average-tests.jl && \
# Parallelization tests for condition bitwise sample reduction
julia -p3 -Lsca.jl conditional-bitwisereduction-tests.jl && \
# Parallelization & vanilla correlation equivalence tests for incremental correlation statistics
julia -p3 -Lsca.jl incremental-correlation-tests.jl && \

# Example run of main function that performs vanilla correlation statistics on an input trace set (i.e. having the entire sample and hypothesis matrices present in memory)
julia -Lsca.jl main-noninc.jl destraces/tdes2_enc_9084b0087a1a1270587c146ccc60a252.trs && \
# Example run of main function that performs vanilla correlation statistics on conditionally averaged output
julia -p3 -Lsca.jl main-condavg.jl aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs && \
# Example run of main function that performs vanilla correlation statistics on bitwise sample reduced output
julia -p3 -Lsca.jl main-condred.jl destraces/des_enc_1c764a2af6e0322e.trs && \
# Example run of main function that performs vanilla correlation statistics on bitwise sample reduced output using Klemsa's leakage models for WB AESes, hardcoded for AES128 FORWARD input
julia -p3 -Lsca.jl main-condred-wbaes.jl aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs && \
# Example run of main function that performs incremental correlation statistics on an input trace set
julia -p3 -Lsca.jl main-inccpa.jl aestraces/aes128_mc_invciph_da6339e783ee690017b8604aaeed3a6d.trs
```



# Running from Inspector

First of all, you're currently missing out on the parallelization when you're running Jlsca from Inspector. This is because from Inspector to Jlsca the trace set data and samples are transported over a pipe, since I thought it was cool to be able to run Jlsca in an Inspector chain. The implementation of parallelization in Jlsca now assumes seekable files for each process, so the pipe is no more an option. I have not come around to fix the Inspector module to safely pass the temp file data to Inspector. This is TBD.

In addition to the installation steps for Jlsca described before, you also need to:

3. Copy `inspector/Jlsca4InspectorModule.java` to `$HOME/Inspector/modules/jlsca` (or the Windows equivalent).

4. Edit `Jlsca4InspectorModule.java` and change `JLSCA_PATH` to point to wherever you installed Jlsca.

Start Inspector and open the module source `Jlsca4InspectorModule.java`. Hit compile, and run on a trace set. This will open a dialog. The dialog is intended to be always consistent: i.e. you should only be able to run it in a way that "makes sense". You can still crash everything if you enter wrong offsets. Offset in the dialog are 0-based, as you Java guys would be used to.

Design wise, `Jlsca4InspectorModule.java` consists of 2 classes, a module class that extends Inspector's `Module` class and a panel class that extends `JPanel` and implements the module GUI. The GUI code is horrible, and I'm quite proud of it. The panel classes exposes a `toJlscParameters()` method which is called by the module when you press the OK button. This function returns a String which is a Julia expression that constructs a parameters object which will be passed to Jlsca: it's printed in the "log" window. The module simply executes Julia with Jlsca, passes the parameters, and passes the trace sample and data to standard input of the slave Julia process. Whatever Jlsca prints on std error and std out is printed in the Inspector "log" and "out" console. No traces are returned.

If you run the module with a known key and a >0 update interval it will create a KKA file with the key ranking which you can plot in openoffice (Excel for Windows users).

If you attack inner rounds, you'll need to manually cut and paste "next phase input" data from Jlsca's output in Inspector's "out" window into the phase input field in the module's GUI. This is because the Inspector module only makes a single pass over the trace set, whereas to break the inner rounds you need to do another analysis pass.
