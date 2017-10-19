# What is it?

Jlsca is a toolbox in Julia to do the computational part (DPA) of a side channel attack. It supports:

* Conditional averaging, for analog measurements
* Conditional bitwise sample reduction, for whiteboxes
* Threaded and tiled incremental correlation statistics
* Parallelization of all the above (multi-core / multi-machine)
* Correlation power analysis (CPA)
* non-profiled Linear regression analysis (LRA)
* Mutual Information Analysis (MIA)
* AES128/192/256 enc/dec, backward/forward S-box attacks
* AES128 enc/dec chosen input MixColumn attack
* Some whitebox models for AES (INV MUL / Klemsa)
* DES/TDES1/TDES2/TDES3 enc/dec, backward/forward attack
* SHA1 backward/forward attack (for HMAC)
* Known key analysis + key rank evolution CSV output
* Inspector trace set input and output
* Split sample and data raw binary (Daredevil) input and output

Then, not really that related to this toolbox, but I've been playing with a Picoscope, and there is an example in `examples/piposcope.jl` that does (a quite fast, if I may say so myself) acquisition on Riscure's Pinata board using the scope's rapid block mode. Check the file header of `piposcope.jl` for more information. 

# Why would I want it?

It runs standalone or inside Riscure's Inspector as a module, so you would want this if:

* You don't have Inspector but you want to do DPA or understand how it works.

* You have Inspector but you want to play with features that are currently (4.10) not in Inspector, like:
	* [non-profiled LRA](https://eprint.iacr.org/2013/794.pdf)
 	* [Conditional averaging](https://eprint.iacr.org/2013/794.pdf)
	* Conditional sample reduction for attacking whiteboxes (see conditional-bitwisereduction.jl for what that means)
	* Superduper fast parallization of conditional averaging, conditional bitwise sample reduction, and [incremental correlation statistics](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.214.8508&rep=rep1&type=pdf)!
	* [Mutual Information Analysis](https://eprint.iacr.org/2007/198.pdf) (MIA)

# Who wrote it?

It's written for fun by me (Cees-Bart Breunesse) and Ilya Kizhvatov (whose [pysca](https://github.com/ikizhvatov/pysca) I shamelessly used as a baseline). Ruben Muijrers contributed the bit compression for whiteboxes used in conditional bitwise sample reduction. This toolbox is not a Riscure product, and Riscure does not support or maintain this code. If it crashes or you have feature requests, Github allows you to contact the authors, or you do a pull request ;-) It's the first code I ever wrote in Julia so if you have comments about how to make it faster or less of a hack (try the parallelization code), by all means contact me.

# Installation

1. Install Julia (0.6.0 is tested, everything prior is *no longer compatible*) and make sure the `julia` executable is in your path (notably for Windows users). Start he Julia REPL by executing `julia`.

2. In the REPL type `Pkg.clone("https://github.com/Riscure/Jlsca")`

You can now close the Julia prompt. 

# Running 

There are several ways to interact with Jlsca. You can run scripts from command line, interactive through Julia's REPL or via Jupyter notebooks. The first two are described in the this README. The elegant and powerful Jupyter approach is described [here](https://github.com/ikizhvatov/jlsca-tutorials), and includes a solution for Riscure's [RHME2](https://github.com/Riscure/Rhme-2016) SCA challenges from 2016.  

# Multi-threading versus multi-processing

Various components (conditional averaging, conditional sample reduction, incremental correlation) in Jlsca can be split and run in *parallel* in different worker processes. Only one component in Jlsca in currently *threaded*, and that is the incremental correlation statistics. On a single CPU with multiple cores, running incremental correlation with multiple threads in a single process will probably outperform splitting the work over multiple processes that use a single thread. The reason for this is that parallel processes on a single CPU will thrash the cache. The threaded implementation of incremental correlation is tiled and cache friendly. Usually, choosing #workers == #CPUs and #threads  == #hardware cores in a single CPU is the preferred way, but of course your milage may vary. Julia by default uses a single worker, and a single thead (per worker). To change this run as `julia -p 2` to give Julia 2 workers (== 3 processes, 1 master process and 2 workers, on the same machine), and `JULIA_NUM_THREADS=2 julia` to give the Julia process 2 threads. It's a bit unfortunate that this interface is not unified ..  

I parallelized components in Jlsca because I wanted to run and split over multiple machines, but so far I haven't found the time to experiment with that. On my TODO list is to create a small cluster with 2+ nodes, each with a dual-Xeon CPU and a fast shared filesystem, since the input trace sets need to be accessible for each worker. A small, lean and simple implementation of a cluster would be Linux + NFS + SSH on each node. Julia can then be deployed to these nodes using the `--machinefile` option, as described [here](https://docs.julialang.org/en/stable/manual/parallel-computing). This would be the easiest way to unleash Jlsca's parallel abilities. 

# Running from cmd line

Step 2 in the installation performed a git clone of Jlsca in your Julia's user directory. For me, it's in ~/.julia/v0.5/Jlsca. Jlsca is a library, but there are a few script files in Jlsca's `examples` directory. These scripts perform the various attacks and combination of settings supported by Jlsca. Some attack parameters, for example the "known key", are extracted from the file name, and some hard coded attack defaults are used (i.e. CPA, single bit0 or HW attack). You can change all this by editing the main files only: the library code under `src` need not be touched for that.

### File `main-noninc.jl`

This file performs vanilla correlation statistics on an input trace set. Vanilla meaning that it will compute correlation with the entire sample and hypothesis matrices present in memory. This is a good starting point for playing and implementing new statistics or attacks. This main does not do parallelization, so it will complain when you specify multiple processes (`-pX`) on the `julia` command line. For example:
```
julia examples/main-noninc.jl destraces/tdes2_enc_9084b0087a1a1270587c146ccc60a252.trs
```
Or if you want to do a backwards attack do this (applies to all the main-xxx.jl files)
```
julia examples/main-noninc.jl destraces/tdes2_enc_9084b0087a1a1270587c146ccc60a252.trs BACKWARD
```

### File `main-condavg.jl`

This file performs vanilla correlation statistics but will first run the conditional averager over the trace set input. This job can be parallelized to, for example, 2 processes by adding `-p 2` to the command line.
```
julia examples/main-condavg.jl aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs
```

### File `main-condred.jl`

This file perform vanilla correlation statistics over conditionally sample reduced trace sets. Check the source of `conditional-bitwisereduction.jl` if you want to know more; this is only useful for whiteboxes, since it works on bit vector sample data, not on floating points. This process can be parallelized.
```
julia examples/main-condred.jl destraces/des_enc_1c764a2af6e0322e.trs
```

### File `main-condred-wbaes.jl`

This file combines Klemsa's [leakage models](https://eprint.iacr.org/2013/794.pdf) for tackling Dual AES with the conditional bit wise reduction. Can be parallelized. In `main-condred-wbaes.jl` the attack params are hardcoded for AES128 trace sets, so you'll need to edit the main file if you want pass it something else, like AES192 or 256. If you want to apply this on your own whitebox data make sure the `params.dataOffset` in `main-condred-wbaes.jl` point to the input (if `params.direction == FORWARD`) or output (if `params.direction == BACKWARD`). Can parallelized, for example:
```
julia examples/main-condred-wbaes.jl aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs
```

### File `main-inccpa.jl`

Last but not least, this file will perform a correlation attack using incremental correlation statistics. This is what Inspector also implements in its "first order" attack modules. You can parallelize or multi-thread this attack. For example:
```
JULIA_NUM_THREADS=2 julia examples/main-inccpa.jl aestraces/aes128_mc_invciph_da6339e783ee690017b8604aaeed3a6d.trs
```

# Running in the REPL

```julia
julia> using Jlsca.Trs

julia> trs=InspectorTrace("aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs")
Opened aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs, #traces 500, #samples 1920 (UInt8), #data 32
Jlsca.Trs.InspectorTrace(0x00,Nullable{Int64}(500),0x0020,1,UInt8,0x00000780,24,IOStream(<file aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs>),Any[],Any[],Union,Union,0,"aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs",24,false,18)

julia> #convert the data bytes to its hamming weight on the fly

julia> addDataPass(trs, x -> Jlsca.Sca.hw.(x))
1-element Array{Any,1}:
 Jlsca.Sca.hw

julia> # reading all samples and data-converted-to-HW into memory

julia> ((data,samples),eof) = readTraces(trs, 1:length(trs))
((
UInt8[0x06 0x06 … 0x02 0x04; 0x04 0x03 … 0x03 0x04; … ; 0x05 0x06 … 0x02 0x08; 0x05 0x04 … 0x05 0x04],

UInt8[0x6f 0x6f … 0x02 0x04; 0xd4 0x2c … 0x03 0x04; … ; 0xad 0xf6 … 0x02 0x08; 0xbc 0xe4 … 0x05 0x04]),false)

julia> using PyPlot.plot

julia> # plotting correlation with byte wise hamming weight of input data

julia> plot(cor(samples, data[:,1:16]))

```
![Input correlation plot](https://raw.githubusercontent.com/Riscure/Jlsca/master/images/inputcorrelation.png)
```julia
julia> # and for the output

julia> plot(cor(samples, data[:,17:32]))

```
![Output correlation plot](https://raw.githubusercontent.com/Riscure/Jlsca/master/images/outputcorrelation.png)

```julia
julia> # Remove the HW data pass

julia> popDataPasss(trs)

julia> # Correlate with the cipher state at the start of round 5. We define a leak function first.

julia> round5leak(str,state,globstate) = (if str == "r5.start"; globstate[:] = state; end; return state;)
round5leak (generic function with 1 method)

julia> # expand the "known key" for this trace set

julia> expkey=KeyExpansion(hex2bytes("0fec9ca47fb2f2fd4df14dcb93aa4967"), 10, 4)

julia> # Then, we define a pass that returns the start of round 5 data for each trace

julia> mypass(data) = (leakstate = zeros(UInt8, 16)
       ; Cipher(data[1:16], expkey, (str,state) -> round5leak(str, state, leakstate)); return leakstate)
mypass (generic function with 1 method)

julia> addDataPass(trs,mypass)
1-element Array{Any,1}:
 mypass

julia> addDataPass(trs, x -> Jlsca.Sca.hw.(x))
2-element Array{Any,1}:
 mypass      
 Jlsca.Sca.hw

julia> ((data,samples),eof) = readTraces(trs, 1:length(trs))
Processing traces .. 100% Time: 0:00:01
((
UInt8[0x07 0x04 … 0x04 0x05; 0x03 0x05 … 0x04 0x05; … ; 0x02 0x02 … 0x05 0x06; 0x02 0x04 … 0x04 0x04],

UInt8[0x6f 0x6f … 0x02 0x04; 0xd4 0x2c … 0x03 0x04; … ; 0xad 0xf6 … 0x02 0x08; 0xbc 0xe4 … 0x05 0x04]),false)

julia> plot(cor(samples, data))
```
![Start of round 5 correlation plot](https://raw.githubusercontent.com/Riscure/Jlsca/master/images/r5startcorrelation.png)

# Running from Inspector

First of all, you're currently missing out on the parallelization when you're running Jlsca from Inspector. This is because from Inspector to Jlsca the trace set data and samples are transported over a pipe, since I thought it was cool to be able to run Jlsca in an Inspector chain. The implementation of parallelization in Jlsca now assumes seekable files for each process, so the pipe is no longer an option. I have not come around to fix the Inspector module to safely pass the temp file data to Inspector. This is TBD.

In addition to the installation steps for Jlsca described before, you also need to:

3. Copy `inspector/Jlsca4InspectorModule.java` to `$HOME/Inspector/modules/jlsca` (or the Windows equivalent).

Start Inspector and open the module source `Jlsca4InspectorModule.java`. Hit compile, and run on a trace set. This will open a dialog. The dialog is intended to be always consistent: i.e. you should only be able to run it in a way that "makes sense". You can still crash everything if you enter wrong offsets. Offset in the dialog are 0-based, as you Java guys would be used to.

Design wise, `Jlsca4InspectorModule.java` consists of 2 classes, a module class that extends Inspector's `Module` class and a panel class that extends `JPanel` and implements the module GUI. The GUI code is horrible, and I'm quite proud of it. The panel classes exposes a `toJlscParameters()` method which is called by the module when you press the OK button. This function returns a String which is a Julia expression that constructs a parameters object which will be passed to Jlsca: it's printed in the "log" window. The module simply executes Julia with Jlsca, passes the parameters, and passes the trace sample and data to standard input of the slave Julia process. Whatever Jlsca prints on std error and std out is printed in the Inspector "log" and "out" console. No correlation traces are returned (also TBD).

If you run the module with a known key and a >0 update interval it will create a KKA file with the key ranking which you can plot in openoffice (Excel for Windows users).

If you attack inner rounds, you'll need to manually cut and paste "next phase input" data from Jlsca's output in Inspector's "out" window into the phase input field in the module's GUI. This is because the Inspector module only makes a single pass over the trace set, whereas to break the inner rounds you need to do another analysis pass.

# Hacking stuff

By all means take a look at the `main-xxx.jl` files, pick one that matches what you want to do closest, copy and change accordingly. Below are some more details on how to set parameters, data and sample passes.

## Attack parameters

There are several supported attacks: AesSboxAttack(), AesMCAttack(), DesSboxAttack(), Sha1InputAttack, and Sha1OutputAttack defined in attackaes-core.jl, attackdes-core.jl and attacksha-core.jl. For example, the following creates a forward AES128 attack attack on all 8 bits of the intermediate state with vanilla CPA:

```julia
# first define an attack
attack = AesSboxAttack()
attack.mode = CIPHER
attack.keyLength = KL128
attack.direction = FORWARD
# then an analysis
analysis = CPA()
analysis.leakages = [Bit(i) for i in 0:7]
# combine the two in a DpaAttack. The attack field is now also accessible
# through params.attack, same for params.analysis.
params = DpaAttack(attack,analysis)

```
What's put in analysis.leakages is a list of objects with a type that inherits from `Leakage` and implements a `leak` function. Look in `sca-leakages.jl` on how to see HW and Bit type leakges are implemented. If you'd like to attack with HW instead, write this:
```julia
params.analysis.leakages = [HW()]
```
If you want to attack the HD between S-box in and out, set this (only for the DES/AES attacks):
```julia
params.attack.xor = true
```
Since we're configuring a forward attack, we need to tell Jlsca what the offset of the input in the trace data is:
```julia
params.dataOffset = 1
```
This means that the input data is the start of the trace data: Julia offsets are 1-based!! If you'd rather run the attack backwards, and the output data is located after the input, you'd type this:
```julia
params.attack.direction = BACKWARD
params.dataOffset = 17
```
If we want to attack all key bytes, we write this:
```julia
params.targetOffsets = collect(1:16)
```
If we only want the first and last key bytes we write this:
```julia
params.targetOffsets = [1,16]
```
If we want LRA instead of CPA, we do this:
```julia
params.analysis = LRA()
params.analysis.basisModel = basisModelSingleBits
```
Big fat disclaimer: currently LRA only supports only a 9 bit model, even if you do a AES MC attack! I need to understand some more about this attack, since choosing a 33 bit basis model results in non-invertible matrices (and a crash). If we want MIA instead of LRA, we do this:
```julia
params.analysis = MIA()
params.analysis.sampleBuckets = 9
params.analysis.leakages = [HW()]

```
The `sampleBuckets` value is the number of buckets in which samples (observations) will be split, but only if the sample type is a real number. If your samples aren't floats, you should add a sample pass like this `addSamplePass(trs, float)`. Like LRA, MIA is a bit hacky, and subject to change ;-)

## Passing attack phase data

To attack inner rounds you need to use key material you recovered earlier. Jlsca does all this automagically by default. For example, AES192 consists of two separate attacks. If you only want to attack the first round of AES192 you can tell Jlsca by setting the attack parameter:
```julia
params.phases = [1]
```
which gives you the first round key, printed as a hex string labeled "next phase input" on the console. You cut and paste that information into the next phase like this, or if you ran phase 1 before this data will already be present in `params.phaseInput`:
```julia
params.phases = [PHASE2]
params.phaseInput = hex2bytes("00112233445566778899aabbccddeeff"))
```

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
setPostProcessor(trs, CondAvgXXXX, getNumberOfAverages(params))
```
For AES, there are max 256 averages per key byte offset. For DES SBOX out there are 64, and for DES ROUNDOUT there are 1024. This is returned by getNumberOfAverages(). See type CondAvg in conditional-average.jl how the averager works: it uses Julia's newly added Threads module. By default only a single thread is used. If you set the JULIA_NUM_THREADS=2 environment variable it will use 2 threads, making it quite much faster if the input has many samples. Using more than 2 threads doesn't currently speed up the process (on my laptop at least), but I haven't profiled it.

The data passes that are configured with addDataPass determine the data on which conditional averaging operates: for AES this is simply the input or the output. For DES it is not since the input or output data gets bit picked from all over the place before it is recombined with a key, and therefore we cannot simply average on individual input bytes. See function round1 in attackdes-core.jl, for example, to see how data is preprocessed before being fed into the conditional averager.

## Parallelization

What's currently parallelized are all the post processors:
* Conditional bitwise sample reduction
* Conditional averaging
* Incremental correlation statistics

All the provided main-xxx.jl files can be run with -pX to run on X processors (local or not, as long as the trace set input is available for all processes). 

There are currently 2 different ways to parallelize each post processor:
* SplitByTracesBlock: This means that each process will visit a subset of traces, but do all the work required for that trace. For conditional averaging this means that each process needs M memory but less trace data needs to be moved around and interpreted. Traces are split in blocks, i.e. the first N go to process 1, the second N to process 2 etc.
* SplitByTracesSliced: Same as SplitByTracesBLock, but process 1 takes trace 1, process 2 takes trace 2, etc.

Since parallelization is tightly coupled to post processors, you need to pass the SplitXXX instance to the post processor instance, see main-xxx.jl.

## Test runs

Since Jlsca is a Julia package, it runs all tests from `test/runtests.jl`. Either trigger this by:

1. ```Pkg.test("Jlsca")``` in the Julia REPL

2. `julia ../test/runtests.jl` from Jlsca's source directory (typically in `~/.julia/v0.5/Jlsca/src`)
