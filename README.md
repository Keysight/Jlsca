# What is it?

Jlsca is a toolbox in Julia to do side channel attacks. It supports:

* Conditional averaging
* Correlation power analysis (CPA) and Linear regression analysis (LRA)
* AES128/192/256 enc/dec, backward/forward S-box attacks
* AES128 enc/dec chosen input MixColumn attack
* DES/TDES1/TDES2/TDES3 enc/dec, backward/forward attack
* Known key analysis + key rank evolution CSV output
* Inspector trace set input
* Split sample and data raw binary (Daredevil) input

# Why would I want it?

It runs standalone or inside Riscure's Inspector as a module, so you would want this if:

* You don't have Inspector but you want to do DPA or understand how it works.

* You have Inspector but you want to play with features that are currently (4.10) not in Inspector, like:
	* [LRA](https://eprint.iacr.org/2013/794.pdf)
 	* [Conditional averaging](https://eprint.iacr.org/2013/794.pdf)

# Who wrote it?

It's written for fun by me (Cees-Bart Breunesse), and Ilya Kizhvatov contributed some python example code I shamelessly copied and adapted. It's not a Riscure product, and Riscure does not support or maintain this code. If it crashes or you have feature requests, Github allows you to contact the authors, or you do a pull request ;-)

# Installation

For Jlsca:

1. Install Julia (0.5.0 is tested) and make sure the `julia` executable is in your path (for Windows users).

2. Start a shell or cmd shell (Windows users), and install an additional required package ProgressMeter like this:
	`julia -e 'Pkg.add("ProgressMeter")'`

Then, if you want to run the Jlsca inspector module:

3. Copy `inspector/Jlsca4InspectorModule.java` to `$HOME/Inspector/modules/jlsca` (or the Windows equivalent).

4. Edit `Jlsca4InspectorModule.java` and change `JLSCA_PATH` to point to wherever you installed Jlsca.

# Running from Inspector

Start Inspector and open the module source `Jlsca4InspectorModule.java`. Hit compile, and run on a trace set. This will open a dialog. The dialog is intended to be always consistent: i.e. you should only be able to run it in a way that "makes sense". You can still crash everything if you enter wrong offsets. Offset in the dialog are 0-based, as you Java guys would be used to.

Design wise, `Jlsca4InspectorModule.java` consists of 2 classes, a module class that extends Inspector's `Module` class and a panel class that extends `JPanel` and implements the module GUI. The GUI code is horrible, and I'm quite proud of it. The panel classes exposes a `toJlscParameters()` method which is called by the module when you press the OK button. This function returns a String which is a Julia expression that constructs a parameters object which will be passed to Jlsca: it's printed in the "log" window. The module simply executes Julia with Jlsca, passes the parameters, and passes the trace sample and data to standard input of the slave Julia process. Whatever Jlsca prints on std error and std out is printed in the Inspector "log" and "out" console. No traces are returned.

If you run the module with a known key and a >0 update interval it will create a KKA file with the key ranking which you can plot in openoffice (Excel for Windows users).

If you attack inner rounds, you'll need to manually cut and paste "next phase input" data from Jlsca's output in Inspector's "out" window into the phase input field in the module's GUI. This is because the Inspector module only makes a single pass over the trace set, whereas to break the inner rounds you need to do another analysis pass.

# Running from cmd line

Function go() in sca.jl can be used to attack all the example traces in directories aestraces/ and destraces/ without having to change any code, for example:
```
julia -Lsca.jl -e"Sca.go()" aestraces/aes192_sb_eqinvciph_5460adcd34117f1d9a90352d3a37188f6e9724f0696898d2.trs
```
or for short:
```
./jlsca.sh aestraces/aes192_sb_eqinvciph_5460adcd34117f1d9a90352d3a37188f6e9724f0696898d2.trs
```

The attack parameters are extracted from the file name, and some hardcoded defaults are used (i.e. CPA, single bit0 or HW attack).

In short this is what happens when you run the above command:

`Sca.go()` sets up a "params" object with all the attack parameters, and then calls function `Sca.sca()` with that parameter object and a trace set. Function Sca.getParameters() called by Sca.go() looks at the filename of trace set and automatically configures a parameter object of the correct type and default parameter values if it can. The used parameters will be printed on the console. You can tweak and change most behavior by changing the parameters and not the underlying code. I recommend you copy go() to myahhack() and tweak it as described in the next section. There are some examples in sca.jl, see the Examples section.

# Attack parameters

There are three supported attacks: AesSboxAttack(), AesMCAttack() and DesSboxAttack(), defined in attackaes-core.jl and attackdes-core.jl. For example, the following creates a forward AES128 attack attack on all 8 bits of the intermediate state with CPA:

```
params = AesSboxAttack()
params.mode = CIPHER
params.keyLength = KL128
params.direction = FORWARD
params.analysis = CPA()
params.analysis.leakageFunctions = [x -> ((x .>> i) & 1) for i in 0:7 ]
```

If you'd like to attack with HW instead, write this:
```
params.analysis.leakageFunctions = [hw]
```
If you want HW + all bits, do this:
```
params.analysis.leakageFunctions = [hw, x -> ((x .>> i) & 1) for i in 0:7]
```
If you want to attack the HD between S-box in and out, set this:
```
params.xor = true
```
Since we're configuring a forward attack, we need to tell Jlsca what the offset of the input in the trace data is:
```
params.dataOffset = 1
```
This means that the input data is the start of the trace data: Julia offets are 1-based!! If you'd rather run the attack backward, and the trace data is located after the input, you'd type this:
```
params.direction = BACKWARD
params.dataOffset = 17
```
If we want to attack all key bytes, we write this:
```
params.keyByteOffsets = collect(1:16)
```
If we only want the first and last key bytes we write this:
```
params.keyByteOffsets = [1,16]
```
If you want LRA instead of CPA, do this:
```
params.analysis = LRA()
params.analysis.basisModel = basisModelSingleBits
```
Big fat disclaimer: currently LRA only supports only a 9 bit model, even if you do a AES MC attack! I need to understand some more about this attack, since choosing a 33 bit basis model results in non-invertible matrices (and a crash).

# Passing attack phase data

To attack inner rounds you need to use key material you recovered earlier. Jlsca does all this automagically by default. For example, AES192 consists of two separate attacks. If you want to attack AES192 you can tell Jlsca to do both phases sequentially without user interaction by setting the attack parameter:
```
params.phases = [PHASE1, PHASE2]
```
Jlsca will then run the two attacks, combine the results, and spits out the full key.

If you want to control the two phases explicitly (if you run the Jlsca module in Inspector, for example) you can do so too. Again, for AES192, you'd first run the attack with:
```
params.phases = [PHASE1]
```
which gives you the first round key, printed as a hex string labeled "next phase input" on the console. You cut and paste that information into the next phase like this:
```
params.phases = [PHASE2]
params.phaseInput = Nullable(hex2bytes("00112233445566778899aabbccddeeff")))
```

# Passing attack phase data from Inspector

If you run the Jlsca Inspector module, you'll have to paste this data (only the hex string) into a GUI text field yourself since I'm to lazy to parse the Jlsca output and feed it back into the module.

# Adding data and sample passes

You can easily added passes (i.e. functions) over sample or trace data. For example, suppose you have a trace set as follows:
```
trs = InspectorTrace("bla.trs")
```
and you want to run an attack over the absolute value of the samples you simple type this:
```
addSamplePass(trs, abs)
```
If you want to do a second order function by recombining samples with addition you type this:
```
function sndorder(samples)
	ln = length(samples)
	ret = zeros(Float32, div(ln*(ln-1),2))
	ctr = 1
	for k in 1:ln
		for l in (k+1):ln
			ret[ctr] = Float32(samples[k]) + Float32(samples[l])
			ctr += 1
		end
	end
	return ret
end
```

And then you add the newly defined function as a pass to the trs object:
```
addSamplePass(trs, sndorder)
```
The same applies to data; for example if you only want to use the first 16 bytes you'd type:
```
addDataPass(trs, x -> x[1:16])
```
Once you push a sample or data pass on the stack of passes, you can pop the last one you added by calling popSamplePass() or popDataPass().

# Conditional averaging and potential other post processors

Conditional averaging [1] is implemented as a trace post processor that is configured in the "trs" object as follows:
```
setPostProcessor(trs, CondAvg, getNumberOfAverages(params))
```
For AES, there are max 256 averages per key byte offset. For DES SBOX out there are 64, and for DES ROUNDOUT there are 1024. This is returned by getNumberOfAverages(). See type CondAvg in conditional-average.jl how the averager works: it uses Julia's newly added Threads module. By default only a single thread is used. If you set the JULIA_NUM_THREADS=2 environment variable it will use 2 threads, making it quite much faster if the input has many samples. Using more than 2 threads doesn't currently speed up the process (on my laptop at least), but I haven't profiled it.

The data passes that are configured with addDataPass determine the data on which conditional averaging operates: for AES this is simply the input or the output. For DES it is not since the input or output data gets bit picked from all over the place before it is recombined with a key, and therefore we cannot simply average on individual input bytes. See function round1 in attackdes-core.jl, for example, to see how data is preprocessed before being fed into the conditional averager.

# Examples

Function `wb()` in `sca.jl` implements the [leakage models](https://eprint.iacr.org/2013/794.pdf) to attack 	Dual AES implementations
Function `hammer()` in `sca.jl` can be used as a starting point for running many CPAs on many memory dumps extracted from whiteboxes.

# Test runs

If you hack shit and you want to verify stuff is still working, you can run all the files that end in "tests.jl". These files take no arguments and throw an exception if a test fails.

Specifically, you may want to run this to various attacks on all the example traces in the aestraces directory:
```
$ julia attackaes-tests.jl
```
Or this, to run various attacks on all the test traces in the destraces directory:
```
$ julia attackdes-tests.jl
```
This, if you're speeding up the AES implementation:
```
$ julia aes-tests.jl
```
Or this if you're optimizing bit vectors in DES:
```
$ julia des-tests.jl
```
