#!/usr/bin/env julia -Lsca.jl

# Converter between Inspector trs and Daredevil split binary format, and vice versa.
#  Assumes that individual bytes in the spit bnary represents a bit; trs file can either store
#  bits as bytes, or have bits packed. See test() for examples of use.
#
# Tested so far only with UInt8 traces.
#
# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse, Ilya Kizhvatov

include("trs.jl")

using Trs

# Convert Inspector trs file to Daredevil split binary format
# filename      - Inspector trs file name
# dataStartByte - first data byte to take (starting from 1)
# dataNumBytes  - number of data bytes to take
# bitsToBytes   - represent individual bits from trs as bytes in split binary
function trs2splitbin(filename, dataOffset, dataBytes, bitsToBytes::Bool = true)

    # open the trs and extract relevant parameters
    trs = InspectorTrace(filename)
    (data,samples) = trs[1]
    numOriginalDataBytes = length(data)
    numOriginalSamples = length(samples)
    numOriginalTraces = length(trs)
    sampleType = eltype(samples)

    if bitsToBytes
        numOriginalSamples = numOriginalSamples * 8
        sampleType = UInt8
    end

    # assert a careless user
    if (dataOffset + dataBytes - 1 > numOriginalDataBytes)
        @printf("Requested data range is out of bounds! \n")
        exit()
    end

    # create and format split binary file names
    guessesfn = @sprintf("data_UInt8_%dt.bin", numOriginalTraces)
    samplesfn = @sprintf("samples_%s_%dt.bin", sampleType, numOriginalTraces)

    # open a split binary file pair for writing
    bin = SplitBinary(guessesfn, dataBytes, samplesfn, numOriginalSamples, sampleType, numOriginalTraces, true)

    # copy traces
    for i in 1:numOriginalTraces
        s = trs[i][2]
        if bitsToBytes
            # convert bit array to bytes
            # no matter what the original trs data type is, we interpret it as UInt64 and convet ot a sequence of bits
            foo = BitVector()
            foo.chunks = reinterpret(UInt64, s)
            foo.len = numOriginalSamples
            foo.dims = (0,)
            s = UInt8.(foo)
        end
        bin[i] = (trs[i][1][dataOffset:dataOffset+dataBytes-1], s)
    end

    # dump lines for the Daredevil config file (not the complete config file though) to the console
    @printf("Daredevil config:\n")
    @printf("guess=%s %d %d\n", guessesfn, length(trs), dataBytes)
    @printf("trace=%s %d %d\n", samplesfn, length(trs), numOriginalSamples)

    # graceful exit
    close(trs)
    close(bin)
end

# Convert Daredevil split binary format to Inspector trs. No error checking so far, call at your own risk.
#  Takes many paramters manually so far, not parsing the filenames because Daredevil itself stores
#  parameters in the config file and not in the filename
# dataFname               - file with data bytes
# dataSpace               - number of data bytes per trace
# sampelsFn               - file with samples
# numberOfSamplesPerTrace - number of samples per traces
# sampleType              - type of a trace sample (UInt8, UInt32 etc.)
# numTraces               - number of traces
# bytesToBits             - interpret split binary bytes as bits and store them packed in UInt8 in the trs
function splitbin2trs(dataFname, dataSpace, samplesFn, numberOfSamplesPerTrace, sampleType, numTraces, bytesToBits::Bool = true)

    bin = SplitBinary(dataFname, dataSpace, samplesFn, numberOfSamplesPerTrace, sampleType, numTraces)

    numberOfSamplesPerTraceTrs = numberOfSamplesPerTrace
    if bytesToBits
        # check if input samples are in appropirate format for bit packing
        if (sampleType != UInt8) && (numberOfSamplesPerTrace % 8 != 0)
          throw(ErrorException("For bytesToBits packing, sampleType needs to be UInt8 and numberOfSamplesPerTrace needs to be a multiple of 8\n"))
        end
        numberOfSamplesPerTraceTrs = div(numberOfSamplesPerTrace, 8)
    end

    trsfn = @sprintf("output_%s_%dt%s.trs", sampleType, numTraces, bytesToBits ? "" : "_bitsasbytes")
    trs = InspectorTrace(trsfn, dataSpace, sampleType, numberOfSamplesPerTraceTrs)

    for i in 1:numTraces
        s = bin[i][2]
        if bytesToBits
            trs[i] = (bin[i][1], reinterpret(UInt8, BitArray(s).chunks)[1:numberOfSamplesPerTraceTrs])
        else
            trs[i] = (bin[i][1], s)
        end
    end

    close(bin)
    close(trs)
end

# test back and forth
# TODO: add test with different data types!
function test(cleanup::Bool = true)

    ### 1. Without bit compression
    
    # take file storing bits compressed and create uncompressed splitbin
    trs2splitbin("testtraces/trs2splitbin_bitpacked.trs", 1, 32) 
    
    # re-create the compressed trs
    splitbin2trs("data_UInt8_17t.bin", 32, "samples_UInt8_17t.bin", 1024, UInt8, 17) 
    
    if readstring(`cmp testtraces/trs2splitbin_bitpacked.trs output_UInt8_17t.trs`) != ""
        @printf("Files not identical, fail!\n")
        exit()
    end

    ### 2. With bit compression
    
    run(`mv samples_UInt8_17t.bin samples_UInt8_17t_original.bin`)
    run(`mv data_UInt8_17t.bin data_UInt8_17t_original.bin`)
    
    # take the uncompressed splitbin and create an uncompressed trs
    splitbin2trs("data_UInt8_17t_original.bin", 32, "samples_UInt8_17t_original.bin", 1024, UInt8, 17, false)
    
    # take the uncompressed trs and create uncompressed splitbin
    trs2splitbin("output_UInt8_17t_bitsasbytes.trs", 1, 32, false)
    
    if readstring(`cmp samples_UInt8_17t.bin samples_UInt8_17t_original.bin`) != ""
        @printf("Files not identical, fail!\n")hexdump -
        exit()
    end

    ### 3. Check versus original Daredevil split binary and trs (confirms that endianness is the same)

    trs2splitbin("testtraces/trs2splitbin_bitsasbytes.trs", 1, 32, false)
    if readstring(`cmp samples_UInt8_13t.bin testtraces/trs2splitbin_bitsasbytes.trace`) != ""
        @printf("Files not identical, fail!\n")
        exit()
    end

    if cleanup
        run(`rm data_UInt8_17t.bin data_UInt8_17t_original.bin`)
        run(`rm samples_UInt8_17t.bin samples_UInt8_17t_original.bin`)
        run(`rm output_UInt8_17t.trs output_UInt8_17t_bitsasbytes.trs`)
        run(`rm data_UInt8_13t.bin samples_UInt8_13t.bin`)
    end
end

test()