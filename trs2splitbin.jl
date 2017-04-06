#!/usr/bin/env julia -Lsca.jl

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

    trs = InspectorTrace(filename)

    (data,samples) = trs[1]
    numOriginalDataBytes = length(data)
    numOriginalSamples = length(samples)
    numOriginalTraces = length(trs)
    sampleType = eltype(samples)

    if bitsToBytes
        # add samples pass that converts samples to bit array
        addSamplePass(trs, tobits)
        numOriginalSamples = numOriginalSamples * 8
        sampleType = UInt8
    end

    # assert a careless user
    if (dataOffset + dataBytes - 1 > numOriginalDataBytes)
        @printf("Requested data range is out of bounds! \n")
        exit()
    end

    guessesfn = @sprintf("data_UInt8_%dt.bin", numOriginalTraces)
    samplesfn = @sprintf("samples_%s_%dt.bin", sampleType, numOriginalTraces)

    bin = SplitBinary(guessesfn, dataBytes, samplesfn, numOriginalSamples, sampleType, numOriginalTraces, true)

    for i in 1:length(trs)
        s = trs[i][2]

        if bitsToBytes
            # convert bit array to bytes
            s = UInt8.(s)
        end

        bin[i] = (trs[i][1][dataOffset:dataOffset+dataBytes-1], s)
    end


    @printf("Daredevil config:\n")
    @printf("guess=%s %d %d\n", guessesfn, length(trs), dataBytes)
    @printf("trace=%s %d %d\n", samplesfn, length(trs), numOriginalSamples)

    close(trs)
    close(bin)
end

trs2splitbin(ARGS[1], 1, 16)
