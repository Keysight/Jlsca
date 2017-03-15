# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

include("trs.jl")

using Trs


# Convert Inspector trs file to Daredevil split binary format
# filename      - Inspector trs file name
# dataStartByte - first data byte to take (starting from 1)
# dataNumBytes  - number of data bytes to take
function ins2daredevil(filename, dataOffset, dataBytes)

    trs = InspectorTrace(filename)
    (data,samples) = trs[1]
    numOriginalDataBytes = length(data)
    numOriginalSamples = length(samples)
    numOriginalTraces = length(trs)

    # assert a careless user
    if (dataOffset + dataBytes - 1 > numOriginalDataBytes)
        @printf("Requested data range is out of bounds! \n")
        exit()
    end

    guessesfn = @sprintf("data_UInt8_%dt.bin", numOriginalTraces)
    samplesfn = @sprintf("samples_%s_%dt.bin", eltype(samples), numOriginalTraces)

    bin = SplitBinary(guessesfn, dataBytes, samplesfn, numOriginalSamples, eltype(samples), numOriginalTraces, true)

    for i in 1:length(trs)
        bin[i] = (trs[i][1][dataOffset:dataOffset+dataBytes-1], trs[i][2])
    end


    @printf("Daredevil config:\n")
    @printf("guess=%s %d %d\n", guessesfn, length(trs), dataBytes)
    @printf("trace=%s %d %d\n", samplesfn, length(trs), numOriginalSamples)

    close(trs)
    close(bin)
end

ins2daredevil(ARGS[1], 1, 16)
