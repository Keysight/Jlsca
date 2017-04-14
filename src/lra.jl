# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse, Ilya Kizhvatov

module Lra
export lra

# LRA for normal Matrix input
function lra(data::Matrix, samples::Matrix, keyByteOffsets::Vector{Int}, intermediateFunction::Function, basisFunction::Function, keyChunkValues=collect(UInt8, 0:255))
    (rs,cs) = size(samples)
    (rd,cd) = size(data)

    R2 = zeros(Float64, (cs, cd*length(keyChunkValues)))

    for i in 1:cd
        o = (i-1)*length(keyChunkValues)+1
        R2[:,o:o+length(keyChunkValues)-1] = lra(data[:,i], keyByteOffsets[i], samples, intermediateFunction, basisFunction, keyChunkValues)
    end

    return R2
end

# LRA for a single data column
function lra(data::Vector, dataColumn::Int, samples::Matrix, intermediateFunction::Function, basisFunction::Function, keyChunkValues=collect(UInt8, 0:255))
    (rs, cs) = size(samples)

    SStot = sum((samples .- mean(samples, 1)) .^ 2, 1)'
    SSreg = zeros(Float64, (cs,length(keyChunkValues)))

    for k in keyChunkValues
        M = mapreduce(basisFunction, hcat, intermediateFunction(data, dataColumn, k))'

        E = (M * inv(M' * M) * M' * samples - samples) .^ 2

        SSreg[:,k+1] = mapslices(sum, E, 1)
    end

    R2 = 1 .- SSreg ./ SStot

    return R2
end

end
