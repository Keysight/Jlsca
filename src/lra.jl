# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse, Ilya Kizhvatov

export LRA
"""
    LRA([basisModel])

[Non-profiled linear regression](https://eprint.iacr.org/2013/794.pdf).

Default basisModel function is `basisModelSingleBits`.
"""
type LRA <: NonIncrementalAnalysis
  basisModel::Function

  function LRA()
    return new(basisModelSingleBits)
  end
end

show(io::IO, a::LRA) = print(io, "LRA")

function computeScores(a::LRA, data::AbstractArray{In}, samples::AbstractArray, target::Target{In,Out,Guess}, kbvals::Vector{Guess}) where {In,Out,Guess}
   C = lra(data, samples, target, a.basisModel, kbvals)
  return C
end

function printParameters(a::LRA)
  @printf("basismodel:   %s\n", a.basisModel)
end

# LRA for a single data column
function lra(data::AbstractArray{In}, samples::AbstractArray, t::Target{In,Out,Guess}, basisFunction::Function, keyChunkValues::Vector{Guess}) where {In,Out,Guess}
    (rs, cs) = size(samples)

    SStot = sum((samples .- mean(samples, 1)) .^ 2, 1)'
    SSreg = zeros(Float64, (cs,length(keyChunkValues)))

    for k in keyChunkValues
        M = mapreduce(basisFunction, hcat, target.(t, data, k))'

        E = (M * inv(M' * M) * M' * samples - samples) .^ 2

        SSreg[:,k+1] = mapslices(sum, E, 1)
    end

    R2 = 1 .- SSreg ./ SStot

    return R2
end

# some models for LRA
export basisModelSingleBits
"""
   basisModelSingleBits(input[, bitWidth])

Returns a bits model for given input. Default bitWidth is 8. 
"""
function basisModelSingleBits(x::Integer, bitWidth=8)
  g = zeros(Float64, bitWidth+1)
  for i in 1:bitWidth
      g[i] = (x >> (i-1)) & 1
  end
  g[length(g)] = 1

  return g
end

# TODO: understand why bitWidth=32 results in non-invertable matrices.
# function basisModelSingleBits(x::UInt32, bits=collect(1:31))
#   g = zeros(Float64, length(bits)+1)
#   for i in bits
#       g[i] = (x >> (i-1)) & 1
#   end
#   g[length(g)] = 1

#   return g
# end
