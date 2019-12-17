# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse, Ilya Kizhvatov

mutable struct CPA <: NonIncrementalAnalysis
  leakages::Vector{Leakage}
  postProcessor::Union{Type{CondAvg},Type{CondReduce},Missing}

  function CPA()
    return new([HW()],CondAvg)
  end
end

show(io::IO, a::CPA) = print(io, "CPA")

numberOfLeakages(a::CPA) = length(a.leakages)

maximization(a::CPA) = AbsoluteGlobalMaximization()

function computeScores(a::CPA, data::AbstractArray{In}, samples::AbstractArray, target::Target{In,Out,Guess}, kbvals::Vector{Guess}) where {In,Out,Guess}
  (tr,tc) = size(samples)
  (dr,) = size(data)
  tr == dr || throw(DimensionMismatch())

  HL::Matrix{UInt8} = predict(data, target, kbvals, a.leakages)
  C = cor(samples, HL)
  
  return C
end

function printParameters(a::CPA)
  @printf("leakages:     %s\n", a.leakages)
end

function predict(data::AbstractArray{In,1}, t::Target{In,Out,Guess}, kcVals::Vector{Guess}, leakages::Vector{Leakage}) where {In,Out,Guess}
  (dr,) = size(data)
  nrKcVals = length(kcVals)
  nrLeakages = length(leakages)

  # temp storage for hypothetical intermediates for a single data column
  H = zeros(Out, dr, nrKcVals)

  # hypothetical leakages for all leakages for each intermediate for each data column.
  HL = zeros(UInt8, dr, nrKcVals*nrLeakages)

  j = 1
  # for a given data column, compute the hypothetical intermediate for each key hypothesis. Overwritten the next iteration.
  for i in kcVals
    for r in 1:dr
      H[r,i+1] = target(t, data[r,j], i)
    end
  end
  
  # for a given data column, compute all the leakages for all hypothetical intermediates for each key hypothesis and append to the large HL matrix
  for l in 1:nrLeakages
    hl_lower = (l-1)*nrKcVals + 1
    hl_upper = hl_lower + nrKcVals - 1
    for c in 1:nrKcVals
      for r in 1:dr
       HL[r,hl_lower+c-1] = leak(leakages[l], H[r,c])
      end
    end
  end

  return HL
end
