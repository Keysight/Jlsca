using Jlsca.Align
using Test
using Statistics

mutable struct CorrelationAlignNaive
  reference::Vector
  referenceOffset::Int
  maxShift::Int

  function CorrelationAlignNaive(reference, referenceOffset, maxShift)
    new(reference, referenceOffset, maxShift)
  end
end

import Jlsca.Align:correlationAlign
# naive O(n^2) implementation
function correlationAlign(samples::Vector, state::CorrelationAlignNaive)
  align::Int = 0
  maxCorr::Float64 = 0

  reference::Vector = state.reference
  referenceOffset::Int = state.referenceOffset
  maxShift::Int = state.maxShift

  window = max(1, referenceOffset - maxShift):(min(referenceOffset + maxShift + length(reference), length(samples)) - length(reference) + 1)

  @inbounds for o in window
    e = o + length(reference) - 1
    corr = cor(samples[o:e], reference)
    if corr > maxCorr
      maxCorr = corr
      align = o
    end
  end

  ret = (referenceOffset-align,maxCorr)
  return ret
end

function test1()
    cols = 50
    rows = 100
    data = rand(Float64, cols)
    dataM = Array{Float64}(undef,rows,cols)
    window = 10:20
    reference = data[window]
    maxShift = 10
    shifts = Vector{Int}(undef,rows)

    fftwalignstate = CorrelationAlignFFT(reference, window[1], maxShift)
    naivealignstate = CorrelationAlignNaive(reference, window[1], maxShift)

    for i in 1:rows
        shifts[i] = rand(1:maxShift)
        dataM[i,:] = circshift(data, shifts[i])
    end

    for i in 1:rows
        (shift,corval) = correlationAlign(dataM[i,:], fftwalignstate)
        @test shift == -shifts[i]
        @test corval ≈ 1
    end

    for i in 1:rows
        (shift,corval) = correlationAlign(dataM[i,:], naivealignstate)
        @test shift == -shifts[i]
        @test corval ≈ 1
    end

end

function speedtest1()
    cols = 5000
    rows = 20000
    data = rand(Float64, cols)
    window = 10:20
    reference = data[window]
    maxShift = 5000
    shifts = Vector{Int}(undef,rows)

    fftwalignstate = CorrelationAlignFFT(reference, window[1], maxShift)

    for i in 1:rows
        correlationAlign(rand(Float64, cols), fftwalignstate)
    end

    return fftwalignstate
end

test1()
# @time speedtest1()
# @profile speedtest1()
# Profile.print(maxdepth=12,combine=true)
