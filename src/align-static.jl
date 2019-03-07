# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using FFTW

FFTW.set_num_threads(Threads.nthreads())

export CorrelationAlignFFT
mutable struct CorrelationAlignFFT
  reversereference0mean::Vector{Float64}
  referenceOffset::Int
  maxShift::Int
  square_sum_x2::Float64
  plan1::Union{Missing,Ref}
  plan2::Union{Missing,Ref}
  initialized::Bool
  sums_y::Vector{Float64}
  sums_y2::Vector{Float64}
  scores::Vector{Float64}
  lengthsamples::Int
  window::UnitRange

  function CorrelationAlignFFT(reference::Vector, referenceOffset::Int, maxShift::Int)
    referenceOffset >= 0 || throw(ErrorException("no negative referenceOffset"))
    maxShift >= 0 || throw(ErrorException("no negative maxShift"))
    reference0mean = reference .- mean(reference)
    reversereference0mean = reverse(reference0mean)
    square_sum_x2 = sqrt(sum(reference0mean .^ 2))

    new(reversereference0mean, referenceOffset, maxShift, square_sum_x2, missing, missing, false)
  end

end

function myconv(u::AbstractVector{T}, v::AbstractVector{T}, state::CorrelationAlignFFT) where T
    nu = length(u)
    nv = length(v)
    n = nu + nv - 1
    np2 = n > 1024 ? nextprod([2,3,5], n) : nextpow(2,n)
    upad = [u; zeros(T, np2 - nu)]
    vpad = [v; zeros(T, np2 - nv)]
    if T <: Real
      if ismissing(state.plan1)
        state.plan1 = Ref(plan_rfft(upad))
      end

      upad_f = state.plan1[] * upad
      vpad_f = state.plan1[] * vpad
      dotp = upad_f .* vpad_f

      if ismissing(state.plan2)
        state.plan2 = Ref(plan_irfft(dotp, np2))
      end
      y = state.plan2[] * dotp
    else
        throw(ErrorException("don't"))
    end
    return y[1:n]
end


function pearson(cv::Vector{Float64},sums_y::Vector{Float64},sums_y2::Vector{Float64},square_sum_x2::Float64,window::UnitRange,n::Int,scores::Vector{Float64})
    # compute pearson's correlation
  @inbounds for i in 1:(length(window)-n+1)
    sum_x_y = cv[n+i-1]
    sum_y2 = sums_y2[i+n] - sums_y2[i]
    sum_y = sums_y[i+n] - sums_y[i]
    argh = sum_y2 - (sum_y ^ 2)/n
    r::Float64 = 0
    if argh > 0
      r = sum_x_y / (square_sum_x2 * sqrt(argh))
    end

    scores[i] = r
  end
end

# http://scribblethink.org/Work/nvisionInterface/nip.html (thx Jasper van Woudenberg)
function fastnormalizedcrosscorrelation(samples, state::CorrelationAlignFFT)
  align::Int = 0
  maxCorr::Float64 = 0

  reversereference0mean = state.reversereference0mean
  n = length(reversereference0mean)
  referenceOffset = state.referenceOffset
  maxShift = state.maxShift
  square_sum_x2 = state.square_sum_x2
  plan1 = state.plan1
  plan2 = state.plan2
  window = max(1, referenceOffset - maxShift):(min(referenceOffset + maxShift + n, length(samples)))

  if !state.initialized
    state.sums_y = zeros(Float64, length(window)+1)
    state.sums_y2 = zeros(Float64, length(window)+1)
    state.scores = zeros(Float64, length(window)+1)
    state.lengthsamples = length(samples)
    state.window = window
  end

  state.lengthsamples == length(samples) || error("Need $(state.lengthsamples) samples, not $(length(samples))")

  # these are just caches, i.e. not persisted between calls of this function
  sums_y = state.sums_y
  sums_y2 = state.sums_y2
  scores = state.scores

  # compute convolution (sums of squares between ref and samples)
  cv::Vector{Float64} = myconv(reversereference0mean, @view(samples[window]), state)
  # cv::Vector{Float64} = conv(reversereference0mean, @view(samples[window]))

  # pre-compute the sums and sums of squares of samples
  idx = 2
  @inbounds for i in window
    s::Float64 = samples[i]
    sums_y[idx] = sums_y[idx-1] + s
    sums_y2[idx] = sums_y2[idx-1] + (s ^ 2)
    idx += 1
  end

  # compute pearson's correlation
  pearson(cv,sums_y,sums_y2,square_sum_x2,window,n,scores)

  nothing
end

export correlationAlign

function correlationAlign(samples::Vector{Float32}, state::CorrelationAlignFFT)
  correlationAlign(map(Float64, samples), state)
end

function correlationAlign(samples::Vector{Float64}, state::CorrelationAlignFFT)
  fastnormalizedcrosscorrelation(samples, state)

  (val,idx) = findmax(state.scores) 

  ret = (state.referenceOffset-state.window[idx],val)

  return ret
end

export AlignPass

import ..Trs.Pass
import ..Trs.pass

"""
Performs alignment by computing the convolution of a reference with each
trace, and circshifts the trace so that the highest correlation peaks line up
in time. You can set a minimum correlation value and a maximum shift distance.

# Example

```
offset = 700
len = 600
maxshift = 2000
mincor = 0.7

ref = getSamples(trs,1)[offset:offset+len-1]
ca = CorrelationAlignFFT(ref,200,maxshift)
align = AlignPass(ca,length(trs),mincor)

addSamplePass(trs, align)
```

"""
mutable struct AlignPass <: Pass 
  c::CorrelationAlignFFT
  shifts::Vector{Tuple{Int,Float64}}
  hasval::BitVector
  lowerBound::Float64

  function AlignPass(c::CorrelationAlignFFT, nrTraces::Int, lowerBound::Float64)
    new(c, Vector{Tuple{Int,Float64}}(undef,nrTraces), falses(nrTraces), lowerBound)
  end
end

outtype(a::AlignPass, intype::AbstractVector) = intype
outlength(a::AlignPass, inlen::Int, intype::AbstractVector) = inlen

function pass(a::AlignPass, x::Vector, idx::Int)
  if !a.hasval[idx]
    a.shifts[idx] = correlationAlign(convert(Vector{Float64}, x), a.c)
    a.hasval[idx] = true
  end
  (shift, corrval) = a.shifts[idx]
  if corrval > a.lowerBound
    return circshift(x, shift)
  else
    return Vector{eltype(x)}(undef,0)
  end
end
