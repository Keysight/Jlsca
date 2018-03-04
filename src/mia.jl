# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse
#
# Implements Mutual Information Analysis, as described in https://eprint.iacr.org/2007/198.pdf
#
# TODO: the caller of mia will attack each key byte individually, causing the
# MiaColumnData for the samples to be recomputed each time. Should be improved
# although the bulk of the work is in the p(x,y) computation

export MIA
"""
    MIA([leakages,buckets])

Implements Mutual Information Analysis, as described in https://eprint.iacr.org/2007/198.pdf

Default leakages are `[HW()]` and the number of buckets is 9.
"""
type MIA <: NonIncrementalAnalysis
  leakages::Vector{Leakage}
  sampleBuckets::Int

  function MIA()
    return new([HW()], 9)
  end
end

show(io::IO, a::MIA) = print(io, "MIA")

function printParameters(a::MIA)
  @printf("leakages:     %s\n", a.leakages)
  @printf("buckets:      %d\n", a.sampleBuckets)
end

numberOfLeakages(a::MIA) = length(a.leakages)

function computeScores(a::MIA, data::AbstractArray{In}, samples::AbstractArray, target::Target{In,Out,Guess}, kbvals::Vector{Guess}) where {In,Out,Guess}
  (tr,tc) = size(samples)
  (dr,) = size(data)
  tr == dr || throw(DimensionMismatch())

  # DPA prediction
  HL::Matrix{UInt8} = predict(data, target, kbvals, a.leakages)
  C = mia(samples, HL, a.sampleBuckets)
  return C
end

type MiaColumnData{T}
  uniques::Set{T}
  where::Dict{T,IntSet}
  p::Dict{T, Float64}
  numobs::Int

  function MiaColumnData{T}(X::AbstractArray{T}) where T
    uniques = Set{T}()
    where = Dict{T,IntSet}()
    p = Dict{T, Float64}()
    numobs = length(X)

    for (idx,val) in enumerate(X)
      push!(uniques, val)
      if !(val in keys(where))
        where[val] = IntSet()
      end
      push!(where[val], idx)
    end

    for x in uniques
      wherex = where[x]
      px = length(wherex) / numobs
      p[x] = px
    end

    return new(uniques, where, p, numobs)
  end
end

function dump(c::MiaColumnData)
  # print(c.uniques)
  @printf("%s\n", c.where)
  # print(c.p)
  # print(c.numobs)
  @printf("entropy: %f\n", - sum(map(x-> x*log2(x), values(c.p))))
  @printf("sum(p): %f\n", sum(values(c.p)))
end

function mia(X::MiaColumnData, Y::MiaColumnData, normalized=false)
  X.numobs == Y.numobs || throw(DimensionMismatch())

  numobs = X.numobs

  mutual_info::Float64 = 0

  uniq_x = X.uniques
  uniq_y = Y.uniques

  for x in uniq_x
    wherex = X.where[x]
    px = X.p[x]
    for y in uniq_y
      wherey = Y.where[y]
      py = Y.p[y]
      pxy = length(intersect(wherex, wherey)) / numobs
      if pxy > 0
          mutual_info += pxy * log2(pxy / (px * py))
      end
    end
  end

  if normalized
    mutual_info = mutual_info / log2(numobs)
  end

  return mutual_info
end

function bucket(X::Vector{Float64}, nrXbuckets::Int)
  minX = minimum(X)
  maxX = maximum(X)

  if minX < 0
    maxX = maxX + abs(minX)
    delta = abs(minX)
    minX = 0
  else
    maxX = maxX - minX
    delta = -abs(minX)
    minX = 0    
  end

  stepX = maxX / nrXbuckets

  Xbucketed = zeros(Int, length(X))
  if stepX > 0
    for (idx,val) in enumerate(X)
      Xbucketed[idx] = min(Int(div(val+delta,stepX)), nrXbuckets - 1)
    end
  end
  return Xbucketed
end

function mia(O::AbstractArray, P::Matrix, nrOfObuckets=9)
  (ro,co) = size(O)
  (rp,cp) = size(P)

  C = zeros(Float64, co, cp)

  if eltype(O) <: AbstractFloat
    Ocolumndata = vec(mapslices(x -> MiaColumnData{Int}(bucket(x, nrOfObuckets)), O, 1))
  else
    Ocolumndata = vec(mapslices(MiaColumnData{eltype(O)}, O, 1))
  end

  # dump(Ocolumndata[1])

  # progress = Progress(co*cp,1)

  for p in 1:cp
    Pcolumndata = MiaColumnData{eltype(P)}(P[:,p])
    for o in 1:co
      C[o,p] = mia(Ocolumndata[o], Pcolumndata)
      # next!(progress)
    end
  end

  # finish!(progress)

  return C
end
