# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

# TODO: move incremental-statistics.jl into its own module
include("incremental-statistics.jl")

import ..Trs.add,..Trs.getGlobCounter
import ..Trs.toVal
export IncrementalCorrelation,init,add,getGlobCounter

type IncrementalCorrelation <: PostProcessor
  worksplit::WorkSplit
  counter::Int
  covXY::Dict{Int,IncrementalCovarianceTiled}
  meanXinitialized::Bool
  meanX::IncrementalMeanVariance
  targetOffsets::Vector{Int}
  attack::Attack
  kbvals::Vector
  leakages::Vector{Leakage}
  targets::Vector{Target}

  function IncrementalCorrelation()
    IncrementalCorrelation(NoSplit())
  end

  function IncrementalCorrelation(w::WorkSplit)
    return new(w, 0, Dict{Int,IncrementalCovarianceTiled}(), false)
  end
end

function init(c::IncrementalCorrelation, attack::Attack, phase::Int, leakages::Vector{Leakage}, targetOffsets::Vector{Int})
  c.targetOffsets = targetOffsets
  c.attack = attack
  c.kbvals = guesses(attack)
  c.leakages = leakages
  c.targets = map(t -> getTarget(attack, phase, t), targetOffsets)
end

function reset(c::IncrementalCorrelation)
  c.covXY = Dict{Int,IncrementalCovarianceTiled}()
  c.meanXinitialized = false
  c.counter = 0
end

function toLeakages!(c::IncrementalCorrelation, hypo::Vector{UInt8}, idx::Int, input::Union{UInt8,UInt16})
  kbOffset = c.targetOffsets[idx]
  nrOfKbVals = length(c.kbvals)
  nrOfFuns = length(c.leakages)
  t = c.targets[kbOffset]

  outputs = target.(t, input, c.kbvals)

  @inbounds for l in 1:nrOfFuns
    hypoidx = (l-1)*nrOfKbVals+1
    hypo[hypoidx:(hypoidx+nrOfKbVals-1)] = leak.(c.leakages[l], outputs)
  end

  return hypo
end

function add(c::IncrementalCorrelation, trs::Trace, traceIdx::Int)
  add(c, c.worksplit, trs, traceIdx)
end

function add(c::IncrementalCorrelation, worksplit::SplitByData, trs::Trace, traceIdx::Int)
  data::AbstractVector = getData(trs, traceIdx)
  if length(data) == 0
    return
  end

  samples::Vector{trs.sampleType} = getSamples(trs, traceIdx)
  if length(samples) == 0
    return
  end

  hypo = zeros(UInt8, length(c.leakages) * length(c.kbvals))

  for idx in 1:length(c.targetOffsets)
    val = data[idx]

    if !(toVal(c.worksplit, Int(idx), Int(val)) in c.worksplit.range)
      continue
    end

    toLeakages!(c, hypo, idx, val)

    if !haskey(c.covXY, idx)
      c.covXY[idx] = IncrementalCovarianceTiled(length(samples), length(hypo))
    end

    add!(c.covXY[idx], samples, hypo)
  end

  c.counter += 1
end

function add(c::IncrementalCorrelation, worksplit::Union{NoSplit,SplitByTraces}, trs::Trace, traceIdx::Int)
  data::AbstractVector = getData(trs, traceIdx)
  if length(data) == 0
    return
  end

  samples::Vector{trs.sampleType} = getSamples(trs, traceIdx)
  if length(samples) == 0
    return
  end

  if !c.meanXinitialized
    c.meanX = IncrementalMeanVariance(length(samples))
    c.meanXinitialized = true
  end

  samplesN = samples .- c.meanX.mean

  for idx in 1:length(c.targetOffsets)
    val = data[idx]

    hypo = zeros(UInt8, length(c.leakages) * length(c.kbvals))
    toLeakages!(c, hypo, idx, val)

    if !haskey(c.covXY, idx)
      c.covXY[idx] = IncrementalCovarianceTiled(c.meanX, IncrementalMeanVariance(length(hypo)))
    end

    add!(c.covXY[idx], samples, hypo, samplesN, false)
  end

  add!(c.meanX, samples, samplesN)

  c.counter += 1
end


function merge(this::IncrementalCorrelation, worksplit::SplitByData, other::IncrementalCorrelation)
  for (idx,cov) in other.covXY
    if !haskey(this.covXY, idx)
      this.covXY[idx] = cov
    else
      add!(this.covXY[idx], other.covXY[idx])
    end
  end
end

function merge(this::IncrementalCorrelation, worksplit::Union{NoSplit,SplitByTraces}, other::IncrementalCorrelation)
  this.counter += other.counter
  for (idx,cov) in other.covXY
    if !haskey(this.covXY, idx)
      this.covXY[idx] = cov
    else
      add!(this.covXY[idx], other.covXY[idx], false)
    end
  end
  add!(this.covXY[1].meanVarX, other.covXY[1].meanVarX)
end


function get(c::IncrementalCorrelation)
  @assert myid() == 1
  if !isa(c.worksplit, NoSplit)
    for worker in workers()
      if worker == c.worksplit.worker
        continue
      else
        other = @fetchfrom worker Main.trs.postProcInstance
        merge(c, c.worksplit, other)
      end
    end
  end

  idxes = sort(collect(keys(c.covXY)))

  rows = c.covXY[1].numberOfX
  cols = sum(x -> c.covXY[x].numberOfY, idxes)
  C = Matrix{Float64}(rows, cols)

  ystart = 0
  yend = 0

  for i in idxes
    yend += c.covXY[i].numberOfY
    C[:,ystart+1:yend] = getCorr(c.covXY[i])
    ystart += c.covXY[i].numberOfY
  end

  # C = mapreduce(x -> getCorr(c.covXY[x]), hcat, sort(collect(keys(c.covXY))))
  return C
end

function getGlobCounter(c::IncrementalCorrelation)
  return c.counter
end
