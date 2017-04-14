# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

# TODO: move incremental-statistics.jl into its own module
include("incremental-statistics.jl")

export IncrementalCorrelation,init

type IncrementalCorrelation <: PostProcessor
  worksplit::WorkSplit
  counter::Int
  covXY::Dict{Int,IncrementalCovariance}
  meanXinitialized::Bool
  meanX::IncrementalMeanVariance
  keyByteOffsets::Vector{Int}
  dataFunction::Function
  kbvals::Vector
  leakageFunctions::Vector{Function}

  function IncrementalCorrelation()
    IncrementalCorrelation(NoSplit())
  end

  function IncrementalCorrelation(w::WorkSplit)
    return new(w, 0, Dict{Int,IncrementalCovariance}(), false)
  end
end

function init(c::IncrementalCorrelation, keyByteOffsets::Vector{Int}, dataFunction::Function, kbvals::Vector, leakageFunctions::Vector{Function})
  c.keyByteOffsets = keyByteOffsets
  c.dataFunction = dataFunction
  c.kbvals = kbvals
  c.leakageFunctions = leakageFunctions
end

function reset(c::IncrementalCorrelation)
  c.covXY = Dict{Int,IncrementalCovariance}()
  c.meanXinitialized = false
end

function toLeakages!(c::IncrementalCorrelation, hypo, idx::Int, input::Integer)
  kbOffset = c.keyByteOffsets[idx]
  nrOfKbVals = length(c.kbvals)

  for (k,kb) in enumerate(c.kbvals)
    target = c.dataFunction([input], kbOffset, kb)[1]
    for (l,lfun) in enumerate(c.leakageFunctions)
      hypo[(l-1)*nrOfKbVals+k] = lfun(target)
    end
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

  hypo = zeros(UInt8, length(c.leakageFunctions) * length(c.kbvals))

  for idx in eachindex(data)
    val = data[idx]

    if !(toVal(c.worksplit, Int(idx), Int(val)) in c.worksplit.range)
      continue
    end

    hypo = toLeakages!(c, hypo, idx, val)

    if !haskey(c.covXY, idx)
      c.covXY[idx] = IncrementalCovariance(length(samples), length(hypo))
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
  hypo = zeros(UInt8, length(c.leakageFunctions) * length(c.kbvals))

  for idx in eachindex(data)
    val = data[idx]

    hypo = toLeakages!(c, hypo, idx, val)

    if !haskey(c.covXY, idx)
      c.covXY[idx] = IncrementalCovariance(c.meanX, IncrementalMeanVariance(length(hypo)))
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

  C = mapreduce(x -> getCorr(c.covXY[x]), hcat, sort(collect(keys(c.covXY))))

  return C
end

function getGlobCounter(c::IncrementalCorrelation)
  return c.counter
end
