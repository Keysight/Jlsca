# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

# TODO: move incremental-statistics.jl into its own module
include("incremental-statistics.jl")

import ..Trs.add,..Trs.getGlobCounter
export IncrementalCorrelation

type IncrementalCPA <: IncrementalAnalysis
  leakages::Vector{Leakage}

  function IncrementalCPA()
    return new([HW()])
  end
end

show(io::IO, a::IncrementalCPA) = print(io, "Incremental CPA")

function printParameters(a::IncrementalCPA)
  @printf("leakages:     %s\n", a.leakages)
end

numberOfLeakages(a::IncrementalCPA) = length(a.leakages)

maximization(a::IncrementalCPA) = AbsoluteGlobalMaximization()

type IncrementalCorrelation <: PostProcessor
  worksplit::WorkSplit
  counter::Int
  covXY::Dict{Int,IncrementalCovarianceTiled}
  meanXinitialized::Bool
  meanX::IncrementalMeanVariance
  targetOffsets::Vector{Int}
  leakages::Vector{Leakage}
  targets::Vector{Target}
  hypocache
  targetcache
  guesses

  function IncrementalCorrelation()
    IncrementalCorrelation(NoSplit())
  end

  function IncrementalCorrelation(w::WorkSplit)
    return new(w, 0, Dict{Int,IncrementalCovarianceTiled}(), false)
  end
end

show(io::IO, a::IncrementalCorrelation) = print(io, "Incremental correlation")

createTargetCache(t::Target{In,Out,Guess}) where {In,Out,Guess} = Vector{Out}(length(guesses(t)))

function init(c::IncrementalCorrelation, targetOffsets::Vector{Int}, leakages::Vector{Leakage}, targets::Vector{Target})
  if c.meanXinitialized 
    # FIXME quietly ignore
    return
  end
  
  c.targetOffsets = targetOffsets
  c.leakages = leakages
  c.targets = targets
  #FIXME: broken for attacks with different target output types
  #FIXME: broken for leakages that don't fit in an byte
  c.hypocache = Vector{UInt8}(length(guesses(targets[1])) * length(leakages))
  c.targetcache = createTargetCache(targets[1])
  c.guesses = guesses(targets[1])
end

function reset(c::IncrementalCorrelation)
  c.covXY = Dict{Int,IncrementalCovarianceTiled}()
  c.meanXinitialized = false
  c.counter = 0
end

function helpert(lt::Leakage, hypoidx::Int, outputs::Vector{Out},hypo::Vector{UInt8}) where {Out}
    nrOfKbVals = length(outputs)
    @inbounds for o in 1:nrOfKbVals
      hypo[hypoidx+o] = leak(lt, outputs[o])
    end
end

function toLeakages!(c::IncrementalCorrelation, t::Target{In,Out,Guess}, input::In) where {In,Out,Guess}
  kbvals = c.guesses::Vector{Guess}
  nrOfKbVals = length(kbvals)
  nrOfFuns = length(c.leakages)
  nrOfTargets = length(input)
  outputs = c.targetcache::Vector{Out}
  hypo = c.hypocache::Vector{UInt8}

  @inbounds for o in 1:nrOfKbVals
    outputs[o] = target(t, input, kbvals[o])
  end

  @inbounds for l in 1:nrOfFuns
    lt = c.leakages[l]
    hypoidx = (l-1)*nrOfKbVals
    helpert(lt,hypoidx,outputs,hypo)
  end

  return hypo
end

function add(c::IncrementalCorrelation, samples::Vector{S}, data::Vector{D}, traceIdx::Int) where {S,D}
  if !c.meanXinitialized
    c.meanXinitialized = true
    c.meanX = IncrementalMeanVariance(length(samples))
    for idx in 1:length(c.targetOffsets)
      hypo = c.hypocache
      c.covXY[idx] = IncrementalCovarianceTiled(c.meanX, IncrementalMeanVariance(length(hypo)))
    end
  end

  samplesN::Vector{Float64} = samples .- c.meanX.mean

  for idx in 1:length(c.targetOffsets)
    val = data[idx]

    hypo = toLeakages!(c, c.targets[c.targetOffsets[idx]], val)

    add!(c.covXY[idx], samples, hypo, samplesN, false)
  end

  add!(c.meanX, samples)

  c.counter += 1
end

function add(c::IncrementalCorrelation, trs::Trace, traceIdx::Int)
  data = getData(trs, traceIdx)
  if length(data) == 0
    return
  end

  samples = getSamples(trs, traceIdx)
  if length(samples) == 0
    return
  end

  add(c,samples,data,traceIdx)

end

function merge(this::IncrementalCorrelation, other::IncrementalCorrelation)
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
        merge(c, other)
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
