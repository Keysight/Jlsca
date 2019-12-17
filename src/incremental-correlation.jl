# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

# TODO: move incremental-statistics.jl into its own module
include("incremental-statistics.jl")

import ..Trs.add,..Trs.getGlobCounter,..Trs.init,..Trs.merge
export IncrementalCorrelation

mutable struct IncrementalCorrelation <: PostProcessor
  counter::Int
  meanXinitialized::Bool
  covXY::IncrementalCovarianceTiled
  targetOffsets::Vector{Int}
  leakages::Vector{Leakage}
  targets::Vector{Target}
  hypocache
  targetcache
  guesses

  function IncrementalCorrelation()
    return new(0, false)
  end
end

show(io::IO, a::IncrementalCorrelation) = print(io, "Incremental correlation")

createTargetCache(t::Target{In,Out,Guess}) where {In,Out,Guess} = Vector{Out}(undef,length(guesses(t)))

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
  c.hypocache = Vector{UInt8}(undef,length(guesses(targets[1])) * length(leakages) * length(targetOffsets))
  c.targetcache = createTargetCache(targets[1])
  c.guesses = guesses(targets[1])
end

function reset(c::IncrementalCorrelation)
  c.meanXinitialized = false
  c.counter = 0
end

function helpert(lt::Leakage, hypoidx::Int, outputs::Vector{Out},hypo::Vector{UInt8}, offset::Int) where {Out}
    nrOfKbVals = length(outputs)
    @inbounds for o in 1:nrOfKbVals
      hypo[offset+hypoidx+o] = leak(lt, outputs[o])
    end
end

function toLeakages!(c::IncrementalCorrelation, t::Target{In,Out,Guess}, input::In, hypo::Vector{UInt8}, offset::Int) where {In,Out,Guess}
  kbvals = c.guesses::Vector{Guess}
  nrOfKbVals = length(kbvals)
  nrOfFuns = length(c.leakages)
  outputs = c.targetcache::Vector{Out}
  hypo = c.hypocache::Vector{UInt8}

  @inbounds for o in 1:nrOfKbVals
    outputs[o] = target(t, input, kbvals[o])
  end

  @inbounds for l in 1:nrOfFuns
    lt = c.leakages[l]
    hypoidx = (l-1)*nrOfKbVals
    helpert(lt,hypoidx,outputs,hypo,offset)
  end

  return offset + nrOfFuns*nrOfKbVals
end

function add(c::IncrementalCorrelation, samples::AbstractVector{S}, data::AbstractVector{D}, traceIdx::Int) where {S,D}
  hypo = c.hypocache
  if !c.meanXinitialized
      c.covXY = IncrementalCovarianceTiled(length(samples), length(hypo))
      c.meanXinitialized = true
  end

  offset = 0

  for idx in 1:length(c.targetOffsets)
    offset = toLeakages!(c, c.targets[c.targetOffsets[idx]], data[idx], hypo, offset)
  end

  add!(c.covXY, samples, hypo)

  c.counter += 1
end

# function add(c::IncrementalCorrelation, trs::Traces, traceIdx::Int)
#   data = getData(trs, traceIdx)
#   if length(data) == 0
#     return
#   end

#   samples = getSamples(trs, traceIdx)
#   if length(samples) == 0
#     return
#   end

#   add(c,samples,data,traceIdx)

# end

function merge(this::IncrementalCorrelation, other::IncrementalCorrelation)
  this.counter += other.counter
  add!(this.covXY, other.covXY)
end


function get(c::IncrementalCorrelation)
  C = getCorr(c.covXY)

  return C
end

function getGlobCounter(c::IncrementalCorrelation)
  return c.counter
end


mutable struct IncrementalCPA <: IncrementalAnalysis
  leakages::Vector{Leakage}
  postProcessor::Type{IncrementalCorrelation}

  function IncrementalCPA()
    return new([HW()],IncrementalCorrelation)
  end
end

show(io::IO, a::IncrementalCPA) = print(io, "Incremental CPA")

function printParameters(a::IncrementalCPA)
  @printf("leakages:     %s\n", a.leakages)
end

numberOfLeakages(a::IncrementalCPA) = length(a.leakages)

maximization(a::IncrementalCPA) = AbsoluteGlobalMaximization()
