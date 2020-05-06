# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export WorkSplit
abstract type WorkSplit end

export SplitByTraces
abstract type SplitByTraces <: WorkSplit end

export SplitByTracesSliced
struct SplitByTracesSliced <: SplitByTraces end

function getWorkerRange(w::SplitByTracesSliced, globalRange::UnitRange)
  if nprocs() > 1
    return (globalRange[1] + myid() - 2, nworkers(), globalRange[end])
  else
    return (globalRange[1],1,globalRange[end])
  end
end


export SplitByTracesBlock
struct SplitByTracesBlock <: SplitByTraces end

export getWorkerRange
function getWorkerRange(w::SplitByTracesBlock, globalRange::UnitRange)
  len = length(globalRange)
  n = nworkers()
  blocksize  = div(len,n)
  if nprocs() > 1
    traceStart = globalRange[1] + (myid() - 2)*blocksize

    if myid() == findmax(workers())[1]
      traceEnd = globalRange[end]
    else
      traceEnd = traceStart + blocksize - 1
    end

    return (traceStart, 1, traceEnd)
  else
    return (globalRange[1],1,globalRange[end])
  end
end


export DistributedTrace

mutable struct DistributedTrace <: Traces
  count::Int
  trsfn::Function
  worksplit::WorkSplit

  function DistributedTrace(trsfn::Function,worksplit=SplitByTracesBlock())
    fn = let trs = nothing
      function cachetrs()
        if trs == nothing
          trs = trsfn()
        end

        return trs
      end
      cachetrs
    end

    return new(0,fn,worksplit)
  end

end

length(trs::DistributedTrace) = @fetch length(trs.trsfn())
nrsamples(trs::DistributedTrace, post::Bool) = @fetch nrsamples(trs.trsfn(),post)
nrsamples(trs::DistributedTrace) = @fetch nrsamples(trs.trsfn())
sampletype(trs::DistributedTrace) = @fetch sampletype(trs.trsfn())

function setPostProcessor(trs::DistributedTrace, p::Union{Missing,Type{<: PostProcessor}})
    @sync for worker in workers()
      @spawnat worker setPostProcessor(trs.trsfn(),p)
    end
end

function initPostProcessor(trs::DistributedTrace, args...)
  @sync for worker in workers()
    @spawnat worker initPostProcessor(trs.trsfn(), args...)
  end
end

function getPostProcessorResult(trs::DistributedTrace)
  ww = workers()
  worker1copy = @fetchfrom ww[1] meta(trs.trsfn()).postProcInstance

  for worker in ww
    if worker == ww[1]
      continue
    else
      other = @fetchfrom worker meta(trs.trsfn()).postProcInstance
      merge(worker1copy, other)
    end
  end

  return get(worker1copy)
end

function setColumnRange(trs::DistributedTrace, r::Union{Missing,UnitRange})
  @sync for worker in workers()
    @spawnat worker setColumnRange(trs.trsfn(), r)
  end
end

function setPreColumnRange(trs::DistributedTrace, r::Union{Missing,UnitRange})
  @sync for worker in workers()
    @spawnat worker setPreColumnRange(trs.trsfn(), r)
  end
end

function addSamplePass(trs::DistributedTrace, f::Function, prprnd=false)
  @sync for worker in workers()
    @spawnat worker addSamplePass(trs.trsfn(), f, prprnd)
  end
end

function popSamplePass(trs::DistributedTrace, fromStart=false)
  @sync for worker in workers()
    @spawnat worker popSamplePass(trs.trsfn(), fromStart)
  end
end

function addDataPass(trs::DistributedTrace, f::Function, prprnd=false)
  @sync for worker in workers()
    @spawnat worker addDataPass(trs.trsfn(), f, prprnd)
  end
end

function popDataPass(trs::DistributedTrace, fromStart=false)
  @sync for worker in workers()
    @spawnat worker popDataPass(trs.trsfn(), fromStart)
  end
end

function reset(trs::DistributedTrace)
  @sync for worker in workers()
    @spawnat worker reset(trs.trsfn())
  end
end

function getCounter(trs::DistributedTrace)
  total = 0
  @sync for worker in workers()
    total += @fetchfrom worker meta(trs.trsfn()).tracesReturned
  end

  return total
end

function hasPostProcessor(trs::DistributedTrace)
  return @fetch hasPostProcessor(trs.trsfn())
end
