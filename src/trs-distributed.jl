export DistributedTrace

mutable struct DistributedTrace <: Traces
  count::Int

  function DistributedTrace()
    return new(0)
  end

end

length(trs::DistributedTrace) = @fetch length(Main.trs)
pipe(trs::DistributedTrace) = false

nrsamples(trs::DistributedTrace, post::Bool) = @fetch nrsamples(Main.trs,post)
nrsamples(trs::DistributedTrace) = @fetch nrsamples(Main.trs)
sampletype(trs::DistributedTrace) = @fetch sampletype(Main.trs)

function setColumnRange(trs::DistributedTrace, r::Union{Missing,UnitRange})
  @sync for worker in workers()
    @spawnat worker setColumnRange(Main.trs, r)
  end
end

function setPreColumnRange(trs::DistributedTrace, r::Union{Missing,UnitRange})
  @sync for worker in workers()
    @spawnat worker setPreColumnRange(Main.trs, r)
  end
end

function addSamplePass(trs::DistributedTrace, f::Function, prprnd=false)
  @sync for worker in workers()
    @spawnat worker addSamplePass(Main.trs, f, prprnd)
  end
end

function popSamplePass(trs::DistributedTrace, fromStart=false)
  @sync for worker in workers()
    @spawnat worker popSamplePass(Main.trs, fromStart)
  end
end

function addDataPass(trs::DistributedTrace, f::Function, prprnd=false)
  @sync for worker in workers()
    @spawnat worker addDataPass(Main.trs, f, prprnd)
  end
end

function popDataPass(trs::DistributedTrace, fromStart=false)
  @sync for worker in workers()
    @spawnat worker popDataPass(Main.trs, fromStart)
  end
end

function reset(trs::DistributedTrace)
  @sync for worker in workers()
    @spawnat worker reset(Main.trs)
  end
end

function getCounter(trs2::DistributedTrace)
  if isa(trs2, DistributedTrace)
    worksplit = @fetch meta(Main.trs).postProcInstance.worksplit
  else
    worksplit = meta(trs2).postProcInstance.worksplit
  end

  total = 0
  @sync for worker in workers()
    total += @fetchfrom worker meta(Main.trs).tracesReturned
  end

  return total
end

function hasPostProcessor(trs::DistributedTrace)
  return @fetch hasPostProcessor(Main.trs)
end
