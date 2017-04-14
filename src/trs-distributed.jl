export DistributedTrace

import Base.sync_begin, Base.sync_end, Base.async_run_thunk
export @everyworker

macro everyworker(ex)
    quote
        sync_begin()
        thunk = ()->(eval(Main,$(Expr(:quote,ex))); nothing)
        for pid in workers()
            async_run_thunk(()->remotecall_fetch(thunk, pid))
            yield() # ensure that the remotecall_fetch has been started
        end
        sync_end()
    end
end

type DistributedTrace <: Trace
  count::Int

  function DistributedTrace()
    return new(0)
  end

end

length(trs::DistributedTrace) = @fetch length(Main.trs)
pipe(trs::DistributedTrace) = false


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
    worksplit = @fetch Main.trs.postProcInstance.worksplit
  else
    worksplit = trs2.postProcInstance.worksplit
  end

  if isa(worksplit, SplitByTraces)
    total::Int = 0
    @sync for worker in workers()
      total += @fetchfrom worker Main.trs.tracesReturned
    end
  elseif isa(worksplit, SplitByData) || isa(worksplit, NoSplit)
    total = @fetch Main.trs.tracesReturned
  else
    throw(ErrorException("not suppoerpeopsodpsofd!!!1"))
  end

  return total
end

function hasPostProcessor(trs::DistributedTrace)
  return @fetch hasPostProcessor(Main.trs)
end
