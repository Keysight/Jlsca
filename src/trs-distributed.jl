export DistributedTrace

import Base.sync_begin, Base.sync_end, Base.async_run_thunk
export @everyworker,@worker

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

macro worker(pid,ex)
    quote
        sync_begin()
        thunk = ()->(eval(Main,$(Expr(:quote,ex))); nothing)
        async_run_thunk(()->remotecall_fetch(thunk, pid))
        yield() # ensure that the remotecall_fetch has been started
        sync_end()
    end
end

type DistributedTrace <: Trace
  count::Int
  colRange::Nullable{Range}

  function DistributedTrace()
    return new(0,Nullable{Range}())
  end

end

length(trs::DistributedTrace) = @fetch length(Main.trs)
pipe(trs::DistributedTrace) = false

nrSamplePasses(trs::DistributedTrace) = @fetch length(Main.trs.passes)

function setColumnRange(trs::DistributedTrace, r::Nullable{Range})
  @sync for worker in workers()
    @spawnat worker setColumnRange(Main.trs, r)
  end
end

function setPreColumnRange(trs::DistributedTrace, r::Nullable{Range})
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
    worksplit = @fetch Main.trs.postProcInstance.worksplit
  else
    worksplit = trs2.postProcInstance.worksplit
  end

  total = 0
  @sync for worker in workers()
    total += @fetchfrom worker Main.trs.tracesReturned
  end

  return total
end

function hasPostProcessor(trs::DistributedTrace)
  return @fetch hasPostProcessor(Main.trs)
end
