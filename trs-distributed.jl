export DistributedTrace

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

function getCounter(trs::DistributedTrace)
  total = @fetch Main.trs.tracesReturned
  # total::Int = 0
  # @sync for worker in workers()
  #   total += @fetchfrom worker Main.trs.tracesReturned
  # end
  return total
end

function setPostProcessor(trs::DistributedTrace, x, args...)
  @sync for worker in workers()
    @spawnat worker setPostProcessor(Main.trs, x, args...)
  end
end


function instantiatePostProcessor(trs::DistributedTrace)
  @sync for worker in workers()
    @spawnat worker instantiatePostProcessor(Main.trs)
  end
end

# return immediately
function runPostProcessor(trs::DistributedTrace, range::Range, done::BitArray{1})
  for w in workers()
    @async begin
      @spawnat w begin
        runPostProcessor(Main.trs, range)
      end
      if nprocs() > 1
        done[w-1] = true
      else
        done[1] = true
      end
    end
  end
end
