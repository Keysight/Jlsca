# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse

@inline function add(c::PostProcessor,trs::Traces,idx::Int)
      data = getData(trs,idx)
      if length(data) == 0
        return
      end

      samples = getSamples(trs,idx)
      if length(samples) == 0
        return
      end

      add(c,samples,data,idx)
end

function add(c::PostProcessor, trs::Traces, localrange::Tuple, update::Function)
  traceStart,traceStep,traceEnd = localrange
  rangestr = @sprintf("trace range %s", traceStart:traceStep:traceEnd)
  m = meta(trs)
  @printf("Running processor \"%s\" on %s, %d data passes, %d sample passes\n", c, rangestr, length(m.dataPasses), length(m.passes))
  total = 0
  bla = 0
  try
    t1 = time()
    for idx in traceStart:traceStep:traceEnd
      # uncomment for hot loop profiling
      # if idx == traceStart
      #   Profile.clear_malloc_data()
      #   Profile.start_timer()
      # end
      add(c, trs, idx)
      total += 1

      t2 = time()
      if t2 - t1 > 0.2
        t1 = time()
        remotecall_wait(update, 1, total - bla)
        bla = total
      end
    end
    # uncomment for hot loop profiling
    # Profile.stop_timer()
    # Profile.print(maxdepth=20,combine=true)
    # exit()
  catch e
    if !isa(e, EOFError)
      rethrow(e)
    else
      @printf("EOF!!!!1\n")
    end
  end

  m.tracesReturned = getGlobCounter(c)
end
