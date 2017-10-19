# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse

export WorkSplit,SplitByTraces,SplitByTracesSliced,SplitByTracesBlock,NoSplit,getWorkerRange

abstract type WorkSplit end

type NoSplit <: WorkSplit end

function splitRange(numberOfAverages::Int, numberOfCandidates::Int, workers::Int)
  range = 0:((numberOfAverages)*numberOfCandidates-1)
  workerranges = Range[]
  workers = min(length(range), workers)
  stepsize = div(range[end] - range[1] + 1, workers)

  for i in 1:workers
    start = (i-1)*stepsize + range[1]
    if i < workers
      stop = start + stepsize - 1
    else
      stop = range[end]
    end
    push!(workerranges, start:stop)
  end

  return workerranges
end

abstract type SplitByTraces <: WorkSplit end

type SplitByTracesSliced <: SplitByTraces
  worker::Int

  function SplitByTracesSliced()
    new(myid())
  end
end

function getWorkerRange(w::SplitByTracesSliced, globalRange::Range)
  if nprocs() > 1
    return (globalRange[1] + w.worker - 2, nworkers(), globalRange[end])
  else
    return (globalRange[1],1,globalRange[end])
  end
end


type SplitByTracesBlock <: SplitByTraces
  worker::Int

  function SplitByTracesBlock()
    new(myid())
  end
end

function getWorkerRange(w::SplitByTracesBlock, globalRange::Range)
  if nprocs() > 1
    traceStart = (w.worker - 2) * div(globalRange[end], nworkers()) + 1
    if w.worker == findmax(workers())[1]
      traceEnd = globalRange[end]
    else
      traceEnd = (w.worker - 1) * div(globalRange[end], nworkers())
    end
    return (traceStart, 1, traceEnd)
  else
    return (globalRange[1],1,globalRange[end])
  end
end

function add(c::PostProcessor, trs::Trace, globalRange::Range, update::Function)
  if !isa(c.worksplit, NoSplit)
    (traceStart,traceStep,traceEnd) = getWorkerRange(c.worksplit, globalRange)
  else
    traceStart = globalRange[1]
    traceStep = 1
    traceEnd = globalRange[end]
  end
  rangestr = @sprintf("trace range %s", traceStart:traceStep:traceEnd)

  @printf("Running processor \"%s\" on %s, %d data passes, %d sample passes\n", c, rangestr, length(trs.dataPasses), length(trs.passes))
  total = 0
  bla = 0
  try
    t1 = time()
    for idx in traceStart:traceStep:traceEnd
      add(c, trs, idx)
      total += 1
      t2 = time()
      if t2 - t1 > 0.2
        t1 = time()
        remotecall_wait(update, 1, total - bla)
        bla = total
      end
    end
  catch e
    if !isa(e, EOFError)
      rethrow(e)
    else
      @printf("EOF!!!!1\n")
    end
  end

  trs.tracesReturned = getGlobCounter(c)
end
