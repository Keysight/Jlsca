# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse

type WorkSplit
  numberOfAverages::Int
  numberOfCandidates::Int
  worker::Int

  function WorkSplit(numberOfAverages::Int, numberOfCandidates::Int)
    new(numberOfAverages, numberOfCandidates, myid())
  end
end

getTotalRange(w::WorkSplit) = 0:((w.numberOfAverages)*w.numberOfCandidates-1)
getAverageIdx(w::WorkSplit, val::Int) = div(val,w.numberOfCandidates)+1
getCandidate(w::WorkSplit, val::Int) = val % w.numberOfCandidates
toVal(w::WorkSplit, averageIdx::Int, candidate::Int) = ((averageIdx-1)*w.numberOfCandidates) + candidate

function getWorkerRange(w::WorkSplit)
  if nprocs() > 1
    return splitRange(w, nworkers())[myid()-1]
  else
    return splitRange(w, 1)[1]
  end
end

function splitRange(w::WorkSplit, workers::Int)
  range = getTotalRange(w)
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

function add(c::Cond, trs::Trace, range::Range, f::Function)
  t1 = time()
  cnt = 0
  for idx in range
    add(c, trs, idx)
    t2 = time()
    if t2 - t1 > 0.2
      t1 = time()
      remotecall_wait(f, 1, getGlobCounter(c)-cnt)
      cnt = getGlobCounter(c)
    end
  end
end
