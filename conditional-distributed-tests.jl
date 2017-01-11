# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse

using Base.Test

include("trs-core.jl")
include("conditional.jl")
include("conditional-distributed.jl")

function sanity1()
  # configurable
  workers = 33
  numberOfAverages = 17
  numberOfCandidates = 223


  allEntries = Vector{Tuple{Int,Int}}(numberOfAverages*numberOfCandidates)
  workers = min(workers, length(allEntries))

  @printf("testing for %d workers, %d averages and %d candidates\n", workers, numberOfAverages, numberOfCandidates)
  i = 0
  for a in 1:numberOfAverages
    for b in 1:numberOfCandidates
      i += 1
      allEntries[i] = (a,b-1)
    end
  end

  @test i == numberOfAverages*numberOfCandidates


  w = WorkSplit(numberOfAverages, numberOfCandidates)

  range = getTotalRange(w)

  entrySeen = falses(numberOfAverages*numberOfCandidates)
  for i in range
    entrySeen[i-range[1]+1] = true

    (idx,cand) = allEntries[i-range[1]+1]
    @test idx == getAverageIdx(w,i)
    @test cand == getCandidate(w,i)
    @test i == toVal(w,idx,cand)
  end

  @test !(false in entrySeen)

  workerranges = splitRange(w, workers)
  entrySeen = falses(numberOfAverages*numberOfCandidates)

  base = range[1]
  for wr in workerranges
    @test length(wr) >= div(length(allEntries), workers)
    for i in wr
      @test entrySeen[i-base+1] == false
      entrySeen[i-base+1] = true

      (idx,cand) = allEntries[i-base+1]
      @test idx == getAverageIdx(w,i)
      @test cand == getCandidate(w,i)
      @test i == toVal(w,idx,cand)
    end
  end

  @test !(false in entrySeen)
end

sanity1()
