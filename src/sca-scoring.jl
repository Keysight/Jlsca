# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

import Base.get
import Base.truncate

export printScores

# print the scores pretty
function printScores(params::DpaAttack, phase::Int, rankData::RankData, nrConsumedRows::Int, nrRows::Int, nrConsumedCols::Int, nrCols::Int, targets::Vector{Int}, printsubs=false,  max=5, io=STDOUT) 

  if !(phase in getPhases(rankData))
    return
  end

  nrLeakageFunctions = rankData.nrLeakages
  keyLength = length(targets)
  winners = zeros(UInt8, keyLength)
  phaseDataOffset = offset(params,phase)
  phaseDataLength = numberOfTargets(params, phase)
  correctKeyMaterial = !isnull(params.knownKey) ? params.correctKeyMaterial[phaseDataOffset+1:phaseDataOffset+phaseDataLength] : Vector{UInt8}(0)
  nrConsumedRows = getNrConsumedRows(rankData, phase)
  nrConsumedCols = getNrConsumedCols(rankData, phase)

  j = 1
  for target in targets
    if !(target in getTargets(rankData,phase))
      continue
    end
    nrRows = getNrRows(rankData, phase, target)
    nrCols = getNrCols(rankData, phase, target)
    print(io, "Results @ $nrRows rows, $nrCols cols ($nrConsumedRows rows, $nrConsumedCols cols, consumed)\n")
    scores = getScores(rankData, phase, target)

    # sort peaks
    ranks = sortperm(scores, rev=true)

    winners[j] = ranks[1] - 1
    j += 1

    @printf(io, "target: %d, phase: %d, \"%s\"\n", target, phase, getTarget(params, phase, target))

    printableIndexes = ranks[1:max]
    if length(correctKeyMaterial) > 0
      correctKbOffset = findfirst(x -> x == (correctKeyMaterial[target] + 1), ranks)
      if correctKbOffset > max
        printableIndexes = [ ranks[1:max-1] ; correctKeyMaterial[target] + 1]
      end
    end
    
    # print top 5 peaks
    # for known key scenario: print top 5 if it includes the correct key byte, top 4 and the correct key byte otherwise
    for i in printableIndexes
      cand = i - 1
      peak = scores[i]
      rank = findfirst(x -> x == i, ranks)

      if length(correctKeyMaterial) > 0 && cand == correctKeyMaterial[target]
        pretty = "correct  "
      else
        pretty = "candidate"
      end

      if nrLeakageFunctions == 1
        sample = getOffsets(rankData, phase, target)[i]
        @printf(io, "rank: %3d, %s: 0x%02x, peak: %f @ %d\n", rank, pretty, cand, peak, sample)
      else
        @printf(io, "rank: %3d, %s: 0x%02x, %s of peaks: %f\n", rank, pretty, cand, params.leakageCombinator, peak)
        if printsubs
          # print the max peak for each leakage function
          for leakage in 1:nrLeakageFunctions
            lscores = getScores(rankData, phase, target, leakage)
            loffsets = getOffsets(rankData, phase, target, leakage)
            lrank = lscores[i]
            lsample = loffsets[i]
            @printf(io, " %0.2f @ %d\n", lrank, sample)
          end
        end
      end
    end
  end

  @printf(io, "recovered key material: %s\n", bytes2hex(winners))

end

function lazyinit(a::RankData, phase::Int, target::Int, guesses::Int, leakage::Int, nrConsumedRows::Int, nrConsumedCols::Int, nrRows::Int, nrCols::Int)
  if !(phase in keys(a.nrConsumedRows))
    a.nrConsumedRows[phase] = IntSet()
    a.nrConsumedCols[phase] = zeros(Int, a.intervals)
    a.nrRows[phase] = Dict{Int, Vector{Int}}()
    a.nrCols[phase] = Dict{Int, Vector{Int}}()
    a.combinedScores[phase] = Dict{Int, Matrix{Float64}}()
    a.scores[phase] = Dict{Int, Dict{Int, Matrix{Float64}}}()
    a.offsets[phase] = Dict{Int, Dict{Int, Matrix{Int}}}()
  end

  push!(a.nrConsumedRows[phase], nrConsumedRows)
  r = find(x -> x == nrConsumedRows, a.nrConsumedRows[phase])[1]
  
  if !(target in keys(a.scores[phase]))
    a.scores[phase][target] = Dict{Int,Matrix{Float64}}()
    a.offsets[phase][target] = Dict{Int,Matrix{Int}}()
    a.nrRows[phase][target] = zeros(Int, a.intervals)
    a.nrCols[phase][target] = zeros(Int, a.intervals)
  end
  
  if !(leakage in keys(a.scores[phase][target]))
    a.scores[phase][target][leakage] = zeros(Float64, guesses, a.intervals)
    a.offsets[phase][target][leakage] = zeros(Int, guesses,a.intervals)
  end
  
  if !(target in keys(a.combinedScores[phase]))
    if a.nrLeakages == 1
      a.combinedScores[phase][target] = first(a.scores[phase][target])[2]
    else
      a.combinedScores[phase][target] = zeros(Float64, guesses, a.intervals)
    end
  end

  if leakage == 1
    if target == 1
      a.nrConsumedCols[phase][r] += nrConsumedCols
    end
    a.nrCols[phase][target][r] += nrCols
    a.nrRows[phase][target][r] = nrRows
  end

  return r
end

function update!(g::AbsoluteGlobalMaximization, a::RankData, phase::Int, C::AbstractArray{Float64,2}, target::Int, leakage::Int, nrConsumedRows::Int, nrConsumedCols::Int,  nrRows::Int, nrCols::Int, colOffset::Int)
  (samples,guesses) = size(C)
  r = lazyinit(a,phase,target,guesses,leakage,nrConsumedRows,nrConsumedCols,nrRows,nrCols)
  (corrvals, corrvaloffsets) = findmax(abs.(C), 1)

  for (idx,val) in enumerate(corrvals)
    if val > a.scores[phase][target][leakage][idx,r]
      a.scores[phase][target][leakage][idx,r] = val
      a.offsets[phase][target][leakage][idx,r] = ind2sub(size(C), corrvaloffsets[idx])[1] + colOffset-1
    end
  end
end

function update!(g::GlobalMaximization, a::RankData, phase::Int, C::AbstractArray{Float64,2}, target::Int, leakage::Int, nrConsumedRows::Int, nrConsumedCols::Int,  nrRows::Int, nrCols::Int, colOffset::Int)
  (samples,guesses) = size(C)
  r = lazyinit(a,phase,target,guesses,leakage,nrConsumedRows,nrConsumedCols,nrRows,nrCols)
  (corrvals, corrvaloffsets) = findmax(C, 1)

  for (idx,val) in enumerate(corrvals)
    if val > a.scores[phase][target][leakage][idx,r]
      a.scores[phase][target][leakage][idx,r] = val
      a.offsets[phase][target][leakage][idx,r] = ind2sub(size(C), corrvaloffsets[idx])[1] + colOffset-1
    end
  end
end

function update!(g::NormalizedMaximization, a::RankData, phase::Int, C::AbstractArray{Float64,2}, target::Int, leakage::Int, nrConsumedRows::Int, nrConsumedCols::Int,  nrRows::Int, nrCols::Int, colOffset::Int)
  (samples,guesses) = size(C)
  r = lazyinit(a,phase,target,guesses,leakage,nrConsumedRows,nrConsumedCols,nrRows,nrCols)

  for s in 1:samples
    cols = C[s,:]
    val = (maximum(cols) - mean(cols)) / std(cols)
    idx = findmax(cols)[2]
    if val > a.scores[phase][target][leakage][idx,r]
      a.scores[phase][target][leakage][idx,r] = val
      a.offsets[phase][target][leakage][idx,r] = s + colOffset-1
    end
  end
end

function setCombined!(a::Sum, sc::RankData, phase::Int, target::Int, nrConsumedRows::Int)
  if sc.nrLeakages > 1
    r = length(sc.nrConsumedRows[phase])
    sc.combinedScores[phase][target][:,r] .= 0

    for leakage in keys(sc.scores[phase][target])
      sc.combinedScores[phase][target][:,r] += sc.scores[phase][target][leakage][:,r]
    end
  end
end

export getIntervals

function getIntervals(evo::RankData)
  return collect(1:evo.intervals)
end

export getPhases

function getPhases(evo::RankData)
  return sort(collect(keys(evo.nrConsumedRows)))
end

export getTargets

function getTargets(evo::RankData, phase::Int)
  return sort(collect(keys(evo.combinedScores[phase])))
end

export getLeakages

function getLeakages(evo::RankData, phase::Int, target::Int)
  return sort(collect(keys(evo.scores[phase][target])))
end

export getGuesses

function getGuesses(evo::RankData, phase::Int, target::Int)
  return collect(UInt8, 0:size(evo.combinedScores[phase][target])[1]-1)
end

export getRankingsEvolution

function getRankingsEvolution(evo::RankData, phase::Int, target::Int, kbval::UInt8)
    (rows,cols) = size(evo.combinedScores[phase][target])
    ranks = map(r -> findfirst(x -> x == kbval + 1, sortperm(evo.combinedScores[phase][target][:,r], rev=true)), 1:cols)
    return ranks
end

function getRankingsEvolution(evo::RankData, phase::Int, target::Int, leakage::Int, kbval::UInt8)
    (rows,cols) = size(evo.scores[phase][target][leakage])
    ranks = map(r -> findfirst(x -> x == kbval + 1, sortperm(evo.scores[phase][target][leakage][:,r], rev=true)), 1:cols)
    return ranks
end

export getScoresEvolution

function getScoresEvolution(evo::RankData, phase::Int, target::Int)
  return evo.combinedScores[phase][target]
end  

function getScoresEvolution(evo::RankData, phase::Int, target::Int, leakage::Int)
  return evo.scores[phase][target][leakage]
end  

function getScoresEvolution(evo::RankData, phase::Int, target::Int, kbval::UInt8)
  return evo.combinedScores[phase][target][kbval+1,:]
end

function getScoresEvolution(evo::RankData, phase::Int, target::Int, leakage::Int, kbval::UInt8)
  return evo.scores[phase][target][leakage][kbval+1,:]
end

export getOffsetsEvolution

function getOffsetsEvolution(evo::RankData, phase::Int, target::Int, leakage::Int)
  return evo.offsets[phase][target][leakage]
end

export getNrConsumedRows

function getNrConsumedRows(evo::RankData, phase::Int)
  return last(evo.nrConsumedRows[phase])
end

export getNrConsumedRowsEvolution

function getNrConsumedRowsEvolution(evo::RankData, phase::Int)
  return collect(evo.nrConsumedRows[phase])
end

export getNrConsumedCols

function getNrConsumedCols(evo::RankData, phase::Int)
  r = length(evo.nrConsumedRows[phase])
  return evo.nrConsumedCols[phase][r]
end

export getNrConsumedColsEvolution

function getNrConsumedColsEvolution(evo::RankData, phase::Int)
  return evo.nrConsumedCols[phase]
end

export getNrRows

function getNrRows(evo::RankData, phase::Int, target::Int)
  r = length(evo.nrConsumedRows[phase])
  return evo.nrRows[phase][target][r]
end

export getNrRowsEvolution

function getNrRowsEvolution(evo::RankData, phase::Int, target::Int)
  return evo.nrRows[phase][target]
end

export getNrCols

function getNrCols(evo::RankData, phase::Int, target::Int)
  r = length(evo.nrConsumedRows[phase])
  return evo.nrCols[phase][target][r]
end

export getNrColsEvolution

function getNrColsEvolution(evo::RankData, phase::Int, target::Int)
  return evo.nrCols[phase][target]
end

export getScores

function getScores(sc::RankData, phase::Int, target::Int, leakage::Int)
  r = length(sc.nrConsumedRows[phase])
  return sc.scores[phase][target][leakage][:,r]
end

function getScores(sc::RankData, phase::Int, target::Int)
  r = length(sc.nrConsumedRows[phase])
  return sc.combinedScores[phase][target][:,r]
end

export getOffsets

function getOffsets(sc::RankData, phase::Int, target::Int, leakage::Int)
  r = length(sc.nrConsumedRows[phase])
  return sc.offsets[phase][target][leakage][:,r]
end

function getOffsets(sc::RankData, phase::Int, target::Int)
  r = length(sc.nrConsumedRows[phase])
  return sc.offsets[phase][target][1][:,r]
end

function haveAllData(evo::RankData, attack::Attack, phase::Int)
  if !(phase in getPhases(evo))
    return false
  elseif length(getTargets(evo, phase)) != numberOfTargets(attack,phase)
    return false
  else  
    return true
  end
end

export getPhaseKey

function getPhaseKey(params::DpaAttack, attack::Attack, phase::Int, sc::RankData)
  return map(x -> UInt8(sortperm(getScores(sc,phase,x), rev=true)[1] - 1), getTargets(sc, phase))
end

export getKey

function getKey(params::DpaAttack, sc::RankData)
  ckm = nothing
  allPhaseData = Vector{UInt8}(0)
  for phase in 1:numberOfPhases(params.attack)
    if phase in keys(sc.scores)
      phaseData = getPhaseKey(params, params.attack, phase, sc)
    else
      if ckm == nothing
        ckm = correctKeyMaterial(attack, get(params.knownKey))
      end
      o = sum(x -> numberOfTargets(params,x), 1:phase-1)
      l = numberOfTargets(params,p)
      phaseData = ckm[o+1:o+l]
    end
    allPhaseData = vcat(allPhaseData,phaseData)
  end

  return recoverKey(params.attack, allPhaseData)
end

function truncate(fname)
    fd = open(fname, "w")
    truncate(fd, 0)
    close(fd)
end

function correctKeyRanks2CSV(params::DpaAttack)
  evo = params.rankData
  phases = getPhases(evo)
  correctKeyMaterial = params.correctKeyMaterial

  for phase in phases
    kkaFilename = @sprintf("%s.ranking.phase%02d.csv",get(params.outputkka),phase)
    truncate(kkaFilename)
    isempty = stat(kkaFilename).size == 0

    fd = open(kkaFilename, "a")

    targets = getTargetOffsets(params, phase)

    print(fd, "nr of traces")
    for target in targets
      print(fd, ",target $target rank")
    end
    print(fd, "\n")

    nrConsumedRows = getNrConsumedRowsEvolution(evo,phase)
    for r in 1:length(nrConsumedRows)
      print(fd, "$(nrConsumedRows[r])")
      for target in targets
        kbval = correctKeyMaterial[offset(params,phase,target)+1]
        scores = getScoresEvolution(evo, phase, target)
        # @assert size(scores)[2] == length(nrConsumedRows)
        rnk = findfirst(x -> x == kbval + 1, sortperm(scores[:,r], rev=true))
        print(fd,",$(rnk)")
      end
      print(fd,"\n")
    end
    close(fd)
  end
end

