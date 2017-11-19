# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

import Base.get
import Base.truncate

export printScores

# print the scores pretty
function printScores(params::DpaAttack, phase::Int, rankData::RankData, numberOfTraces::Int, numberOfRows::Int, numberOfColsProcessed::Int, numberOfColsAfterProcessing::Int, targets::Vector{Int}, printsubs=false,  max=5, io=STDOUT) 
  nrLeakageFunctions = rankData.nrLeakages
  keyLength = length(targets)
  winners = zeros(UInt8, keyLength)
  phaseDataOffset = offset(params,phase)
  phaseDataLength = numberOfTargets(params, phase)
  correctKeyMaterial = !isnull(params.knownKey) ? params.correctKeyMaterial[phaseDataOffset+1:phaseDataOffset+phaseDataLength] : Vector{UInt8}(0)
  print(io, "Results @ $numberOfRows rows, $numberOfColsAfterProcessing cols ($numberOfTraces rows, $numberOfColsProcessed cols, consumed)\n")

  j = 1
  for target in targets
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

function lazyinit(a::RankData, phase::Int, target::Int, guesses::Int, leakage::Int, numberOfTraces::Int)
  if !(phase in keys(a.numberOfTraces))
    a.numberOfTraces[phase] = IntSet()
    a.combinedScores[phase] = Dict{Int, Matrix{Float64}}()
    a.scores[phase] = Dict{Int, Dict{Int, Matrix{Float64}}}()
    a.offsets[phase] = Dict{Int, Dict{Int, Matrix{Int}}}()
  end

  push!(a.numberOfTraces[phase], numberOfTraces)
  
  if !(target in keys(a.scores[phase]))
    a.scores[phase][target] = Dict{Int,Matrix{Float64}}()
    a.offsets[phase][target] = Dict{Int,Matrix{Int}}()
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

  return find(x -> x == numberOfTraces, a.numberOfTraces[phase])[1]
end

function update!(g::AbsoluteGlobalMaximization, a::RankData, phase::Int, C::AbstractArray{Float64,2}, target::Int, leakage::Int, nrTraces::Int, colStart::Int)
  (samples,guesses) = size(C)
  r = lazyinit(a,phase,target,guesses,leakage,nrTraces)
  (corrvals, corrvaloffsets) = findmax(abs.(C), 1)

  for (idx,val) in enumerate(corrvals)
    if val > a.scores[phase][target][leakage][idx,r]
      a.scores[phase][target][leakage][idx,r] = val
      a.offsets[phase][target][leakage][idx,r] = ind2sub(size(C), corrvaloffsets[idx])[1] + colStart-1
    end
  end
end

function update!(g::GlobalMaximization, a::RankData, phase::Int, C::AbstractArray{Float64,2}, target::Int, leakage::Int, nrTraces::Int, colStart::Int)
  (samples,guesses) = size(C)
  r = lazyinit(a,phase,target,guesses,leakage,nrTraces)
  (corrvals, corrvaloffsets) = findmax(C, 1)

  for (idx,val) in enumerate(corrvals)
    if val > a.scores[phase][target][leakage][idx,r]
      a.scores[phase][target][leakage][idx,r] = val
      a.offsets[phase][target][leakage][idx,r] = ind2sub(size(C), corrvaloffsets[idx])[1] + colStart-1
    end
  end
end

function update!(g::NormalizedMaximization, a::RankData, phase::Int, C::AbstractArray{Float64,2}, target::Int, leakage::Int, nrTraces::Int, colStart::Int)
  (samples,guesses) = size(C)
  r = lazyinit(a,phase,target,guesses,leakage,nrTraces)

  for s in 1:samples
    cols = C[s,:]
    val = (maximum(cols) - mean(cols)) / std(cols)
    idx = findmax(cols)[2]
    if val > a.scores[phase][target][leakage][idx,r]
      a.scores[phase][target][leakage][idx,r] = val
      a.offsets[phase][target][leakage][idx,r] = s + colStart-1
    end
  end
end

function setCombined!(a::Sum, sc::RankData, phase::Int, target::Int, nrTraces::Int)
  if sc.nrLeakages > 1
    r = length(sc.numberOfTraces[phase])
    sc.combinedScores[phase][target][:,r] .= 0

    for leakage in keys(sc.scores[phase][target])
      sc.combinedScores[phase][target][:,r] += sc.scores[phase][target][leakage][:,r]
    end
  end
end

export getPhases

function getPhases(evo::RankData)
  return sort(collect(keys(evo.numberOfTraces)))
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

export getNumberOfTraces

function getNumberOfTraces(evo::RankData, phase::Int)
  return collect(evo.numberOfTraces[phase])
end

export getScores

function getScores(sc::RankData, phase::Int, target::Int, leakage::Int)
  r = length(sc.numberOfTraces[phase])
  return sc.scores[phase][target][leakage][:,r]
end

function getScores(sc::RankData, phase::Int, target::Int)
  r = length(sc.numberOfTraces[phase])
  return sc.combinedScores[phase][target][:,r]
end

export getOffsets

function getOffsets(sc::RankData, phase::Int, target::Int, leakage::Int)
  r = length(sc.numberOfTraces[phase])
  return sc.offsets[phase][target][leakage][:,r]
end

function getOffsets(sc::RankData, phase::Int, target::Int)
  r = length(sc.numberOfTraces[phase])
  return sc.offsets[phase][target][1][:,r]
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

    numberOfTraces = getNumberOfTraces(evo,phase)
    
    for r in 1:length(numberOfTraces)
      print(fd, "$(numberOfTraces[r])")
      for target in targets
        kbval = correctKeyMaterial[offset(params,phase,target)+1]
        scores = getScoresEvolution(evo, phase, target)
        @assert size(scores)[2] == length(numberOfTraces)
        rnk = findfirst(x -> x == kbval + 1, sortperm(scores[:,r], rev=true))
        print(fd,",$(rnk)")
      end
      print(fd,"\n")
    end
    close(fd)
  end
end

