# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export sampleDeviationPreprocessor
export getRankData
export add2kka
export printScores
export getRoundKey

import Base.get
import Base.truncate


length(sc::RankData) = length(sc.scores)
getindex(sc::RankData, i::Int) = (sc.scores[i], sc.offsets[i])

function clearRankData!(sc::RankData)
  for i in 1:length(sc)
    (scores,offsets) = sc[i]
    for j in 1:length(scores)
      scores[j] .= 0
      offsets[j] .= 0
    end
  end
end

function updateRankData!(a::GlobalMaximization, sc::RankData, C::AbstractArray{Float64,2}, targetOffset::Int, leakageIdx::Int)
    scores = sc.scores[leakageIdx][targetOffset]
    offsets = sc.offsets[leakageIdx][targetOffset]
    (corrvals, corrvaloffsets) = findmax(C, 1)

    for (idx,val) in enumerate(corrvals)
      if val > scores[idx]
        scores[idx] = val
        offsets[idx] = ind2sub(size(C), corrvaloffsets[idx])[1]
      end
    end
end

function updateRankData!(a::NormalizedMaximization, sc::RankData, C::AbstractArray{Float64,2}, targetOffset::Int, leakageIdx::Int)
    scores = sc.scores[leakageIdx][targetOffset]
    offsets = sc.offsets[leakageIdx][targetOffset]
    (rows,) = size(C)

    for r in 1:rows
      cols = C[r,:]
      val = (maximum(cols) - mean(cols)) / std(cols)
      idx = findmax(cols)[2]
      if val > scores[idx]
        scores[idx] = val
        offsets[idx] = r
      end
    end
end

function setCombinedRankData!(a::Sum, sc::RankData)
  for targetOffset in 1:sc.nrTargets
    sc.combinedScores[targetOffset] .= 0
  end

  for i in 1:sc.nrLeakages
    (scoresSingleLeakage,offsetsSingleLeakage) = sc[i]
    for targetOffset in 1:sc.nrTargets
      scores = sc.combinedScores[targetOffset]
      scores .= scores .+ scoresSingleLeakage[targetOffset]
    end
  end
end

function getScores(sc::RankData, target::Int, leakage::Int)
  return sc.scores[leakage][target]
end

function getScores(sc::RankData, target::Int)
  return sc.combinedScores[target]
end

function getRoundKey(params::DpaAttack, attack::Attack, phase::Int, sc::RankData)
  return map(x -> UInt8(sortperm(getScores(sc,x), rev=true)[1] - 1), 1:sc.nrTargets)
end

# print the scores pretty
function printScores(params::DpaAttack, phase::Int, rankData::RankData, numberOfTraces::Int, numberOfRows::Int, keyOffsets::Vector{Int}, printsubs=false,  max=5, io=STDOUT) 
  nrLeakageFunctions = length(rankData)
  keyLength = length(keyOffsets)
  winners = zeros(UInt8, keyLength)
  phaseDataOffset = offset(params,phase)
  phaseDataLength = numberOfTargets(params, phase)
  correctRoundKeymaterial = params.correctKeyMaterial[phaseDataOffset+1:phaseDataOffset+phaseDataLength]
  print(io, "Results @ $numberOfRows rows ($numberOfTraces traces consumed)\n")

  targets = getTargetOffsets(params, phase)

  for j in 1:length(keyOffsets)
    kbOffset = targets[keyOffsets[j]]
    corrvalsPerCand = getScores(rankData, keyOffsets[j])

    # sort peaks
    indexes = sortperm(corrvalsPerCand, rev=true)

    winners[j] = indexes[1] - 1

    @printf(io, "target: %d, phase: %d, \"%s\"\n", kbOffset, phase, getTarget(params, phase, kbOffset))

    printableIndexes = indexes[1:max]
    if length(correctRoundKeymaterial) > 0
      correctKbOffset = findfirst(x -> x == (correctRoundKeymaterial[kbOffset] + 1), indexes)
      if correctKbOffset > max
        printableIndexes = [ indexes[1:max-1] ; correctRoundKeymaterial[kbOffset] + 1]
      end
    end
    
    # print top 5 peaks
    # for known key scenario: print top 5 if it includes the correct key byte, top 4 and the correct key byte otherwise
    for i in printableIndexes
      cand = i - 1
      peak = corrvalsPerCand[i]
      rank = findfirst(x -> x == i, indexes)

      if length(correctRoundKeymaterial) > 0 && cand == correctRoundKeymaterial[kbOffset]
        pretty = "correct  "
      else
        pretty = "candidate"
      end

      if nrLeakageFunctions == 1
        sample = rankData.offsets[1][keyOffsets[j]][i]
        @printf(io, "rank: %3d, %s: 0x%02x, peak: %f @ %d\n", rank, pretty, cand, peak, sample)
      else
        @printf(io, "rank: %3d, %s: 0x%02x, %s of peaks: %f\n", rank, pretty, cand, params.leakageCombinator, peak)
        if printsubs
          # print the max peak for each leakage function
          for l in 1:nrLeakageFunctions
            (lscores, loffsets) = rankData[l]
            sample = loffsets[keyOffsets[j]][i]
            @printf(io, " %0.2f @ %d\n", lscores[keyOffsets[j]][i], sample)
          end
        end
      end
    end
  end

  @printf(io, "recovered key material: %s\n", bytes2hex(winners))

end

type RankEvolutionData
  numberOfTraces
  scores
  combinedScores

  function RankEvolutionData(params::DpaAttack)
    numberOfTraces = Dict{Int, IntSet}()
    combinedScores = Dict{Int, Dict{Int, Matrix{Float64}}}()
    scores = Dict{Int, Dict{Int, Dict{Int, Matrix{Float64}}}}()
    return new(numberOfTraces,scores,combinedScores)
  end
end

function update!(evo::RankEvolutionData, phase::Int, targets::Vector{Int}, ranks::RankData, numberOfTraces::Int)
  if !(phase in keys(evo.numberOfTraces))
    evo.numberOfTraces[phase] = IntSet()
    evo.combinedScores[phase] = Dict{Int, Matrix{Float64}}()
    evo.scores[phase] = Dict{Int, Dict{Int, Matrix{Float64}}}()
  end

  push!(evo.numberOfTraces[phase], numberOfTraces)
  for target in targets
    combinedScores = getScores(ranks, target)
    if !(target in keys(evo.combinedScores[phase]))
      evo.combinedScores[phase][target] = Matrix{Float64}(length(combinedScores),0)
    end
    evo.combinedScores[phase][target] = hcat(evo.combinedScores[phase][target], combinedScores)
    if ranks.nrLeakages > 1
      if !(target in keys(evo.scores[phase]))
        evo.scores[phase][target] = Dict{Int,Matrix{Float64}}()
      end
      for leakage in 1:ranks.nrLeakages
        scores = getScores(ranks, target, leakage)
        if !(leakage in keys(evo.scores[phase][target]))
          evo.scores[phase][target][leakage] = Matrix{Float64}(length(scores),0)
        end
        evo.scores[phase][target][leakage] = hcat(evo.scores[phase][target][leakage], scores)
      end
    end
  end
end

function getPhases(evo::RankEvolutionData)
  return sort(collect(keys(evo.numberOfTraces)))
end

function getTargets(evo::RankEvolutionData, phase::Int)
  return sort(collect(keys(evo.combinedScores[phase])))
end

function getRankings(evo::RankEvolutionData, phase::Int, target::Int, kbval::UInt8)
    (rows,cols) = size(evo.combinedScores[phase][target])
    ranks = map(r -> findfirst(x -> x == kbval + 1, sortperm(evo.combinedScores[phase][target][r,:], rev=true)), 1:cols)
    return ranks
end

function getRankings(evo::RankEvolutionData, phase::Int, target::Int, leakage::Int, kbval::UInt8)
    (rows,cols) = size(evo.scores[phase][target][leakage])
    ranks = map(r -> findfirst(x -> x == kbval + 1, sortperm(evo.scores[phase][target][leakage][r,:], rev=true)), 1:cols)
    return ranks
end

function getScores(evo::RankEvolutionData, phase::Int, target::Int)
  return evo.combinedScores[phase][target]
end  

function getScores(evo::RankEvolutionData, phase::Int, target::Int, kbval::UInt8)
  return evo.combinedScores[phase][target][kbval+1,:]
end

function getScores(evo::RankEvolutionData, phase::Int, target::Int, leakage::Int, kbval::UInt8)
  return evo.scores[phase][target][leakage][kbval+1,:]
end


function getNumberOfTraces(evo::RankEvolutionData, phase::Int)
  return collect(evo.numberOfTraces[phase])
end

function truncate(fname)
    fd = open(fname, "w")
    truncate(fd, 0)
    close(fd)
end

function correctKeyRanks2CSV(params::DpaAttack, evo::RankEvolutionData)
  phases = getPhases(evo)
  correctKeyMaterial = params.correctKeyMaterial

  for phase in phases
    kkaFilename = @sprintf("%s.ranking.phase%02d.csv",get(params.outputkka),phase)
    truncate(kkaFilename)
    isempty = stat(kkaFilename).size == 0

    fd = open(kkaFilename, "a")

    reltargets = getTargets(evo, phase)
    targets = getTargetOffsets(params, phase)

    print(fd, "nr of traces")
    for target in targets
      print(fd, ",target $target rank")
    end
    print(fd, "\n")

    numberOfTraces = getNumberOfTraces(evo,phase)
    
    for r in 1:length(numberOfTraces)
      print(fd, "$(numberOfTraces[r])")
      for target in reltargets
        kbval = correctKeyMaterial[offset(params,phase,targets[target])+1]
        scores = getScores(evo, phase, target)
        @assert size(scores)[2] == length(numberOfTraces)
        rnk = findfirst(x -> x == kbval + 1, sortperm(scores[:,r], rev=true))
        print(fd,",$(rnk)")
      end
      print(fd,"\n")
    end
    close(fd)
  end
end

function add2kka(params::DpaAttack, phase::Int, rankData::RankData, numberOfTraces::Int, numberOfRows::Int, keyOffsets::Vector{Int})
  @assert(!isnull(params.outputkka) && !isnull(params.knownKey))

  phaseDataOffset = offset(params,phase)
  phaseDataLength = numberOfTargets(params, phase)
  correctRoundKeymaterial = params.correctKeyMaterial

  kkaFilename = get(params.outputkka) * "phase$(phase).csv"
  isempty = stat(kkaFilename).size == 0

  fd = open(kkaFilename, "a")

  if isempty
    @printf(fd, "numberOfTraces,numberOfRows")
    for j in 1:length(correctRoundKeymaterial)
      @printf(fd, ",")
      # @printf(fd, "kb%d rank,kb%d value,kb%d score", j,j,j)
      @printf(fd, "kb%d rank", j)
    end
    @printf(fd, "\n")
  end


  @printf(fd, "%d,%d", numberOfTraces, numberOfRows)

  for i in 1:length(correctRoundKeymaterial)
    if i in keyOffsets
      j = findfirst(x -> x == i, keyOffsets)
      scoresPerCand = getScores(rankData, i)
      # sort peaks
      indexesPerCand = sortperm(scoresPerCand, rev=true)
      keybyte = correctRoundKeymaterial[keyOffsets[j]]
      rank = findfirst(x -> x == (keybyte + 1), indexesPerCand)
      score = scoresPerCand[keybyte+1]

      @printf(fd, ",")
      # @printf(fd, "%d,0x%02x,%f", rank, keybyte, score)
      @printf(fd, "%d", rank)
    else
      # @printf(fd,",,,")
      @printf(fd,",")
    end
  end

  @printf(fd, "\n")

  close(fd)
end
