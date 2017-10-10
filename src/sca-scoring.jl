# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export sampleDeviationPreprocessor
export getScoresAndOffsets,getCombinedScores
export add2kka
export printScores
export getRoundKey

import Base.get
import Base.truncate

type ScoresAndOffsets 
  # per leakage, per target, scores for all kbvals
  scores::Vector{Vector{Vector{Float64}}}
  # per leakage, per target, offsets for all scores
  offsets::Vector{Vector{Vector{Int}}}
  nrTargets::Int
  nrLeakages::Int

  function ScoresAndOffsets(params::DpaAttack, phase::Int)

    nrLeakageFunctions = getNrLeakageFunctions(params.analysis)
    scores = Vector{Vector{Vector{Float64}}}(nrLeakageFunctions)
    offsets = Vector{Vector{Vector{Int}}}(nrLeakageFunctions)

    targetOffsets = getTargetOffsets(params, phase)
    nrTargets = length(targetOffsets)

    for l in 1:nrLeakageFunctions
      scores[l] = Vector{Vector{Float64}}(nrTargets)
      offsets[l] = Vector{Vector{Int}}(nrTargets)
      for t in 1:nrTargets
        kbvalsLen = length(guesses(getTarget(params, phase, targetOffsets[t])))
        scores[l][t] = zeros(Float64, kbvalsLen)
        offsets[l][t] = zeros(Int, kbvalsLen)
      end
    end

    return new(scores,offsets,nrTargets,nrLeakageFunctions)
  end
end

length(sc::ScoresAndOffsets) = length(sc.scores)
getindex(sc::ScoresAndOffsets, i::Int) = (sc.scores[i], sc.offsets[i])

function clearScoresAndOffsets!(sc::ScoresAndOffsets)
  for i in 1:length(sc)
    (scores,offsets) = sc[i]
    for j in 1:length(scores)
      scores[j] .= 0
      offsets[j] .= 0
    end
  end
end

function updateScoresAndOffsets!(a::GlobalMaximization, sc::ScoresAndOffsets, C::AbstractArray{Float64,2}, leakageIdx::Int, targetOffset::Int)

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

function updateScoresAndOffsets!(a::NormalizedMaximization, sc::ScoresAndOffsets, C::AbstractArray{Float64,2}, leakageIdx::Int, targetOffset::Int)

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

function getScores(a::Sum, params::DpaAttack, sc::ScoresAndOffsets, targetOffet::Int)
  scores = zeros(sc.scores[1][targetOffet])

  for i in 1:length(sc)
    (scoresSingleLeakage,offsetsSingleLeakage) = sc[i]
    scores = scores .+ scoresSingleLeakage[targetOffet]
  end

  return scores
end

function getRoundKey(params::DpaAttack, attack::Attack, phase::Int, sc::ScoresAndOffsets)
  return map(x -> UInt8(sortperm(getScores(params.leakageCombinator,params,sc,x), rev=true)[1] - 1), 1:sc.nrTargets)
end

# print the scores pretty
function printScores(params::DpaAttack, phase::Int, scoresAndOffsets::ScoresAndOffsets, numberOfTraces, keyOffsets, prettyKeyOffsets, printsubs=false,  max=5, io=STDOUT)
  
  nrLeakageFunctions = length(scoresAndOffsets)
  keyLength = length(keyOffsets)
  winners = zeros(UInt8, keyLength)
  phaseDataOffset = phase > 1 ? sum(x -> numberOfTargets(params, x), 1:phase-1) : 0
  phaseDataLength = numberOfTargets(params, phase)
  correctRoundKeymaterial = !isnull(params.knownKey) ? correctKeyMaterial(params.attack, get(params.knownKey))[phaseDataOffset+1:phaseDataOffset+phaseDataLength] : Vector{UInt8}(0)
  @printf(io, "Results @ %d rows\n", numberOfTraces)

  for j in 1:keyLength
    kbOffset = keyOffsets[j]
    corrvalsPerCand = getScores(params.leakageCombinator, params, scoresAndOffsets, kbOffset)

    # sort peaks
    indexes = sortperm(vec(corrvalsPerCand), rev=true)

    winners[j] = indexes[1] - 1

    @printf(io, "kb: %d\n", prettyKeyOffsets[kbOffset] )

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
        sample = scoresAndOffsets.offsets[1][kbOffset][i]
        @printf(io, "rank: %3d, %s: 0x%02x, peak: %f @ %d\n", rank, pretty, cand, peak, sample)
      else
        @printf(io, "rank: %3d, %s: 0x%02x, %s of peaks: %f\n", rank, pretty, cand, params.leakageCombinator, peak)
        if printsubs
          # print the max peak for each leakage function
          for l in 1:nrLeakageFunctions
            (lscores, loffsets) = scoresAndOffsets[l]
            sample = loffsets[kbOffset][i]
            @printf(io, " %0.2f @ %d\n", lscores[kbOffset][i], sample)
          end
        end
      end
    end
  end

  @printf(io, "recovered key material: %s\n", bytes2hex(winners))

end

function truncate(fname)
    fd = open(fname, "w")
    truncate(fd, 0)
    close(fd)
end

function add2kka(scoresAndOffsets::Vector{Tuple{Matrix{Float64}, Matrix{UInt}}}, keyOffsets, numberOfTraces, correctRoundKeymaterial::Vector{UInt8}, fdorstring::Union{IO,AbstractString},  leakageFunctionsCombinator=(+))
  local fd

  if isa(fdorstring,AbstractString)
    isempty = stat(fdorstring).size == 0

    fd = open(fdorstring, "a")

    if isempty
      @printf(fd, "#traces")
      for j in 1:length(correctRoundKeymaterial)
        @printf(fd, ",")
        # @printf(fd, "kb%d rank,kb%d value,kb%d score", j,j,j)
        @printf(fd, "kb%d rank", j)
      end
      @printf(fd, "\n")
    end
  else
    fd = fdorstring
  end

  scores = getCombinedScores(scoresAndOffsets, leakageFunctionsCombinator)

  @printf(fd, "%d", numberOfTraces)
  for i in 1:length(correctRoundKeymaterial)
    if i in keyOffsets
      j = findfirst(x -> x == i, keyOffsets)
      scoresPerCand = vec(scores[:,j])

      # sort peaks
      indexesPerCand = sortperm(vec(scoresPerCand), rev=true)
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

  if isa(fdorstring,AbstractString)
    close(fd)
  end

end
