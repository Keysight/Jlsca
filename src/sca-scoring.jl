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

function allocateScoresAndOffsets(nrLeakageFunctions::Int, nrKeyChunkValues::Int, keyLength::Int)
  scoresAndOffsets = Vector{Tuple{Matrix{Float64}, Matrix{UInt}}}(nrLeakageFunctions)

  for i in 1:length(scoresAndOffsets)
    scoresAndOffsets[i] = (zeros(Float64, nrKeyChunkValues, keyLength), zeros(UInt, nrKeyChunkValues, keyLength))
  end

  return scoresAndOffsets
end

function clearScoresAndOffsets!(scoresAndOffsets::Vector{Tuple{Matrix{Float64}, Matrix{UInt}}})  
  for i in 1:length(scoresAndOffsets)
    scoresAndOffsets[i][1] .= 0
    scoresAndOffsets[i][2] .= 0
  end
end

# the scoring function returns two vectors of matrices, one with scores matrices, one with offet matrices into the samples, for each leakage function
function updateScoresAndOffsets!(scoresAndOffsets::Vector{Tuple{Matrix{Float64}, Matrix{UInt}}}, C::Matrix{Float64}, keyIdxIntoC::Int, keyIdxIntoScores::Int, nrLeakageFunctions::Int, nrKeyChunkValues::Int=256)
  (rc, cc) = size(C)

  for l in 1:nrLeakageFunctions
    # max per column for each leakage function for given key byte idx
    (scores, offsets) = scoresAndOffsets[l]

    lower = (keyIdxIntoC-1)*nrLeakageFunctions*nrKeyChunkValues + (l-1)*nrKeyChunkValues  + 1
    upper = lower+nrKeyChunkValues-1
    (corrvals, corrvaloffsets) = findmax(C[:,lower:upper], 1)

    for (idx,val) in enumerate(corrvals)
      if val > scores[:,keyIdxIntoScores][idx]
        scores[idx,keyIdxIntoScores] = val
        offsets[idx,keyIdxIntoScores] = ind2sub(size(C), corrvaloffsets[idx])[1]
      end
    end
  end

  return scoresAndOffsets
end

# combine the leakages contributing to a single candidate
function getCombinedScores(scoresAndOffsets::Vector{Tuple{Matrix{Float64}, Matrix{UInt}}}, leakageFunctionsCombinator::Function=(+))
  scores = zeros(scoresAndOffsets[1][1])

  for (scoresSingleLeakage,offsetsSingleLeakage) in scoresAndOffsets
    scores = leakageFunctionsCombinator(scores, scoresSingleLeakage)
  end

  return scores
end

# get a round key from the scores
function getRoundKey(params::DpaAttack, attack::Attack, phase::Int, scores::Matrix{Float64})
  return vec(mapslices(x -> UInt8(sortperm(x, rev=true)[1] - 1), scores, 1))
end

# # get a round key from the scores per leakage function by recombining them first
# function getRoundKey(scoresAndOffsets::Vector{Tuple{Matrix{Float64}, Matrix{UInt}}}, leakageFunctionsCombinator=(+))
#   scores = getCombinedScores(scoresAndOffsets, leakageFunctionsCombinator)

#   return getRoundKey(scores)
# end

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

# print the scores pretty
function printScores(params::DpaAttack, phase::Int, scoresAndOffsets::Vector{Tuple{Matrix{Float64}, Matrix{UInt}}}, numberOfTraces, keyOffsets, prettyKeyOffsets, leakageFunctionsCombinator=(+), printsubs=false,  max=5, io=STDOUT)
  # FIXME: leakageFunctionsCombinator should be in attack params.
  scores = getCombinedScores(scoresAndOffsets, leakageFunctionsCombinator)

  nrLeakageFunctions = length(scoresAndOffsets)
  keyLength = length(keyOffsets)
  winners = zeros(UInt8, keyLength)
  phaseDataOffset = phase > 1 ? sum(x -> numberOfTargets(params.attack, x), 1:phase-1) : 1
  phaseDataLength = numberOfTargets(params.attack, phase)
  correctRoundKeymaterial = !isnull(params.knownKey) ? correctKeyMaterial(params.attack, get(params.knownKey))[phaseDataOffset+1:phaseDataOffset+phaseDataLength] : Vector{UInt8}(0)
  @printf(io, "Results @ %d rows\n", numberOfTraces)

  for j in 1:keyLength
    kbOffset = keyOffsets[j]
    corrvalsPerCand = vec(scores[:,kbOffset])

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
        sample = scoresAndOffsets[1][2][i,kbOffset]
        @printf(io, "rank: %3d, %s: 0x%02x, peak: %f @ %d\n", rank, pretty, cand, peak, sample)
      else
        @printf(io, "rank: %3d, %s: 0x%02x, %s of peaks: %f\n", rank, pretty, cand, string(leakageFunctionsCombinator), peak)
        if printsubs
          # print the max peak for each leakage function
          for l in 1:nrLeakageFunctions
            (lscores, loffsets) = scoresAndOffsets[l]
            sample = loffsets[i,kbOffset]
            @printf(io, " %0.2f @ %d\n", lscores[i,kbOffset], sample)
          end
        end
      end
    end
  end

  @printf(io, "recovered key material: %s\n", bytes2hex(winners))

end
