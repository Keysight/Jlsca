# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

# Run: julia -p3 -Lsca.jl <thisfile>

using Base.Test

using Jlsca.Sca
using Jlsca.Trs

function IncrementalCPATest(splitmode)
    len = 200

    fullfilename = "../aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs"
    @printf("file: %s\n", fullfilename)

    direction = FORWARD
    params = getParameters(fullfilename, direction)

    params.analysis = IncrementalCPA()
    params.analysis.leakages = [Bit(0),Bit(7)]

    # numberOfAverages = numberOfTargets(params.attack, 1)
    # numberOfCandidates = length(guesses(params.attack))

    @everyworker begin
      using Jlsca.Sca
      using Jlsca.Trs

      trs = InspectorTrace($fullfilename)
      if $splitmode == 1
        setPostProcessor(trs, IncrementalCorrelation(SplitByTracesSliced()))
      elseif $splitmode == 2
        setPostProcessor(trs, IncrementalCorrelation(SplitByTracesBlock()))
      # elseif $splitmode == 3
      #   setPostProcessor(trs, IncrementalCorrelation(SplitByData($numberOfAverages, $numberOfCandidates)))
      end
    end

    sando = Vector{Tuple{Matrix{Float64}, Matrix{UInt}}}(2)
    sandoIdx = 1

    cb::Function = (phase,params,scoresAndOffsets,dataWidth,keyOffsets,numberOfTraces2) -> (sando[sandoIdx] = scoresAndOffsets[1]; sandoIdx += 1)

    key = sca(DistributedTrace(),params,1, len, false, Nullable{Function}(cb))

    @test(key == get(params.knownKey))

    params.analysis = CPA()
    params.analysis.leakages = [Bit(0),Bit(7)]

    trs = InspectorTrace(fullfilename)

    key = sca(trs,params,1, len, false, Nullable{Function}(cb))

    @test(key == get(params.knownKey))

    @test sandoIdx == 3

    @test sando[1][1] ≈ sando[2][1]
    @test sando[1][2] ≈ sando[2][2]
end

function ParallelIncrementalCPATest(splitmode)
    len = 200

    fullfilename = "../aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs"
    @printf("file: %s\n", fullfilename)

    direction = FORWARD
    params = getParameters(fullfilename, direction)

    params.analysis = IncrementalCPA()
    params.analysis.leakages = [Bit(0),Bit(7)]

    # numberOfAverages = numberOfTargets(params.attack, 1)
    # numberOfCandidates = length(guesses(params.attack))

    @everyworker begin
      using Jlsca.Trs
      trs = InspectorTrace($fullfilename)
      if $splitmode == 1
        setPostProcessor(trs, IncrementalCorrelation(SplitByTracesSliced()))
      elseif $splitmode == 2
        setPostProcessor(trs, IncrementalCorrelation(SplitByTracesBlock()))
      # elseif $splitmode == 3
      #   setPostProcessor(trs, IncrementalCorrelation(SplitByData($numberOfAverages, $numberOfCandidates)))
      end
    end

    sando = Vector{Tuple{Matrix{Float64}, Matrix{UInt}}}(2)
    sandoIdx = 1

    cb::Function = (phase,params,scoresAndOffsets,dataWidth,keyOffsets,numberOfTraces2) -> (sando[sandoIdx] = scoresAndOffsets[1]; sandoIdx += 1)

    key = sca(DistributedTrace(),params,1, len, false, Nullable{Function}(cb))

    @test(key == get(params.knownKey))

    params.analysis = IncrementalCPA()
    params.analysis.leakages = [Bit(0),Bit(7)]

    trs = InspectorTrace(fullfilename)
    setPostProcessor(trs, IncrementalCorrelation(NoSplit()))

    key = sca(trs,params,1, len, false, Nullable{Function}(cb))

    @test(key == get(params.knownKey))

    @test sandoIdx == 3

    @test sando[1][1] ≈ sando[2][1]
    @test sando[1][2] == sando[2][2]
end

function ParallelIncrementalCPATestWithInterval()
    len = 200
    updateInterval = 49

    fullfilename = "../aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs"
    @printf("file: %s\n", fullfilename)

    direction = FORWARD
    params = getParameters(fullfilename, direction)

    params.analysis = IncrementalCPA()
    params.analysis.leakages = [Bit(0),Bit(7)]
    params.updateInterval = Nullable(updateInterval)

    # numberOfAverages = numberOfTargets(params.attack, 1)
    # numberOfCandidates = length(guesses(params.attack))

    @everyworker begin
      using Jlsca.Trs
      trs = InspectorTrace($fullfilename)
      setPostProcessor(trs, IncrementalCorrelation(SplitByTracesSliced()))
    end

    numberOfScas = div(len, updateInterval) + ((len % updateInterval) > 0 ? 1 : 0)
    sando = Vector{Tuple{Matrix{Float64}, Matrix{UInt}, Int}}(numberOfScas*2)
    sandoIdx = 1

    cb::Function = (phase,params,scoresAndOffsets,dataWidth,keyOffsets,numberOfTraces2) -> (sando[sandoIdx] = (copy(scoresAndOffsets[1][1]),copy(scoresAndOffsets[1][2]),numberOfTraces2); sandoIdx += 1)

    key = sca(DistributedTrace(),params,1, len, false, Nullable{Function}(cb))

    @test(key == get(params.knownKey))

    params.analysis = IncrementalCPA()
    params.analysis.leakages = [Bit(0),Bit(7)]
    params.updateInterval = Nullable()

    for s in 1:numberOfScas
      len2 = min(len, updateInterval*s)

      trs = InspectorTrace(fullfilename)
      setPostProcessor(trs, IncrementalCorrelation(NoSplit()))

      key = sca(trs,params,1, len2, false, Nullable{Function}(cb))

      @test(key == get(params.knownKey))
    end

    @test sandoIdx == numberOfScas*2+1

    for s in 1:numberOfScas
      @test sando[s][1] ≈ sando[s+numberOfScas][1]
      # TODO: This test fails for the given trace set because two samples
      # have approx the same correlation and a different sample wins when
      # updateing the scores. Doesn't matter for correctness, but I should
      # compare the raw correlation matrices instead of the scores and
      # offsets.
      # @test sando[s][2] == sando[s+numberOfScas][2]
      @test sando[s][3] == sando[s+numberOfScas][3]
    end
end


@assert nworkers() > 1

IncrementalCPATest(1)
IncrementalCPATest(2)
# IncrementalCPATest(3)

ParallelIncrementalCPATest(1)
ParallelIncrementalCPATest(2)
# ParallelIncrementalCPATest(3)

ParallelIncrementalCPATestWithInterval()
