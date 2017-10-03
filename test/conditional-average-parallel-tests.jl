# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

# Run: julia -p3 -Lsca.jl <thisfile>

using Base.Test

using Jlsca.Sca
using Jlsca.Trs

function ParallelCondAvgTest(splitmode)
    len = 200

    fullfilename = "../aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs"
    @printf("file: %s\n", fullfilename)

    direction = FORWARD
    params = getParameters(fullfilename, direction)

    params.analysis = CPA()

    # numberOfAverages = numberOfTargets(params.attack, 1)
    # numberOfCandidates = length(guesses(params.attack))

    @everyworker begin
      using Jlsca.Trs
      trs = InspectorTrace($fullfilename)
      if $splitmode == 1
        setPostProcessor(trs, CondAvg(SplitByTracesSliced()))
      elseif $splitmode == 2
        setPostProcessor(trs, CondAvg(SplitByTracesBlock()))
      # elseif $splitmode == 3
      #   setPostProcessor(trs, CondAvg(SplitByData($numberOfAverages, $numberOfCandidates)))
      end
    end

    sando = Vector{Sca.ScoresAndOffsets}(2)
    sandoIdx = 1

    cb::Function = (phase,params,scoresAndOffsets,dataWidth,keyOffsets,numberOfTraces2) -> (sando[sandoIdx] = deepcopy(scoresAndOffsets); sandoIdx += 1)

    key = sca(DistributedTrace(),params,1, len, false, Nullable{Function}(cb))

    @test(key == get(params.knownKey))

    params.analysis = CPA()

    trs = InspectorTrace(fullfilename)
    setPostProcessor(trs, CondAvg(NoSplit()))

    key = sca(trs,params,1, len, false, Nullable{Function}(cb))

    @test(key == get(params.knownKey))

    @test sandoIdx == 3
    @test sando[1].nrTargets == sando[2].nrTargets
    @test sando[1].nrLeakages == sando[2].nrLeakages
    nrTargets = sando[1].nrTargets
    nrLeakages = sando[1].nrLeakages

    for l in 1:nrLeakages
      for t in 1:nrTargets
        @test sando[1].scores[l][t] ≈ sando[2].scores[l][t]
        @test sando[1].offsets[l][t] == sando[2].offsets[l][t]
      end
    end
end

function ParallelCondAvgTestWithInterval()
    len = 200
    updateInterval = 49

    fullfilename = "../aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs"
    @printf("file: %s\n", fullfilename)

    direction = FORWARD
    params = getParameters(fullfilename, direction)

    params.analysis = CPA()
    params.updateInterval = Nullable(updateInterval)

    # numberOfAverages = numberOfTargets(params.attack, 1)
    # numberOfCandidates = length(guesses(params.attack))

    @everyworker begin
      using Jlsca.Trs
      trs = InspectorTrace($fullfilename)
      setPostProcessor(trs, CondAvg(SplitByTracesSliced()))
    end

    numberOfScas = div(len, updateInterval) + ((len % updateInterval) > 0 ? 1 : 0)
    sando = Vector{Sca.ScoresAndOffsets}(numberOfScas*2)
    sandoIdx = 1

    cb::Function = (phase,params,scoresAndOffsets,dataWidth,keyOffsets,numberOfTraces2) -> (sando[sandoIdx] = deepcopy(scoresAndOffsets); sandoIdx += 1)

    key = sca(DistributedTrace(),params,1, len, false, Nullable{Function}(cb))

    @test(key == get(params.knownKey))

    params.analysis = CPA()
    params.analysis.leakages = [HW()]
    params.updateInterval = Nullable()

    for s in 1:numberOfScas
      len2 = min(len, updateInterval*s)

      trs = InspectorTrace(fullfilename)
      setPostProcessor(trs, CondAvg(NoSplit()))

      key = sca(trs,params,1, len2, false, Nullable{Function}(cb))

      @test(key == get(params.knownKey))
    end

    @test sandoIdx == numberOfScas*2+1
    
    for s in 1:numberOfScas
      @test sando[s].nrTargets == sando[s+numberOfScas].nrTargets
      @test sando[s].nrLeakages == sando[s+numberOfScas].nrLeakages
      nrTargets = sando[s].nrTargets
      nrLeakages = sando[s].nrLeakages

      for l in 1:nrLeakages
        for t in 1:nrTargets
          @test sando[s].scores[l][t] ≈ sando[s+numberOfScas].scores[l][t]
          @test sando[s].offsets[l][t] == sando[s+numberOfScas].offsets[l][t]
        end
      end
    end
end


@assert nworkers() > 1

ParallelCondAvgTest(1)
ParallelCondAvgTest(2)
# ParallelCondAvgTest(3)

ParallelCondAvgTestWithInterval()
