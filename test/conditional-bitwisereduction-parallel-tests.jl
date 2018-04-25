# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

@everywhere using Jlsca.Sca
@everywhere using Jlsca.Trs

function ParallelCondReduceTest(splitmode)
    len = 200

    fullfilename = "../aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs"
    @printf("file: %s\n", fullfilename)

    direction = FORWARD
    params = getParameters(fullfilename, direction)

    params.analysis = CPA()
    params.analysis.leakages = [Bit(0)]

    @everywhere begin
      trs = InspectorTrace($fullfilename, true)
      addSamplePass(trs, BitPass())
      if $splitmode == 1
        setPostProcessor(trs, CondReduce(SplitByTracesSliced()))
      elseif $splitmode == 2
        setPostProcessor(trs, CondReduce(SplitByTracesBlock()))
      end
    end

    rankData1 = sca(DistributedTrace(),params,1, len)

    params.analysis = CPA()
    params.analysis.leakages = [Bit(0)]

    trs = InspectorTrace(fullfilename, true)
    addSamplePass(trs, BitPass())
    setPostProcessor(trs, CondReduce())

    rankData2 = sca(trs,params,1, len)

    @test getPhases(rankData1) == getPhases(rankData2) == collect(1:numberOfPhases(params.attack))
    for phase in getPhases(rankData1) 
        @test getTargets(rankData1,phase) == getTargets(rankData2,phase) == collect(1:numberOfTargets(params.attack, phase))
        for target in getTargets(rankData1, phase)
            @test getLeakages(rankData1,phase,target) == getLeakages(rankData2,phase,target) == collect(1:numberOfLeakages(params.analysis)) 
            for leakage in getLeakages(rankData1, phase, target)
              @test getScores(rankData1, phase, target, leakage) ≈ getScores(rankData2, phase, target, leakage)
              # FIXME (not critical, but annoying) 
              # @test getOffsets(rankData1, phase, target, leakage) == getOffsets(rankData2, phase, target, leakage)
            end
        end
    end
end


function ParallelCondReduceTestWithInterval(splitmode)
    len = 200
    updateInterval = 49
    numberOfScas = div(len, updateInterval) + ((len % updateInterval) > 0 ? 1 : 0)

    fullfilename = "../aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs"
    @printf("file: %s\n", fullfilename)

    direction = FORWARD
    params = getParameters(fullfilename, direction)

    params.analysis = CPA()
    params.analysis.leakages = [Bit(0)]
    params.updateInterval = Nullable(updateInterval)
    params.maxCols = 512

    @everywhere begin
      trs = InspectorTrace($fullfilename, true)
      addSamplePass(trs, BitPass())
      if $splitmode == 1
        setPostProcessor(trs, CondReduce(SplitByTracesSliced()))
      elseif $splitmode == 2
        setPostProcessor(trs, CondReduce(SplitByTracesBlock()))
      end
    end

    rankData1 = sca(DistributedTrace(),params,1, len)
    rankData2 = Vector{RankData}(numberOfScas)

    params.analysis = CPA()
    params.analysis.leakages = [Bit(0)]
    params.updateInterval = Nullable()
    params.maxCols = 448

    for s in 1:numberOfScas
      len2 = min(len, updateInterval*s)

      trs = InspectorTrace(fullfilename,true)
      addSamplePass(trs, BitPass())
      setPostProcessor(trs, CondReduce())

      rankData2[s] = sca(trs,params,1, len2)
    end

    for s in 1:numberOfScas    
      @test getPhases(rankData1) == getPhases(rankData2[s]) == collect(1:numberOfPhases(params.attack))
      for phase in getPhases(rankData1) 
          @test getTargets(rankData1,phase) == getTargets(rankData2[s],phase) == collect(1:numberOfTargets(params.attack, phase))
          for target in getTargets(rankData1, phase)
            @test getLeakages(rankData1,phase,target) == getLeakages(rankData2[s],phase,target) == collect(1:numberOfLeakages(params.analysis)) 
            for leakage in getLeakages(rankData1, phase, target)
              @test getScoresEvolution(rankData1, phase, target, leakage)[:,s] ≈ getScores(rankData2[s], phase, target, leakage)
              # FIXME (not critical, but annoying) 
              # @test getOffsetsEvolution(rankData1, phase, target, leakage)[:,s] == getOffsets(rankData2[s], phase, target, leakage)
            end
          end
      end
    end

end

@assert nworkers() > 1

ParallelCondReduceTest(1)
ParallelCondReduceTest(2)

ParallelCondReduceTestWithInterval(1)
ParallelCondReduceTestWithInterval(2)

