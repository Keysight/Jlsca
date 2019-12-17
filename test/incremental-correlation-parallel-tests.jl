# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Test

using Jlsca.Sca
using Jlsca.Trs
@everywhere using Jlsca.Sca
@everywhere using Jlsca.Trs

function IncrementalCPATest()
    len = 200

    fullfilename = "../aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs"
    print("file: $fullfilename\n")

    direction = FORWARD
    params = getParameters(fullfilename, direction)

    params.analysis = IncrementalCPA()
    params.analysis.leakages = [Bit(0),Bit(7)]

    trs = InspectorTrace(fullfilename)

    rankData1 = sca(trs,params,1, len)
    close(trs)

    params.analysis = CPA()
    params.analysis.leakages = [Bit(0),Bit(7)]
    params.analysis.postProcessor = missing

    trs = InspectorTrace(fullfilename)

    rankData2 = sca(trs,params,1, len)
    close(trs)

    @test getPhases(rankData1) == getPhases(rankData2) == collect(1:numberOfPhases(params.attack))
    for phase in getPhases(rankData1) 
        @test getTargets(rankData1,phase) == getTargets(rankData2,phase) == collect(1:numberOfTargets(params.attack, phase))
        for target in getTargets(rankData1, phase)
            @test getLeakages(rankData1,phase,target) == getLeakages(rankData2,phase,target) == collect(1:numberOfLeakages(params.analysis)) 
            for leakage in getLeakages(rankData1, phase, target)
              @test getScores(rankData1, phase, target, leakage) ≈ getScores(rankData2, phase, target, leakage)
              @test getOffsets(rankData1, phase, target, leakage) == getOffsets(rankData2, phase, target, leakage)
            end
        end
    end
end

function ParallelIncrementalCPATest(splitmode)
    len = 200

    fullfilename = "../aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs"
    print("file: $fullfilename\n")

    direction = FORWARD
    params = getParameters(fullfilename, direction)

    params.analysis = IncrementalCPA()
    params.analysis.leakages = [Bit(0),Bit(7)]

    # forcing a new world, in Julia notebooks just do the
    # @everywhere block creating the function in a different cell,
    # in that case no let required
    let
      @everywhere begin
        trs = InspectorTrace($fullfilename)
        getTrs() = trs
      end
    end

    rankData1 = sca(DistributedTrace(getTrs,splitmode),params,1, len)
    @everywhere close(trs)

    params.analysis = IncrementalCPA()
    params.analysis.leakages = [Bit(0),Bit(7)]

    trs = InspectorTrace(fullfilename)

    rankData2 = sca(trs,params,1, len)
    close(trs)

    @test getPhases(rankData1) == getPhases(rankData2) == collect(1:numberOfPhases(params.attack))
    for phase in getPhases(rankData1) 
        @test getTargets(rankData1,phase) == getTargets(rankData2,phase) == collect(1:numberOfTargets(params.attack, phase))
        for target in getTargets(rankData1, phase)
            @test getLeakages(rankData1,phase,target) == getLeakages(rankData2,phase,target) == collect(1:numberOfLeakages(params.analysis)) 
            for leakage in getLeakages(rankData1, phase, target)
              @test getScores(rankData1, phase, target, leakage) ≈ getScores(rankData2, phase, target, leakage)
              @test getOffsets(rankData1, phase, target, leakage) == getOffsets(rankData2, phase, target, leakage)
            end
        end
    end
end

function ParallelIncrementalCPATestWithInterval(splitmode)
    len = 200
    updateInterval = 49
    numberOfScas = div(len, updateInterval) + ((len % updateInterval) > 0 ? 1 : 0)

    fullfilename = "../aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs"
    print("file: $fullfilename\n")

    direction = FORWARD
    params = getParameters(fullfilename, direction)

    params.analysis = IncrementalCPA()
    params.analysis.leakages = [Bit(0),Bit(7)]
    params.updateInterval = updateInterval
    params.maxCols = 600

    # forcing a new world, in Julia notebooks just do the
    # @everywhere block creating the function in a different cell,
    # in that case no let required
    let
      @everywhere begin
        trs = InspectorTrace($fullfilename)
        getTrs() = trs
      end
    end

    rankData1 = sca(DistributedTrace(getTrs,splitmode),params,1, len)
    @everywhere close(trs)
    params.analysis = IncrementalCPA()
    params.analysis.leakages = [Bit(0),Bit(7)]
    params.updateInterval = missing
    params.maxCols = 588
    rankData2 = Vector{RankData}(undef,numberOfScas)

    for s in 1:numberOfScas
      len2 = min(len, updateInterval*s)
      trs = InspectorTrace(fullfilename)
      
      rankData2[s] = sca(trs,params,1, len2)

      close(trs)
    end

    for s in 1:numberOfScas    
      @test getPhases(rankData1) == getPhases(rankData2[s]) == collect(1:numberOfPhases(params.attack))
      for phase in getPhases(rankData1) 
          @test getTargets(rankData1,phase) == getTargets(rankData2[s],phase) == collect(1:numberOfTargets(params.attack, phase))
          for target in getTargets(rankData1, phase)
            @test getLeakages(rankData1,phase,target) == getLeakages(rankData2[s],phase,target) == collect(1:numberOfLeakages(params.analysis)) 
            for leakage in getLeakages(rankData1, phase, target)
              @test getScoresEvolution(rankData1, phase, target, leakage)[:,s] ≈ getScores(rankData2[s], phase, target, leakage)
              @test getOffsetsEvolution(rankData1, phase, target, leakage)[:,s] == getOffsets(rankData2[s], phase, target, leakage)
            end
          end
      end
    end
end

@assert nworkers() > 1

IncrementalCPATest()

ParallelIncrementalCPATest(SplitByTracesSliced())
ParallelIncrementalCPATest(SplitByTracesBlock())

ParallelIncrementalCPATestWithInterval(SplitByTracesSliced())
ParallelIncrementalCPATestWithInterval(SplitByTracesBlock())
