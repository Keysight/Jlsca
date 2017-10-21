# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

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

    @everyworker begin
      using Jlsca.Trs
      trs = InspectorTrace($fullfilename)
      if $splitmode == 1
        setPostProcessor(trs, CondAvg(SplitByTracesSliced()))
      elseif $splitmode == 2
        setPostProcessor(trs, CondAvg(SplitByTracesBlock()))
      end
    end

    sando = Vector{Matrix{Float64}}(totalNumberOfTargets(params.attack) * 2)
    sandoIdx = 1

    cb::Function = (phase,target,leakage,corr) -> (sando[sandoIdx] = Matrix{Float64}(size(corr)); sando[sandoIdx] .= corr; sandoIdx += 1)
    params.scoresCallBack = cb

    key = sca(DistributedTrace(),params,1, len)

    @test(key == get(params.knownKey))

    params.analysis = CPA()

    trs = InspectorTrace(fullfilename)
    setPostProcessor(trs, CondAvg())

    key = sca(trs,params,1, len)

    @test(key == get(params.knownKey))

    @test sandoIdx == length(sando) + 1
    for i in 1:totalNumberOfTargets(params.attack)
        @test sando[i] ≈ sando[i+totalNumberOfTargets(params.attack)]
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

    @everyworker begin
      using Jlsca.Trs
      trs = InspectorTrace($fullfilename)
      setPostProcessor(trs, CondAvg(SplitByTracesSliced()))
    end

    numberOfScas = div(len, updateInterval) + ((len % updateInterval) > 0 ? 1 : 0)
    sando = Vector{Matrix{Float64}}(totalNumberOfTargets(params.attack) * numberOfScas * 2)
    sandoIdx = 1

    cb::Function = (phase,target,leakage,corr) -> (sando[sandoIdx] = Matrix{Float64}(size(corr)); sando[sandoIdx] .= corr; sandoIdx += 1)
    params.scoresCallBack = cb

    key = sca(DistributedTrace(),params,1, len)

    @test(key == get(params.knownKey))

    params.analysis = CPA()
    params.analysis.leakages = [HW()]
    params.updateInterval = Nullable()

    for s in 1:numberOfScas
      len2 = min(len, updateInterval*s)

      trs = InspectorTrace(fullfilename)
      setPostProcessor(trs, CondAvg())

      key = sca(trs,params,1, len2)

      @test(key == get(params.knownKey))
    end

    @test sandoIdx == length(sando) + 1
    for i in 1:totalNumberOfTargets(params.attack)
        @test sando[i] ≈ sando[i+totalNumberOfTargets(params.attack)*numberOfScas]
    end

end


@assert nworkers() > 1

ParallelCondAvgTest(1)
ParallelCondAvgTest(2)
# ParallelCondAvgTest(3)

ParallelCondAvgTestWithInterval()
