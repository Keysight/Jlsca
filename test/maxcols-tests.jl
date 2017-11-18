using Jlsca.Sca
using Jlsca.Trs

using Base.Test

function testVanilla()
    rows = 100
    cols = 100
    maxCols = 21

    trs = InMemory(rand(UInt8, rows,16), rand(Float64, 100, cols))

    attack = AesSboxAttack()
    analysis = CPA() 
    params = DpaAttack(attack,analysis)

    rankData1 = sca(trs, params, 1, length(trs))

    params.maxCols = maxCols

    rankData2 = sca(trs, params, 1, length(trs))

    @test getPhases(rankData1) == getPhases(rankData2)
    for phase in getPhases(rankData1) 
        @test getTargets(rankData1,phase) == getTargets(rankData2,phase)
        for target in getTargets(rankData1, phase)
            @test getScores(rankData1, phase, target) ≈ getScores(rankData2, phase, target)
        end
    end
end

function testCondAvg()
    rows = 100
    cols = 100
    maxCols = 21

    trs = InMemory(rand(UInt8, rows,16), rand(Float64, 100, cols))
    setPostProcessor(trs, CondAvg())

    attack = AesSboxAttack()
    analysis = CPA() 
    params = DpaAttack(attack,analysis)

    rankData1 = sca(trs, params, 1, length(trs))

    params.maxCols = maxCols
    params.updateInterval = div(rows,3)

    rankData2 = sca(trs, params, 1, length(trs))

    @test getPhases(rankData1) == getPhases(rankData2)
    for phase in getPhases(rankData1) 
        @test getTargets(rankData1,phase) == getTargets(rankData2,phase)
        for target in getTargets(rankData1, phase)
            @test getScores(rankData1, phase, target) ≈ getScores(rankData2, phase, target)
        end
    end
end

function testIncCpa()
    rows = 100
    cols = 100
    maxCols = 21

    trs = InMemory(rand(UInt8, rows,16), rand(Float64, 100, cols))
    setPostProcessor(trs, IncrementalCorrelation())

    attack = AesSboxAttack()
    analysis = IncrementalCPA() 
    params = DpaAttack(attack,analysis)

    rankData1 = sca(trs, params, 1, length(trs))

    params.maxCols = maxCols
    params.updateInterval = div(rows,3)

    rankData2 = sca(trs, params, 1, length(trs))

    @test getPhases(rankData1) == getPhases(rankData2)
    for phase in getPhases(rankData1) 
        @test getTargets(rankData1,phase) == getTargets(rankData2,phase)
        for target in getTargets(rankData1, phase)
            @test getScores(rankData1, phase, target) ≈ getScores(rankData2, phase, target)
        end
    end
end

testVanilla()
testCondAvg()
testIncCpa()
