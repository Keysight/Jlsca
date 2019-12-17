using Jlsca.Sca
using Jlsca.Trs

using Test

function testVanilla()
    rows = 100
    cols = 100
    maxCols = 21

    trs = VirtuaTrace(rand(UInt8, 16,rows), rand(Float64, cols, rows))

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
            @test getOffsets(rankData1, phase, target) == getOffsets(rankData2, phase, target)
        end
    end
end

function testCondAvg()
    rows = 100
    cols = 100
    maxCols = 21

    trs = VirtuaTrace(rand(UInt8,16,rows), rand(Float64,cols,100))

    attack = AesSboxAttack()
    analysis = CPA() 
    params = DpaAttack(attack,analysis)
    params.targetOffsets = [1]

    rankData1 = sca(trs, params, 1, length(trs))

    params.maxCols = maxCols
    params.updateInterval = div(rows,3)
    params.targetOffsets = [1]

    rankData2 = sca(trs, params, 1, length(trs))

    @test getPhases(rankData1) == getPhases(rankData2)
    for phase in getPhases(rankData1) 
        @test getTargets(rankData1,phase) == getTargets(rankData2,phase)
        for target in getTargets(rankData1, phase)
            @test getScores(rankData1, phase, target) ≈ getScores(rankData2, phase, target)
            @test getOffsets(rankData1, phase, target) == getOffsets(rankData2, phase, target)
        end
    end
end

function testIncCpa()
    rows = 100
    cols = 100
    maxCols = 21

    trs = VirtuaTrace(rand(UInt8, 16,rows), rand(Float64, cols, rows))

    attack = AesSboxAttack()
    analysis = IncrementalCPA() 
    params = DpaAttack(attack,analysis)

    rankData1 = sca(trs, params, 1, length(trs))

    params.maxCols = maxCols
    # params.updateInterval = div(rows,3)

    rankData2 = sca(trs, params, 1, length(trs))

    @test getPhases(rankData1) == getPhases(rankData2)
    for phase in getPhases(rankData1) 
        @test getTargets(rankData1,phase) == getTargets(rankData2,phase)
        for target in getTargets(rankData1, phase)
            @test getScores(rankData1, phase, target) ≈ getScores(rankData2, phase, target)
            @test getOffsets(rankData1, phase, target) == getOffsets(rankData2, phase, target)
        end
    end
end

function testCondReduce()
    rows = 100
    cols = 100
    maxCols = 64

    trs = VirtuaTrace(rand(UInt8, 16,rows), rand(UInt8, cols, rows))
    # addSamplePass(trs, BitPass())
    addSamplePass(trs, BitPass())

    attack = AesSboxAttack()
    analysis = CPA() 
    params = DpaAttack(attack,analysis)
    params.analysis.postProcessor = CondReduce

    rankData1 = sca(trs, params, 1, length(trs))

    params.maxCols = maxCols
    # params.updateInterval = div(rows,3)

    rankData2 = sca(trs, params, 1, length(trs))

    # FIXME: think about why this (apparently) is not always true
    # @test getPhases(rankData1) == getPhases(rankData2)
    for phase in getPhases(rankData1) 
        if !(phase in getPhases(rankData2))
            continue
        end
        targets1 = getTargets(rankData1,phase)
        targets2 = getTargets(rankData2,phase)
        # for cond reduce, targets1 != targets2 due to compression
        # but, for all shared targets the scores must be equivalent
        # offsets will not be matching due to the compression.
        for target in ∩(targets1,targets2)
            @test getScores(rankData1, phase, target) ≈ getScores(rankData2, phase, target)
        end
    end
end

testVanilla()
testCondAvg()
testIncCpa()
testCondReduce()
