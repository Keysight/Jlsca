
# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using RecipesBase

export PlotScoresEvolution

"""
Plots the evolution of scores for a given sca result, parameter set, phase and target.

# Example
Plot the score evolution for phase 1, target 2
```
using Plots

params.knownKey = hex2bytes("00112233445566778899aabbccddeeff")
rankdata = sca(trs,params)

plot(PlotScoresEvolution(),rankdata,params,1,2)
```
If you don't know the key and params.knownKey is not set (or set to Nullable()), this plot will show you the evolution of the 5 highest ranked key candidates.
```
params.knownKey = Nullable()
plot(PlotScoresEvolution(),rankdata,params,1,2)
```    

"""
struct PlotScoresEvolution end

@recipe function f(::PlotScoresEvolution, rankdata::RankData, params, phase, target, combined=true, leakage=1)
    xrows = getNrConsumedRowsEvolution(rankdata,phase)
    if combined
        scores = getScoresEvolution(rankdata, phase, target)
    else
        scores = getScoresEvolution(rankdata, phase, target, leakage)
    end
    cands = size(scores)[1]
    
    if !isnull(params.knownKey) 
        kb = getCorrectKey(params,phase,target)
        color := reshape([x == kb + 1 ? :red : :grey for x in 1:cands],(1,cands))
        label := reshape([x == kb + 1 ? "correct" : x == kb + 2 ? "incorrect" : "" for x in 1:cands],(1,cands))
    else
        if combined
            finalscores = getScores(rankdata, phase, target)
        else
            finalscores = getScores(rankdata, phase, target, leakage)
        end
        ranked = sortperm(finalscores, rev=true)[1:5]
        color := reshape([x in ranked ? :auto : :grey for x in 1:cands],(1,cands))
        label := reshape([x in ranked ? "0x$(hex(x-1))" : "" for x in 1:cands],(1,cands))
    end
    ylabel := (rankdata.nrLeakages > 1 && combined ? "$(params.leakageCombinator) of scores" : "scores")
    xlabel := "#traces"
    title := "score evolution phase $phase, target $target"
    xrows,scores'
end

export PlotRanksEvolution

"""
Plots the evolution of the rank of the correct key bytes for all phases and targets. You need to know the key to use this plot.

# Example

```
using Plots

params.knownKey = hex2bytes("00112233445566778899aabbccddeeff")
rankdata = sca(trs,params)

plot(PlotRanksEvolution(),rankdata,params)
```
"""
struct PlotRanksEvolution end

@recipe function f(::PlotRanksEvolution, rankdata::RankData, params)
    if isnull(params.knownKey) 
        error("need params.knownKey (or if you don't know the key, look at PlotScoresEvolution)")
    end
    
    xxrows = Vector[]
    rrankings = Vector[]
    labels = String[]
    
    for phase in getPhases(rankdata)
        xrows = getNrConsumedRowsEvolution(rankdata,phase)
        for target in getTargets(rankdata, phase)
            kb = getCorrectKey(params,phase,target)
            rankings = getRankingsEvolution(rankdata, phase, target, kb)            
            push!(xxrows,xrows)
            push!(rrankings,rankings)
            push!(labels, "phase $phase, target $target")
        end
    end
    
    color := :auto
    label := labels

    ylabel := "rank"
    xlabel --> "#traces"
    title --> "rank evolution"
    xxrows,rrankings
end

