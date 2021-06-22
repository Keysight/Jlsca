# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ..Trs

import ..Trs.reset
# no longer exported in Trs because shouldn't be called 
# by user code anymore.
import ..Trs.setPostProcessor

export CPA,IncrementalCPA
export Status,Direction
export printParameters,getParameters
export target
export guesses,numberOfPhases,numberOfTargets,recoverKey,getDataPass,getTargets,isKeyCorrect,correctKeyMaterial,keylength,blocklength
export totalNumberOfTargets
export RankData,RankData

@enum Direction FORWARD=1 BACKWARD=2
@enum Status FINISHED PHASERESULT INTERMEDIATERANKS INTERMEDIATESCORES BREAK

const PHASE1 = 1
const PHASE2 = 2
const PHASE3 = 3
const PHASE4 = 4
const PHASE5 = 5
const PHASE6 = 6

export PHASE1,PHASE2,PHASE3,PHASE4,PHASE5,PHASE6
for s in instances(Direction); @eval export $(Symbol(s)); end
for s in instances(Status); @eval export $(Symbol(s)); end

export Attack
"""
Inherit this abstract type for your own attacks. Type `Attack` has type parameter `Unit`, usually an UInt8, which is the type used for defining the type of functions `getDataPass`, `getTargets` and `recoverKey`. 

Implemented attacks in Jlsca:
`AesSboxAttack`,`AesMCAttack`,`DesSboxAttack`,`DesRoundAttack`,`Sha1InputAttack`, `Sha1OutputAttack`.
"""
abstract type Attack{Unit <: Integer} end

export Analysis
abstract type Analysis end

export NonIncrementalAnalysis
"""
Inherit this abstract type for your own non-incremental analysis. Non-incremental here means that the analysis will receive an observation matrix and a corresponding matrix of inputs. A non-incremental analysis can be combined with a post processor like conditional averaging `CondAvg` (or, for binary samples `CondReduce`) to run on large trace sets.

Implemented non-incremental analysisises in Jlsca: `CPA`,`LRA`, and `MIA`.
"""
abstract type NonIncrementalAnalysis <: Analysis end

export IncrementalAnalysis
"""
Inherit this abstract type for your own incremental analysis. Incremental here means that the analysis will receive a row of the observation matrix, and corresponding row of the inputs, at a time. An incremental analysis needs to implement a corresponding post processor `PostProcessor`, and cannot be combined with the existing processors (`CondAvg`,`CondReduce`). 

Implemented incremental analysis in Jlsca: `IncrementalCPA` and its corresponding post processor `IncrementalCorrelation`.
"""
abstract type IncrementalAnalysis <: Analysis end

export Target
"""
Inherit this abstract type to define your own target functions for your own attack. The type parameters are the input, output and guess types of the target function respectively. You'll need to implement `target` for your `Target` type. 

Implemented targets in Jlsca: `MCOut`,`InvMCOut`,`SboxOut`,`InvSboxOut`,`DesSboxOut`,`RoundOut`,`ModAdd`, ....

# Example
```
mutable struct MyTarget <: Target{UInt8,UInt8,UInt8} end
target(a::MyTarget, input::UInt8, kb::UInt8) = xor(input,kb)
```
"""
abstract type Target{In <: Integer, Out <: Integer, Guess <: Integer} end

export Maximization
"""
Inherit this abstract type to define your own maximization strategy.

Implemented strategies in Jlsca are: `AbsoluteGlobalMaximization`,`GlobalMaximization`,`NormalizedMaximization`.
"""
abstract type Maximization end

export AbsoluteGlobalMaximization
"""
To retrieve a vector of scores from a matrix of C = (sample columns,score for guesses)
we first take the absolute of C, then max value of each column. 

# Examples
```
params = DpaAttack(AesSboxAttack(),CPA())
params.maximization = AbsoluteGlobalMaximization()
```
"""
mutable struct AbsoluteGlobalMaximization <: Maximization end
show(io::IO, a::AbsoluteGlobalMaximization) = print(io, "abs global max")

export GlobalMaximization
"""
To retrieve a vector of scores from a matrix of C = (sample columns,score for guesses)
we take max value of each column.

# Examples
```
params = DpaAttack(AesSboxAttack(),CPA())
params.maximization = GlobalMaximization()
```
"""
mutable struct GlobalMaximization <: Maximization end
show(io::IO, a::GlobalMaximization) = print(io, "global max")

export NormalizedMaximization
"""
To retrieve a vector of scores from a matrix of C = (sample columns,score for guesses)
first divide all the candidate scores for a given sample by the standard deviation of those scores, then take the global maximum over all samples.

# Examples
```
params = DpaAttack(AesSboxAttack(),CPA())
params.maximization = NormalizedMaximization()
```
"""
mutable struct NormalizedMaximization <: Maximization end
show(io::IO, a::NormalizedMaximization) = print(io, "normalized max")

export maximization
"""
   maximization(a::Analysis)

Returns the prefered maximization for an analysis like `CPA`, `MIA` or `LRA`. 

Override this function if your own `Analysis` needs a specific maximization strategy. The default is `GlobalMaximization`.
"""
maximization(a::Analysis) = GlobalMaximization()


export numberOfLeakage
"""
    numberOfLeakages(a::Analysis)

A `CPA` analysis on all-bits AES Sbox attack returns 8 here, a simple HW `CPA` attack returns 1. 

Override this function if your own `Analysis` supports a variable amount of leakages or if it is different from the default `1`.
"""
numberOfLeakages(a::Analysis) = 1

export Combination
"""
Inherit this type to implement your own strategy of combining leakage scores. You'll need to implement `setCombined!` for your strategy.

The default and only combination function is `Sum`.

# Example
```
mutable struct Max <: Combination end
# import in order to override for new type
import Base.show
show(io::IO,a::Max) = print(io, "max")
# import in order to override for new type
import Jlsca.Sca.setCombined!
function setCombined!(a::Max, sc::RankData, phase::Int, target::Int, nrTraces::Int)
  if sc.nrLeakages > 1
    r = length(sc.numberOfTraces[phase])
    sc.combinedScores[phase][target][:,r] .= 0

    for leakage in keys(sc.scores[phase][target])
      sc.combinedScores[phase][target][:,r] = max.(sc.combinedScores[phase][target][:,r], sc.scores[phase][target][leakage][:,r])
    end
  end
end

params = DpaAttack(AesSboxAttack(),CPA())
params.leakageCombinator = Max()
```
"""
abstract type Combination end

"""
The default `Combination` strategy which, for a given key candidate, sums the scores of all leakages.
"""
mutable struct Sum <: Combination end
show(io::IO, a::Sum) = print(io, "+")

"""
Takes the maximum of the scores over all leakages, for a given key candidate.
"""
mutable struct Max <: Combination end
show(io::IO, a::Max) = print(io, "max")

"""
Takes the maximum of the normalized scores over all leakages, for a given key candidate.
"""
mutable struct MaxNormalized <: Combination end
show(io::IO,a::MaxNormalized) = print(io, "max normalized")

"""
Sums the normalized scores of all leakages, for a given key candidate.
"""
mutable struct SumNormalized <: Combination end
show(io::IO,a::SumNormalized) = print(io, "sum normalized")


export DpaAttack
"""
An instance of this goes into `sca` and defines the Dpa attack. 

The constructor takes two arguments: an attack of type `Attack` and an analysis of type `Analysis` to create a `DpaAttack`. For example, `params = DpaAttack(AesSboxAttack(), CPA())`. Note that the attack will be available through `params.attack`, and the analysis via `params.analysis` for later tweaking.

# Optional fields
Once an instance is created, the following fields can be tweaked to change the behavior of `sca`. 
* `dataOffset`: (1-based) offset where in the trace data the data for `attack` is located. Default is 1.
* `knownKey`: the key (byte vector) for this attack, if you know it. Will mark correct guesses in the textual output of `sca`, and allows you to make rank and score evolution plots.
* `updateInterval`: causes `sca` to print out the scores, and updates the rank data, after each `updateInterval` of traces.
*  `phases`: a range of phases (integers) that you want to attack. For example, if your attack has 5 phases and you only want to run phases 3 and 4 you'll write `params.phases = [3,4]`. By default `sca` will go through all defined attack phases.
* `phaseInput`: if you specify `phases`, the `phaseInput` needs to contain a vector of bytes of the key material recovered by phase 1 up to the first phase in your `phases` range. Or, if you fill in `knownKey`, you don't need to specify this.
* `targetOffsets`: the (1-based) list of offsets of the targets you want to attack. By default all targets for each phase are attacked.
* `leakageCombinator`: specify a `Combinator` instance, `Sum` by default.
* `maximization`: specify a `Maximization` strategy, default depends on the analysis.
* `maxCols`: splits up the work by considering maxCols columns of the observation matrix at a time, before feeding it into a post processor. Results per split are combined transparently. You may need to set this (to not run out of memory) for traces with lots of columns, or if you specify a large amount of leakages (for example Klemsa). 
* `maxColsPost`: almost the same as `maxCols`, but this splits up work *after* a post processor. This is only different from `maxCols` and only useful when you're using the `CondReduce` postprocessor, since this is currently the only one that would return less columns than you put in.
* 'keepraw`: caches the output of CPA, LRA or MIA so that you can do fancy stuff yourself with it (see `getRaw` of `RankData`)

# Example
```
attack = AesSboxAttack()
analysis = CPA()
params = DpaAttack(attack, analysis)
params.dataOffset = 2
params.knownKey = hex2bytes("cafecee5deadcee51122334455667788cafecee5deadcee5")
params.attack.keyLength = KL192 # 2 phases for AES192
params.phases = [2]
params.targetOffsets = [1,3]
params.leakageCombinator = Sum()
params.maximization = AbsoluteGlobalMaximization()
params.maxCols = 200000
```
"""
mutable struct DpaAttack
  attack::Attack
  analysis::Analysis
  dataOffset::Int
  knownKey::Union{Missing,Vector{UInt8}}
  updateInterval::Union{Missing,Int}
  phases::Union{Missing,Vector{Int}}
  phaseInput::Union{Missing,Vector}
  outputkka::Union{Missing,AbstractString}
  targetOffsets::Union{Missing,Vector{Int}}
  scoresCallBack::Union{Missing,Function}
  evolutionCb::Union{Missing,Function}
  leakageCombinator::Combination
  maximization::Union{Missing,Maximization}
  maxCols::Union{Missing,Int}
  maxColsPost::Union{Missing,Int}
  keepraw::Bool
  # caching stuff below, not configurable, overwritten for each sca run
  targets::Vector{Vector{Target}}
  phasefn::Vector{Union{Missing,Function}}
  phaseData::Vector
  correctKeyMaterial::Vector
  intervals::Int
  rankData

  function DpaAttack(attack::Attack, analysis::Analysis)
    new(attack,analysis,1,missing,missing,missing,missing,missing,missing, missing, missing, Sum(), missing,missing, missing, false)
  end
end

export RankData

"""
An instance of this is returned by `sca`, and it contains all the information needed to plot and print ranks and scores. If you run `sca` with the `updateInterval` set, the rankdata can be used to plot rank and score evolutions too. 

What is *not* contained in this instance is the "raw" correlation data. 

Data in this instance should be accessed by functions. See:
* `getIntervals`
* `getPhases`
* `getTargets`
* `getLeakages`
* `getGuesses`
* `getRankingsEvolution`
* `getScoresEvolution`
* `getOffsetsEvolution`
* `getNrConsumedRows`
* `getNrConsumedRowsEvolution`
* `getNrConsumedCols`
* `getNrConsumedColsEvolution`
* `getNrRows`
* `getNrRowsEvolution`
* `getNrCols`
* `getNrColsEvolution`
* `getScores`
* `getOffsets`
"""
mutable struct RankData
  nrConsumedRows
  nrConsumedCols
  nrRows
  nrCols
  scores
  offsets
  combinedScores
  intervals
  nrLeakages
  keepraw
  raw

  function RankData(nintervals::Int; nleakages=1, keepraw=false)
    nrConsumedRows = Dict{Int, BitSet}()
    nrConsumedCols = Dict{Int, Vector{Int}}()
    nrRows = Dict{Int, Dict{Int, Vector{Int}}}()
    nrCols = Dict{Int, Dict{Int, Vector{Int}}}()
    combinedScores = Dict{Int, Dict{Int, Matrix{Float64}}}()
    scores = Dict{Int, Dict{Int, Dict{Int, Matrix{Float64}}}}()
    offsets = Dict{Int, Dict{Int, Dict{Int, Matrix{Int}}}}()
    return new(nrConsumedRows,nrConsumedCols,nrRows,nrCols,scores,offsets,combinedScores,nintervals,nleakages,keepraw)
  end

  function RankData(params::DpaAttack)
    RankData(params.intervals; nleakages=numberOfLeakages(params.analysis), keepraw=params.keepraw)
  end
end

function printParameters(a::DpaAttack)
  print("DPA parameters\n")
  print("attack:       $(a.attack)\n")
  printParameters(a.attack)
  print("analysis:     $(a.analysis)\n")
  printParameters(a.analysis)
  print("maximization: $(coalesce(a.maximization, maximization(a.analysis)))\n")
  if numberOfLeakages(a.analysis) > 1
    print("combination:  $(a.leakageCombinator)\n")
  end
  print("data at:      $(a.dataOffset)\n")
  if !ismissing(a.phases)
    print("phases:       $(a.phases)\n")
  end
  if !ismissing(a.targetOffsets)
    print("targets:      $(a.targetOffsets)\n")
  end
  if !ismissing(a.knownKey)
    print("known key:    $(bytes2hex(a.knownKey))\n")
  end
  if !ismissing(a.maxCols)
    print("max cols into post processor: $(a.maxCols)\n")
  end
  if !ismissing(a.maxColsPost)
    print("max cols into non-inc analysis: $(a.maxColsPost)\n")
  end
end

printParameters(a::Attack) = return
guesses(a::Target{In,Out,Guess}) where {In,Out,Guess} = collect(Guess, typemin(Guess):typemax(Guess))
numberOfPhases(a::Attack) = 1
numberOfTargets(a::Attack, phase::Int) = 1
getTargets(a::Attack{U}, phase::Int, phaseInput::AbstractVector{U}) where {U} = []
recoverKey(a::Attack{U}, recoverKeyMaterial::AbstractVector{U}) where {U} = recoverKeyMaterial
getDataPass(a::Attack{U}, phase::Int, phaseInput::AbstractVector{U}) where {U} = missing
totalNumberOfTargets(a::Attack) = sum(x -> numberOfTargets(a,x), 1:numberOfPhases(a))
isKeyCorrect(a::Attack, key1::AbstractVector{UInt8}, key2::AbstractVector{UInt8}) = key1 == key2

unittype(a::Attack{T}) where {T} = T

export numberOfLeakages

function attack(a::NonIncrementalAnalysis, params::DpaAttack, phase::Int, super::Task, trs::Traces, resettrs::Bool, firstTrace::Int, rows::UnitRange, cols::UnitRange, rankData::RankData)

  local kbsamples
  local kbdata

  targetOffsets = getTargetOffsets(params, phase)

  if !ismissing(a.postProcessor) && resettrs
    setPostProcessor(trs,a.postProcessor)
    initPostProcessor(trs)
  end

  ((data, samples), eof) = readTraces(trs, rows)
  nrTraces = getCounter(trs)

  if data == nothing || samples == nothing
    return
  end

  consumedCols = length(cols)
  
  for o in 1:length(targetOffsets)
    if hasPostProcessor(trs)
      kbsamples = samples[o]
      kbdata = data[o]
    else
      kbsamples = samples
      kbdata = @view data[:,o]
    end

    (nrrows,samplecols) = size(kbsamples)

     # FIXME: need to pick something sane here
    maxCols = coalesce(params.maxColsPost, params.maxCols, 200000)

    target = getTarget(params, phase, targetOffsets[o])
    kbvals = guesses(target)
    nrKbvals = length(kbvals)

    if size(kbsamples)[2] == 0
      @printf("Nothing to do, no samples!\n")
      continue
    end
    
    for sr in 1:maxCols:samplecols
      srEnd = min(sr+maxCols-1, samplecols)
      v = @view kbsamples[:,sr:srEnd]

      @printf("%s on samples shape %s (range %s) and data shape %s\n", string(typeof(a).name.name), size(v), string(sr:srEnd), size(kbdata))

      # run the attack
      C = computeScores(a, kbdata, v, target, kbvals)

      # nop the nans
      C[isnan.(C)] .= 0

      # get the scores for all leakage functions
      for l in 1:numberOfLeakages(a)
        oo = (l-1)*nrKbvals
        vv = @view C[:,oo+1:oo+nrKbvals]
        yieldto(super, (INTERMEDIATESCORES, (phase, o, l, vv)))
        update!(coalesce(params.maximization, maximization(a)), rankData, phase, vv, targetOffsets[o], l, nrTraces, consumedCols, nrrows, length(sr:srEnd),cols[1]+sr-1)
        consumedCols = 0
      end
    end

    setCombined!(params.leakageCombinator, rankData, phase, targetOffsets[o], nrTraces)

    # let somebody do something with the scores for these traces
    yieldto(super, (INTERMEDIATERANKS, (rankData, [targetOffsets[o]])))
  end
end

function attack(a::IncrementalAnalysis, params::DpaAttack, phase::Int, super::Task, trs::Traces, resettrs::Bool, firstTrace::Int, rows::UnitRange, cols::UnitRange, rankData::RankData)
  targetOffsets = getTargetOffsets(params, phase)
  leakages = params.analysis.leakages
  targets = getTargets(params, phase)


  # if isa(trs, DistributedTrace)
  #   @sync for w in workers()
  #     @spawnat w init(meta(trs.trsfn()).postProcInstance, targetOffsets, leakages, targets)
  #   end
  # else
  #   init(meta(trs).postProcInstance, targetOffsets, leakages, targets)
  # end

  if resettrs
    setPostProcessor(trs, a.postProcessor)
    initPostProcessor(trs, targetOffsets, leakages, targets)
  end

  (C,eof) = readTraces(trs, rows)

  # nop the nans
  C[isnan.(C)] .= 0

  nrTraces = getCounter(trs)

  (samplecols,hypocols) = size(C)

  @printf("%s on range %s produced (%d, %d) correlation matrix\n", a, cols, samplecols, hypocols)

  nrLeakages = length(a.leakages)
  consumedCols = length(cols)

  for kb in 1:length(targetOffsets)
    nrKbvals = length(guesses(getTarget(params, phase, targetOffsets[kb])))
    for l in 1:nrLeakages
      oo = (l-1)*nrKbvals + (kb-1)*nrLeakages*nrKbvals
      vv = @view C[:,oo+1:oo+nrKbvals]
      yieldto(super, (INTERMEDIATESCORES, (phase, kb, l, vv)))
      update!(coalesce(params.maximization, maximization(a)), rankData, phase, vv, targetOffsets[kb], l, nrTraces, consumedCols, nrTraces, length(cols), cols[1])
      consumedCols = 0
    end
    setCombined!(params.leakageCombinator, rankData, phase, targetOffsets[kb], nrTraces)
  end

  # let somebody do something with the scores for these traces
  yieldto(super, (INTERMEDIATERANKS, (rankData, targetOffsets)))
end

# does the attack & analysis per xxx traces, should be called from an scatask
function analysis(super::Task, params::DpaAttack, phase::Int, trs::Traces, rows::UnitRange)
    local rankData

    if !ismissing(params.updateInterval) && ismissing(params.analysis.postProcessor)
        throw(ErrorException("WARNING: update interval only supported for runs with a post processor"))
    end

    samplecols = nrsamples(trs, true)

    # FIXME: need to pick something sane here
    maxCols = coalesce(params.maxCols, 200000)
    nrsegments = div(samplecols+maxCols-1,maxCols)

    i = 1
    for sr in 1:maxCols:samplecols
      srEnd = min(sr+maxCols-1, samplecols)
      print("Attacking columns $(sr:srEnd) out of $samplecols columns (run $i out of $nrsegments)\n")
      i += 1
      if nrsegments > 1
        setColumnRange(trs, sr:srEnd)
      end

      firstTrace = rows[1]
      numberOfTraces = length(rows)

      offset = firstTrace
      stepSize = min(numberOfTraces, coalesce(params.updateInterval, numberOfTraces))

      rankData = params.rankData
      resettrs = true

      for offset in firstTrace:stepSize:(firstTrace-1+numberOfTraces)
        interval = offset:(offset+min(stepSize, firstTrace - 1 + numberOfTraces - offset + 1)-1)

        attack(params.analysis, params, phase, super, trs, resettrs, firstTrace, interval, sr:srEnd, rankData)
        resettrs = false
      end

      if nrsegments > 1
        setColumnRange(trs, missing)
      end

      # reset the state of trace post processor (conditional averager)
      reset(trs)
    end

    return rankData
end

function scatask(super::Task, trs::Traces, params::DpaAttack, firstTrace::Int, numberOfTraces::Int, phase::Int)

  roundfn = getDataPass(params, phase)

  if params.dataOffset != 1
    addDataPass(trs, x -> x[params.dataOffset:end])
  end

  if !ismissing(roundfn)
    addDataPass(trs, roundfn)
  end

  fullattack = isFullAttack(params, phase)

  if !fullattack
    addDataPass(trs, x -> x[params.targetOffsets])
  end

  # do the attack
  rankData = analysis(super, params, phase, trs, firstTrace:(firstTrace-1+numberOfTraces))

  if !fullattack
    popDataPass(trs)
  end

  if !ismissing(roundfn)
    popDataPass(trs)
  end

  if params.dataOffset != 1
    popDataPass(trs)
  end

  if !fullattack || !haveAllData(rankData, params.attack, phase)
    return
  end

  # get the recovered key material
  roundkey = getPhaseKey(params, params.attack, phase, rankData)
  yieldto(super, (PHASERESULT, roundkey))

  if numberOfPhases(params.attack) == phase
    yieldto(super, (FINISHED,nothing))
  end
end

function getTargetOffsets(a::DpaAttack, phase::Int)
  return coalesce(a.targetOffsets, collect(1:numberOfTargets(a, phase)))
end

function isFullAttack(a::DpaAttack, phase::Int)
  return ismissing(a.targetOffsets) || (numberOfTargets(a, phase) == length(a.targetOffsets))
end

numberOfPhases(a::DpaAttack) = numberOfPhases(a.attack)
numberOfTargets(a::DpaAttack, phase::Int) = numberOfTargets(a.attack,phase)
numberOfGuesses(a::DpaAttack, phase::Int, target::Int) = length(guesses(a.targets[phase][target]))
getTargets(a::DpaAttack, phase::Int) = a.targets[phase]

export getTarget

getTarget(a::DpaAttack, phase::Int, targetOffset::Int) = a.targets[phase][targetOffset]
getDataPass(a::DpaAttack, phase::Int) = a.phasefn[phase]

export offset

"""
    offset(params,phase[,target])

If you'd concatenate all the key material recovered for all phases and targets, this function returns the offset into where key material for a given phase and target is stored. 
"""
offset(a::DpaAttack, phase::Int, target::Int) = (phase > 1 ? sum(x -> numberOfTargets(a,x), 1:phase-1) : 0) + (target-1)
offset(a::DpaAttack, phase::Int) = offset(a,phase,1)

offset(a::Attack, phase::Int, target::Int) = (phase > 1 ? sum(x -> numberOfTargets(a,x), 1:phase-1) : 0) + (target-1)
offset(a::Attack, phase::Int) = offset(a,phase,1)

function lazyinit(params::DpaAttack) 
  if !ismissing(params.knownKey) && !isdefined(params, :correctKeyMaterial)
    knownrkmaterial = correctKeyMaterial(params.attack, params.knownKey)
    params.correctKeyMaterial = knownrkmaterial
  end
end

export getCorrectKey

"""
    getCorrectKey(params,phase,target)

Returns the correct key (byte) for a given phase and target.

# Examples
```
params = DpaAttack(AesSboxAttack(),CPA())
params.attack.direction = BACKWARD
params.knownKey = hex2bytes("1122334455667788cafecee5deadcee5")
print("kb: 0x\$(hex(getCorrectKey(params,1,1)))")
```

"""
function getCorrectKey(params::DpaAttack, phase::Int, target::Int)
  !ismissing(params.knownKey) || throw(ErrorException("Cannot call this without params.knownKey set"))
  lazyinit(params)
  o = offset(params, phase, target)
  kb = params.correctKeyMaterial[o+1]
  return kb
end

export sca

# generic sca function, this one is called in all the unit tests and the main functions
"""
    sca(trs,params,[, firstTrace,[,numberOfTraces]])

Runs the Dpa attack in `params` on trace set `trs`.

# Examples
```
# import to open trace sets
using Jlsca.Trs
# open trace set relative to Jlsca install folder
trs = InspectorTrace("aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs")
# use Aes Sbox attack
attack = AesSboxAttack()
# use vanilla CPA, no incremental / cond avg post processor, so everything in-memory
analysis = CPA()
# combine attack and analysis in Dpa parameters
params = DpaAttack(attack,analysis)
# run attack, and get rank data back
rankData = sca(trs,params)
# print the recovered key from the rank data
print("\$(getKey(params,rankData))")

```
"""
function sca(trs::Traces, params::DpaAttack, firstTrace::Int=1, numberOfTraces::Int=length(trs)-firstTrace+1)
  @printf("\nJlsca running in Julia version: %s, %d processes/%d workers/%d threads per worker\n\n", VERSION, nprocs(), nworkers(), Threads.nthreads())

  issubset(firstTrace:firstTrace+numberOfTraces-1,1:length(trs)) || throw(ErrorException("Too many traces $(firstTrace):$(firstTrace+numberOfTraces-1) selected for trace set of length $(length(trs))"))

  printParameters(params)

  local key = nothing
  local status = nothing
  local phaseInput = Vector{unittype(params.attack)}(undef,0)
  local phaseOutput = Vector{unittype(params.attack)}(undef,0)

  lazyinit(params)
  
  if !ismissing(params.knownKey)
    knownrkmaterial = params.correctKeyMaterial
  end

  finished = false
  phase = 1

  params.targets = Vector{Vector{Target}}(undef,0)
  params.phasefn = Vector{Union{Missing,Function}}(undef,0)
  params.intervals = !ismissing(params.updateInterval) ? (div(numberOfTraces, params.updateInterval) + ((numberOfTraces % params.updateInterval) > 0 ? 1 : 0)) : 1
  params.rankData = RankData(params)

  while !finished
    if phase > min(maximum(coalesce(params.phases, [numberOfPhases(params.attack)])), numberOfPhases(params.attack))
      finished = true
      continue
    end

    phaseDataOffset = offset(params,phase)
    phaseDataLength = numberOfTargets(params, phase)

    if phase > 1
      if !ismissing(params.knownKey)
        phaseInput = knownrkmaterial[1:phaseDataOffset]
      else
        phaseInput = phaseOutput
      end
    end


    targets = getTargets(params.attack, phase, phaseInput)
    @assert length(targets) > 0
    params.targets = [params.targets; [targets]]

    phasefn = getDataPass(params.attack, phase, phaseInput)
    params.phasefn = [params.phasefn; phasefn]

    if !ismissing(params.phases) && !(phase in coalesce(params.phases, []))
      if !ismissing(params.knownKey)
        phaseOutput = vcat(phaseOutput,knownrkmaterial[phaseDataOffset+1:phaseDataOffset+phaseDataLength])
      elseif !ismissing(params.phaseInput)
        phaseOutput = vcat(phaseOutput,params.phaseInput[phaseDataOffset+1:phaseDataOffset+phaseDataLength])
      else
        throw(ErrorException("need phaseInput or knownKey to attack phase $phase"))
      end
      phase += 1
      continue
    end

    print("\nphase: $(phase) / $(numberOfPhases(params.attack)), #targets $(length(targets))\n")
    if length(phaseInput) > 0
      @printf("phase input: %s\n", bytes2hex(reinterpret(UInt8, map(hton, phaseInput))))
    end
    print("\n")

    params.phaseData = phaseInput

    ct = current_task()

    # create the scatask with some sugar to catch exceptions
    t = @task begin
      try
        scatask(ct, trs, params, firstTrace, numberOfTraces, phase)
        yieldto(ct, (BREAK,0))
      catch e
        bt = catch_backtrace()
        showerror(stderr, e, bt)
        print(stderr, "\n")
        Base.throwto(ct, ErrorException("task dead, look at stack trace above"))
      end
    end

    while !istaskdone(t) && t.state != :failed
      (status, statusData) = yieldto(t)

      if status == FINISHED
        finished = true
        key = recoverKey(params.attack, phaseOutput)
        if key != nothing
          @printf("recovered key: %s\n", bytes2hex(key))
          if !ismissing(params.knownKey)
            print("knownkey match: $(isKeyCorrect(params.attack,params.knownKey,key))\n")
          end
        end
      elseif status == INTERMEDIATERANKS
        (rankData, keyOffsets) = statusData
        printScores(rankData, params.attack, params.knownKey, phase, keyOffsets)
      elseif status == PHASERESULT
        phaseOutput = vcat(phaseOutput, statusData)
      elseif status == INTERMEDIATESCORES
        if !ismissing(params.scoresCallBack)
          params.scoresCallBack(statusData...)
        end
      elseif status == BREAK
        break
      else
        @printf("WARNING: don't know how to handle %s produced by scatask\n", string(status))
      end
    end

    phase += 1
  end

  params.phaseInput = phaseOutput

  if !ismissing(params.outputkka) && !ismissing(params.knownKey)
    @printf("KKA output in file(s) with prefix %s\n", params.outputkka)
    correctKeyRanks2CSV(params)
  end

  if !ismissing(params.evolutionCb) 
    params.evolutionCb(params.rankData)
  end

  return params.rankData 
end
