# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ..Trs
using ..Log

import ..Trs.reset

export DpaAttack,Attack,Analysis,LRA,MIA,CPA,IncrementalCPA
export Status,Direction
export printParameters,getParameters
export sca
export Target,target
export guesses,numberOfPhases,numberOfTargets,correctKeyMaterial,recoverKey,getDataPass,getTargets
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

abstract type Attack end
abstract type Analysis end
abstract type NonIncrementalAnalysis <: Analysis end
abstract type IncrementalAnalysis <: Analysis end
abstract type Target{In <:Integer, Out <: Integer} end
abstract type Maximization end

type AbsoluteGlobalMaximization <: Maximization end
type GlobalMaximization <: Maximization end
type NormalizedMaximization <: Maximization end

abstract type Combination end

type Sum <: Combination end
show(io::IO, a::Sum) = print(io, "+")

type DpaAttack
  attack::Attack
  analysis::Analysis
  dataOffset::Int
  knownKey::Nullable{Vector{UInt8}}
  updateInterval::Nullable{Int}
  phases::Nullable{Vector{Int}}
  phaseInput::Nullable{Vector{UInt8}}
  outputkka::Nullable{AbstractString}
  targetOffsets::Nullable{Vector{Int}}
  scoresCallBack::Nullable{Function}
  evolutionCb::Nullable{Function}
  leakageCombinator::Combination
  maximization::Nullable{Maximization}
  maxCols::Nullable{Int}
  # caching stuff below, not configurable, overwritten for each sca run
  targets::Vector{Vector{Target}}
  phasefn::Vector{Nullable{Function}}
  phaseData::Vector{UInt8}
  correctKeyMaterial::Vector{UInt8}
  intervals::Int
  rankData

  function DpaAttack(attack::Attack, analysis::Analysis)
    new(attack,analysis,1,Nullable(),Nullable(),Nullable(),Nullable(),Nullable(),Nullable(), Nullable(), Nullable(), Sum(), Nullable() , Nullable())
  end
end

export RankData

type RankData
  numberOfTraces
  scores
  offsets
  combinedScores
  intervals
  nrLeakages

  function RankData(params::DpaAttack)
    numberOfTraces = Dict{Int, IntSet}()
    combinedScores = Dict{Int, Dict{Int, Matrix{Float64}}}()
    scores = Dict{Int, Dict{Int, Dict{Int, Matrix{Float64}}}}()
    offsets = Dict{Int, Dict{Int, Dict{Int, Matrix{Int}}}}()
    return new(numberOfTraces,scores,offsets,combinedScores,params.intervals,getNrLeakageFunctions(params.analysis))
  end
end

function printParameters(a::DpaAttack)
  printParameters(a.attack)
  @printf("analysis:   %s\n", string(typeof(a.analysis).name.name))
  printParameters(a.analysis)
  @printf("data at:    %s\n", string(a.dataOffset))
  if !isnull(a.phases)
    @printf("phases:     %s\n", string(get(a.phases)))
  end
  if !isnull(a.targetOffsets)
    @printf("targets:    %s\n", string(get(a.targetOffsets)))
  end
  if !isnull(a.knownKey)
    @printf("known key:  %s\n", bytes2hex(get(a.knownKey)))
  end
end

printParameters(a::Attack) = print("Unknown attack\n")
guesses(a::Target{In,Out}) where {In,Out} = collect(UInt8, 0:255)
numberOfPhases(a::Attack) = 1
numberOfTargets(a::Attack, phase::Int) = 1
getTargets(a::Attack, phase::Int, phaseInput::Vector{UInt8}) = []
recoverKey(a::Attack, recoverKeyMaterial::Vector{UInt8}) = recoverKeyMaterial
getDataPass(a::Attack, phase::Int, phaseInput::Vector{UInt8}) = Nullable()
totalNumberOfTargets(a::Attack) = sum(x -> numberOfTargets(a,x), 1:numberOfPhases(a))

export getNrLeakageFunctions

function attack(a::NonIncrementalAnalysis, params::DpaAttack, phase::Int, super::Task, trs::Trace, rows::Range, cols::Range, rankData::RankData)

  local kbsamples
  local kbdata

  targetOffsets = getTargetOffsets(params, phase)

  ((data, samples), eof) = readTraces(trs, rows)

  nrTraces = getCounter(trs)

  if data == nothing || samples == nothing
    return
  end

  for o in 1:length(targetOffsets)
    if hasPostProcessor(trs)
      kbsamples = samples[o]
      kbdata = data[o]
    else
      kbsamples = samples
      kbdata = @view data[:,o]
    end

    (nrrows,samplecols) = size(kbsamples)

    target = getTarget(params, phase, targetOffsets[o])
    kbvals = guesses(target)
    nrKbvals = length(kbvals)

    @printf("%s on samples shape %s (range %s) and data shape %s\n", string(typeof(a).name.name), size(kbsamples), cols, size(kbdata))

    if size(kbsamples)[2] == 0
      @printf("no samples!\n")
      scores = nothing
      continue
    end

    v = kbsamples

    # run the attack
    C = computeScores(a, kbdata, v, target, kbvals)

    # nop the nans
    C[isnan.(C)] = 0

    # get the scores for all leakage functions
    for l in 1:getNrLeakageFunctions(a)
      oo = (l-1)*nrKbvals
      vv = @view C[:,oo+1:oo+nrKbvals]
      yieldto(super, (INTERMEDIATESCORES, (phase, o, l, vv)))
      update!(get(params.maximization, maximization(a)), rankData, phase, vv, targetOffsets[o], l, nrTraces)
    end
    setCombined!(params.leakageCombinator, rankData, phase, targetOffsets[o], nrTraces)

    # let somebody do something with the scores for these traces
    yieldto(super, (INTERMEDIATERANKS, (rankData, nrTraces, nrrows, cols[end], length(cols), [targetOffsets[o]])))
  end
end

function attack(a::IncrementalAnalysis, params::DpaAttack, phase::Int, super::Task, trs::Trace, rows::Range, cols::Range, rankData::RankData)
  targetOffsets = getTargetOffsets(params, phase)
  leakages = params.analysis.leakages
  targets = getTargets(params, phase)

  if isa(trs, DistributedTrace)
    @sync for w in workers()
      @spawnat w init(Main.trs.postProcInstance, targetOffsets, leakages, targets)
    end
  else
    init(trs.postProcInstance, targetOffsets, leakages, targets)
  end

  (C,eof) = readTraces(trs, rows)

  nrTraces = getCounter(trs)

  (samplecols,hypocols) = size(C)

  @printf("%s on range %s produced (%d, %d) correlation matrix\n", a, cols, samplecols, hypocols)

  nrLeakages = length(a.leakages)

  for kb in 1:length(targetOffsets)
    nrKbvals = length(guesses(getTarget(params, phase, targetOffsets[kb])))
    for l in 1:nrLeakages
      oo = (l-1)*nrKbvals + (kb-1)*nrLeakages*nrKbvals
      vv = @view C[:,oo+1:oo+nrKbvals]
      yieldto(super, (INTERMEDIATESCORES, (phase, kb, l, vv)))
      update!(get(params.maximization, maximization(a)), rankData, phase, vv, targetOffsets[kb], l, nrTraces)
    end
    setCombined!(params.leakageCombinator, rankData, phase, targetOffsets[kb], nrTraces)
  end

  # let somebody do something with the scores for these traces
  yieldto(super, (INTERMEDIATERANKS, (rankData, getCounter(trs),getCounter(trs), cols[end], length(cols), collect(1:length(targetOffsets)))))
end

# does the attack & analysis per xxx traces, should be called from an scatask
function analysis(super::Task, params::DpaAttack, phase::Int, trs::Trace, rows::Range)
    local rankData

    if !isnull(params.updateInterval) && !hasPostProcessor(trs)
        throw(ErrorException("WARNING: update interval only supported for runs with a post processor"))
    end

    if isa(trs, DistributedTrace)
      samplecols = @fetch length(getSamples(Main.trs,rows[1]))
    else
      samplecols = length(getSamples(trs,rows[1]))
    end

    # FIXME: need to pick something sane here
    maxCols = get(params.maxCols, 20000)
    segmented = div(samplecols,maxCols) > 0

    for sr in 1:maxCols:samplecols
      srEnd = min(sr+maxCols-1, samplecols)
      if segmented
        addSamplePass(trs, x -> x[sr:srEnd])
      end

      firstTrace = rows[1]
      numberOfTraces = length(rows)

      offset = firstTrace
      stepSize = min(numberOfTraces, get(params.updateInterval, numberOfTraces))
      targetOffsets = getTargetOffsets(params,phase)

      rankData = params.rankData

      eof = false

      for offset in firstTrace:stepSize:numberOfTraces
        interval = offset:(offset+min(stepSize, numberOfTraces - offset + 1)-1)

        if eof
          break
        end

        attack(params.analysis, params, phase, super, trs, interval, sr:srEnd, rankData)
      end

      if segmented
        popSamplePass(trs)
      end

      # reset the state of trace post processor (conditional averager)
      reset(trs)
    end

    return rankData
end

function scatask(super::Task, trs::Trace, params::DpaAttack, firstTrace::Int, numberOfTraces::Int, phase::Int)

  roundfn = getDataPass(params, phase)

  if params.dataOffset != 1
    addDataPass(trs, x -> x[params.dataOffset:end])
  end

  if !isnull(roundfn)
    addDataPass(trs, get(roundfn))
  end

  fullattack = isFullAttack(params, phase)

  if !fullattack
    addDataPass(trs, x -> x[get(params.targetOffsets)])
  end

  # do the attack
  rankData = analysis(super, params, phase, trs, firstTrace:numberOfTraces)

  if !fullattack
    popDataPass(trs)
  end

  if !isnull(roundfn)
    popDataPass(trs)
  end

  if params.dataOffset != 1
    popDataPass(trs)
  end

  if !fullattack
    return
  end

  # get the recovered key material
  roundkey::Vector{UInt8} = getPhaseKey(params, params.attack, phase, rankData)
  yieldto(super, (PHASERESULT, roundkey))

  if numberOfPhases(params.attack) == phase
    yieldto(super, (FINISHED,nothing))
  end
end

function getTargetOffsets(a::DpaAttack, phase::Int)
  return get(a.targetOffsets, collect(1:numberOfTargets(a, phase)))
end

function isFullAttack(a::DpaAttack, phase::Int)
  return isnull(a.targetOffsets) || (numberOfTargets(a, phase) == length(get(a.targetOffsets)))
end

numberOfPhases(a::DpaAttack) = numberOfPhases(a.attack)
numberOfTargets(a::DpaAttack, phase::Int) = numberOfTargets(a.attack,phase)
numberOfGuesses(a::DpaAttack, phase::Int, target::Int) = length(guesses(a.targets[phase][target]))
getTargets(a::DpaAttack, phase::Int) = a.targets[phase]

export getTarget

getTarget(a::DpaAttack, phase::Int, targetOffset::Int) = a.targets[phase][targetOffset]
getDataPass(a::DpaAttack, phase::Int) = a.phasefn[phase]

export offset

offset(a::DpaAttack, phase::Int, target::Int) = (phase > 1 ? sum(x -> numberOfTargets(a,x), 1:phase-1) : 0) + (target-1)
offset(a::DpaAttack, phase::Int) = offset(a,phase,1)

export getCorrectKey

function getCorrectKey(params::DpaAttack, phase::Int, target::Int)
  @assert !isnull(params.knownKey)
  o = offset(params, phase, target)
  kb = params.correctKeyMaterial[o+1]
  return kb
end

# generic sca function, this one is called in all the unit tests and the main functions
function sca(trs::Trace, params::DpaAttack, firstTrace::Int=1, numberOfTraces::Int=length(trs))
  @printf("\nJlsca running in Julia version: %s, %d processes/%d workers/%d threads per worker\n\n", VERSION, nprocs(), nworkers(), Threads.nthreads())

  printParameters(params)

  local key = nothing
  local status = nothing
  local phaseInput = get(params.phaseInput, Vector{UInt8}(0))
  local phaseOutput = Vector{UInt8}(0)

  if !isnull(params.knownKey)
    knownrkmaterial = correctKeyMaterial(params.attack, get(params.knownKey))
    params.correctKeyMaterial = knownrkmaterial
  end


  finished = false
  phase = 1

  params.targets = Vector{Vector{Target}}(0)
  params.phasefn = Vector{Nullable{Function}}(0)
  params.intervals = !isnull(params.updateInterval) ? (div(numberOfTraces, get(params.updateInterval)) + ((numberOfTraces % get(params.updateInterval)) > 0 ? 1 : 0)) : 1
  params.rankData = RankData(params)

  while !finished
    if phase > 1
      if !isnull(params.knownKey)
        knownrklen = sum(x -> numberOfTargets(params,x), 1:phase-1)
        phaseInput = knownrkmaterial[1:knownrklen]
      else
        phaseInput = phaseOutput
      end
    end

    targets = getTargets(params.attack, phase, phaseInput)
    @assert length(targets) > 0
    params.targets = [params.targets; [targets]]

    phasefn = getDataPass(params.attack, phase, phaseInput)
    params.phasefn = [params.phasefn; phasefn]

    if !isnull(params.phases) && !(phase in get(params.phases, []))
      phaseOutput = phaseInput
      phase += 1
      if phase > min(maximum(get(params.phases)), numberOfPhases(params.attack))
        finished = true
      end
      continue
    end

    print("\nphase: $(phase) / $(numberOfPhases(params.attack)), #targets $(length(targets))\n")
    if length(phaseInput) > 0
      @printf("phase input: %s\n", bytes2hex(phaseInput))
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
        showerror(STDERR, e, bt)
        print(STDERR, "\n")
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
          if !isnull(params.knownKey)
            @printf("knownkey match: %s\n", string(key == get(params.knownKey)))
          end
        end
      elseif status == INTERMEDIATERANKS
        (rankData, numberOfTracesProcessed, numberOfRowsAfterProcessing, numberOfColsProcessed, numberOfColsAfterProcessing, keyOffsets) = statusData
        printScores(params, phase, rankData, numberOfTracesProcessed, numberOfRowsAfterProcessing, numberOfColsProcessed, numberOfColsAfterProcessing, keyOffsets)
      elseif status == PHASERESULT
        phaseOutput = vcat(phaseOutput, statusData)
      elseif status == INTERMEDIATESCORES
        if !isnull(params.scoresCallBack)
          get(params.scoresCallBack)(statusData...)
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

  if !isnull(params.outputkka) && !isnull(params.knownKey)
    @printf("KKA output in %s\n", get(params.outputkka))
    correctKeyRanks2CSV(params)
  end

  if !isnull(params.evolutionCb) 
    get(params.evolutionCb)(params.rankData)
  end

  return params.rankData 
end
