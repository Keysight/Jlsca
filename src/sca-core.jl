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

@enum Direction FORWARD=1 BACKWARD=2
@enum Status FINISHED PHASERESULT INTERMEDIATESCORES INTERMEDIATECORRELATION BREAK

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
abstract type Target{In <:Integer, Out <: Integer} end
abstract type Maximization end

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
  leakageCombinator::Combination
  maximization::Maximization
  # caching stuff below, not configurable, overwritten for each sca run
  targets::Vector{Vector{Target}}
  phasefn::Vector{Nullable{Function}}
  phaseData::Vector{UInt8}

  function DpaAttack(attack::Attack, analysis::Analysis)
    new(attack,analysis,1,Nullable(),Nullable(),Nullable(),Nullable(),Nullable(),Nullable(), Nullable(), Sum(), GlobalMaximization())
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
    @printf("key bytes:  %s\n", string(get(a.targetOffsets)))
  end
  if !isnull(a.knownKey)
    @printf("known key:  %s\n", bytes2hex(get(a.knownKey)))
  end
end

printParameters(a::Attack) = print("Unknown attack")
guesses(a::Target{In,Out}) where {In,Out} = collect(UInt8, 0:255)
numberOfPhases(a::Attack) = 1
numberOfTargets(a::Attack, phase::Int) = 1
getTargets(a::Attack, phase::Int, phaseInput::Vector{UInt8}) = []
recoverKey(a::Attack, recoverKeyMaterial::Vector{UInt8}) = recoverKeyMaterial
getDataPass(a::Attack, phase::Int, phaseInput::Vector{UInt8}) = Nullable()
totalNumberOfTargets(a::Attack) = sum(x -> numberOfTargets(a,x), 1:numberOfPhases(a))

# four types of analysis methods: CPA and MIA and LRA and IncrementalCPA
type CPA <: NonIncrementalAnalysis
  leakages::Vector{Leakage}
  postProcess::Vector{Function}
  maxCols::Nullable{Int}
  logfile::SimpleCSV

  function CPA()
    return new([HW()], [x -> abs.(x)], Nullable(), SimpleCSV())
  end
end

type MIA <: NonIncrementalAnalysis
  leakages::Vector{Leakage}
  postProcess::Vector{Function}
  maxCols::Nullable{Int}
  logfile::SimpleCSV
  sampleBuckets::Int

  function MIA()
    return new([HW()], [x -> abs.(x)], Nullable(), SimpleCSV(), 9)
  end
end

type LRA <: NonIncrementalAnalysis
  basisModel::Function
  postProcess::Vector{Function}
  maxCols::Nullable{Int}
  logfile::SimpleCSV

  function LRA(basisModel)
    return new(basisModel, [], Nullable(), SimpleCSV())
  end

  function LRA()
    return new(basisModelSingleBits, [], Nullable(), SimpleCSV())
  end
end

type IncrementalCPA <: Analysis
  leakages::Vector{Leakage}
  postProcess::Vector{Function}
  reducer::Function
  logfile::SimpleCSV

  function IncrementalCPA()
    return new([HW()], [x -> abs.(x)], x -> max(abs.(x)), SimpleCSV())
  end
end

function printParameters(a::IncrementalCPA)
  @printf("leakages:   %s\n", a.leakages)
end

function printParameters(a::LRA)
  @printf("basismodel: %s\n", a.basisModel)
end

function printParameters(a::CPA)
  @printf("leakages:   %s\n", a.leakages)
end

function printParameters(a::MIA)
  @printf("leakages:   %s\n", a.leakages)
  @printf("#buckets:   %d\n", a.sampleBuckets)
end

getNrLeakageFunctions(a::LRA) = 1
getNrLeakageFunctions(a::CPA) = length(a.leakages)
getNrLeakageFunctions(a::MIA) = length(a.leakages)
getNrLeakageFunctions(a::IncrementalCPA) = length(a.leakages)


function computeScores(a::CPA, data::AbstractArray{In}, samples::AbstractArray, target::Target{In,Out}, kbvals::Vector{UInt8}) where {In,Out}
  (tr,tc) = size(samples)
  (dr,) = size(data)
  tr == dr || throw(DimensionMismatch())

  HL::Matrix{UInt8} = predict(data, target, kbvals, a.leakages)
  C = cor(samples, HL)
  return C
end

function computeScores(a::MIA, data::AbstractArray{In}, samples::AbstractArray, target::Target{In,Out}, kbvals::Vector{UInt8}) where {In,Out}
  (tr,tc) = size(samples)
  (dr,) = size(data)
  tr == dr || throw(DimensionMismatch())

  HL::Matrix{UInt8} = predict(data, target, kbvals, a.leakages)
  C = mia(samples, HL, a.sampleBuckets)
  return C
end

function computeScores(a::LRA, data::AbstractArray{In}, samples::AbstractArray, target::Target{In,Out}, kbvals::Vector{UInt8}) where {In,Out}
   C = lra(data, samples, target, a.basisModel, kbvals)
  return C
end

function attack(a::NonIncrementalAnalysis, params::DpaAttack, phase::Int, super::Task, trs::Trace, rows::Range, scoresAndOffsets)

  local kbsamples
  local kbdata

  targetOffsets = getTargetOffsets(params, phase)

  ((data, samples), eof) = readTraces(trs, rows)

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

    # FIXME: need to pick something sane here
    maxCols = get(a.maxCols, 10000)

    target = getTarget(params, phase, targetOffsets[o])
    kbvals = guesses(target)
    nrKbvals = length(kbvals)

    for sr in 1:maxCols:samplecols
      srEnd = min(sr+maxCols-1, samplecols)

      @printf("%s on samples shape %s (range %s) and data shape %s\n", string(typeof(a).name.name), size(kbsamples), string(sr:srEnd), size(kbdata))

      if size(kbsamples)[2] == 0
        @printf("no samples!\n")
        scores = nothing
        continue
      end

      v = @view kbsamples[:,sr:srEnd]

      # run the attack
      C = computeScores(a, kbdata, v, target, kbvals)

      # nop the nans
      C[isnan.(C)] = 0


      for fn in a.postProcess
        C = fn(C)
      end

      # get the scores for all leakage functions
      for l in 1:getNrLeakageFunctions(a)
        oo = (l-1)*nrKbvals
        vv = @view C[:,oo+1:oo+nrKbvals]
        yieldto(super, (INTERMEDIATECORRELATION, (phase, o, l, vv)))
        updateScoresAndOffsets!(params.maximization, scoresAndOffsets, vv, l, o)
      end
    end

    # let somebody do something with the scores for these traces
    yieldto(super, (INTERMEDIATESCORES, (scoresAndOffsets, getCounter(trs), nrrows, [o])))
  end
end

function attack(a::IncrementalCPA, params::DpaAttack, phase::Int, super::Task, trs::Trace, rows::Range, scoresAndOffsets)
  targetOffsets = getTargetOffsets(params, phase)

  if isa(trs, DistributedTrace)
    @sync for w in workers()
      @spawnat w init(Main.trs.postProcInstance, params, phase)
    end
  else
    init(trs.postProcInstance, params, phase)
  end

  (C,eof) = readTraces(trs, rows)

  (samplecols,hypocols) = size(C)

  @printf("%s produced (%d, %d) correlation matrix\n", string(typeof(a).name.name), samplecols, hypocols)

  for fn in a.postProcess
    C = fn(C)
  end

  nrLeakages = length(a.leakages)

  for kb in 1:length(targetOffsets)
    nrKbvals = length(guesses(getTarget(params, phase, targetOffsets[kb])))
    for l in 1:nrLeakages
      oo = (l-1)*nrKbvals + (kb-1)*nrLeakages*nrKbvals
      vv = @view C[:,oo+1:oo+nrKbvals]
      yieldto(super, (INTERMEDIATECORRELATION, (phase, kb, l, vv)))
      updateScoresAndOffsets!(params.maximization, scoresAndOffsets, vv, l, kb)
    end
  end


  # let somebody do something with the scores for these traces
  yieldto(super, (INTERMEDIATESCORES, (scoresAndOffsets, getCounter(trs),getCounter(trs), targetOffsets)))
end

# does the attack & analysis per xxx traces, should be called from an scatask
function analysis(super::Task, params::DpaAttack, phase::Int, trs::Trace, rows::Range)
    local scoresAndOffsets

    if !isnull(params.updateInterval) && !hasPostProcessor(trs)
        @printf("WARNING: update interval only supported for traces with a post processor, option ignored\n")
        updateInterval = Nullable()
    end

    firstTrace = rows[1]
    numberOfTraces = length(rows)

    offset = firstTrace
    stepSize = min(numberOfTraces, get(params.updateInterval, numberOfTraces))
    targetOffsets = getTargetOffsets(params,phase)

    scoresAndOffsets = ScoresAndOffsets(params, phase)

    eof = false

    for offset in firstTrace:stepSize:numberOfTraces
      interval = offset:(offset+min(stepSize, numberOfTraces - offset + 1)-1)

      if eof
        break
      end

      clearScoresAndOffsets!(scoresAndOffsets)

      attack(params.analysis, params, phase, super, trs, interval, scoresAndOffsets)
    end


    # reset the state of trace post processor (conditional averager)
    reset(trs)

    return scoresAndOffsets
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
  scoresAndOffsets = analysis(super, params, phase, trs, firstTrace:numberOfTraces)

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
  roundkey::Vector{UInt8} = getRoundKey(params, params.attack, phase, scoresAndOffsets)
  yieldto(super, (PHASERESULT, roundkey))

  if numberOfPhases(params.attack) == phase
    yieldto(super, (FINISHED,nothing))
  end
end

function getTargetOffsets(a::DpaAttack, phase::Int)
  return get(a.targetOffsets, collect(1:numberOfTargets(a, phase)))
end

function isFullAttack(a::DpaAttack, phase::Int)
  return isnull(a.targetOffsets) || (numberOfTargets(a, phase) == length(get(params.targetOffsets)))
end

numberOfTargets(a::DpaAttack, phase::Int) = length(a.targets[phase])
getTargets(a::DpaAttack, phase::Int) = a.targets[phase]
getTarget(a::DpaAttack, phase::Int, targetOffset::Int) = a.targets[phase][targetOffset]
getDataPass(a::DpaAttack, phase::Int) = a.phasefn[phase]

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
  end

  finished = false
  phase = 1

  params.targets = Vector{Vector{Target}}(0)
  params.phasefn = Vector{Nullable{Function}}(0)

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
      if phase > numberOfPhases(params.attack) 
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
      elseif status == INTERMEDIATESCORES
        (scoresAndOffsets, numberOfTracesProcessed, numberOfRowsAfterProcessing, keyOffsets) = statusData
        printScores(params, phase, scoresAndOffsets, numberOfTracesProcessed, numberOfRowsAfterProcessing ,keyOffsets)

        if !isnull(params.outputkka) && !isnull(params.knownKey)
          add2kka(params, phase, scoresAndOffsets, numberOfTracesProcessed, numberOfRowsAfterProcessing, keyOffsets)
        end
      elseif status == PHASERESULT
        phaseOutput = vcat(phaseOutput, statusData)
      elseif status == INTERMEDIATECORRELATION
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

  if !isnull(params.outputkka) && !isnull(params.knownKey)
    @printf("KKA output in %s\n", get(params.outputkka))
  end

  return key
end


# FIXME: move this somewhere else, or kill it off
# fills the attack parameters with data from the file name
function getParameters(filename::AbstractString, direction::Direction)
  local params::DpaAttack
  local attack::Attack

  m = match(r"aes([0-9]+)_(..)_([^_]*)_([a-zA-Z0-9]*)", filename)
  if m != nothing
    if m.captures[2] == "sb"
      attack = AesSboxAttack()
      analysis = CPA()
      analysis.leakages = [Bit(i) for i in 0:7]
      params = DpaAttack(attack, analysis)
    elseif m.captures[2] == "mc"
      attack = AesMCAttack()
      analysis = CPA()
      params = DpaAttack(attack, analysis)
      params.analysis.leakages = [Bit(i) for i in 0:31]
    end
    attack.keyLength::AesKeyLength = div(parse(m.captures[1]),8)
    modeStr = m.captures[3]
    if modeStr == "ciph"
      attack.mode = CIPHER
    elseif modeStr == "invciph"
      attack.mode = INVCIPHER
    elseif modeStr == "eqinvciph"
      attack.mode = EQINVCIPHER
    end

    params.knownKey = hex2bytes(m.captures[4])
    attack.direction = direction

    if direction == FORWARD
      params.dataOffset = 1
    else
      params.dataOffset = 17
    end
    return params
  end

  m = match(r"([t]{0,1}des[1-3]{0,1})_([^_]*)_([a-zA-Z0-9]*)", filename)
  if m != nothing
    attack = DesRoundAttack()
    analysis = CPA()
    analysis.leakages = [HW()]
    params = DpaAttack(attack, analysis)
    modeStr = m.captures[1]
    if modeStr == "des"
      attack.mode = DES
    elseif modeStr == "tdes1"
      attack.mode = TDES1
    elseif modeStr == "tdes2"
      attack.mode = TDES2
    elseif modeStr == "tdes3"
      attack.mode = TDES3
    end

    attack.encrypt = (m.captures[2] == "enc" ? true : false)

    params.knownKey = hex2bytes(m.captures[3])
    attack.direction = direction
    if direction == FORWARD
      params.dataOffset = 1
    else
      params.dataOffset = 9
    end
    return params
  end

  m = match(r"sha1_([a-zA-Z0-9]{40})", filename)
  if m != nothing
    if direction == FORWARD
      attack = Sha1InputAttack()
      analysis = CPA()
      analysis.leakages = [HW()]
      params = DpaAttack(attack,analysis)
      params.dataOffset = 1
    else
      attack = Sha1OutputAttack()
      analysis = CPA()
      analysis.leakages = [HW()]
      params = DpaAttack(attack,analysis)
      params.dataOffset = 17
    end
    params.knownKey = hex2bytes(m.captures[1])
    return params
  end
end
