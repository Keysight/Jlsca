# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Dpa
using Lra
using Trs

export Attack,Analysis,LRA,DPA,IncrementalCPA
export analysis,attack
export sca
export scatask
export Status
export printParameters,getParameters
export Direction,Phase
export getNumberOfCandidates

abstract Analysis
abstract NonIncrementalAnalysis <: Analysis

# two types of analysis methods: DPA and LRA
type DPA <: NonIncrementalAnalysis
  statistic::Function
  leakageFunctions::Vector{Function}
  postProcess::Vector{Function}
  maxCols::Nullable{Int}

  function DPA()
    return new(cor, [hw], [abs], Nullable())
  end
end

type LRA <: NonIncrementalAnalysis
  basisModel::Function
  postProcess::Vector{Function}
  maxCols::Nullable{Int}

  function LRA(basisModel)
    return new(basisModel, [])
  end

  function LRA()
    return new(basisModelSingleBits, [], Nullable())
  end
end

type IncrementalCPA <: Analysis
  leakageFunctions::Vector{Function}
  postProcess::Vector{Function}
  reducer::Function

  function IncrementalCPA()
    return new([hw], [abs], x -> max(abs(x)))
  end
end

function printParameters(a::IncrementalCPA)
  @printf("leakages:   %s\n", a.leakageFunctions)
end

function printParameters(a::LRA)
  @printf("basismodel: %s\n", a.basisModel)
end

function printParameters(a::DPA)
  @printf("statistic:  %s\n", a.statistic)
  @printf("leakages:   %s\n", a.leakageFunctions)
end

getNrLeakageFunctions(a::LRA) = 1
getNrLeakageFunctions(a::DPA) = length(a.leakageFunctions)
getNrLeakageFunctions(a::IncrementalCPA) = length(a.leakageFunctions)

abstract Attack

# currently supported: LRA and DPA

# (mostly) running a CPA attack, but is not called CPA because it's not necessarly using correlation. You can plug another function in the DPA type "statistic" field. But anyway, it's mostly CPA.
function attack(a::DPA, trs::Trace, range::Range, keyByteOffsets::Vector{Int}, dataFunction::Function, dataFunctionReturnType::DataType, kbvals::Vector, scoresAndOffsets)

  attackfun = (data, samples, keyByteOffsets) -> dpa(data, samples, keyByteOffsets, dataFunction, a.leakageFunctions, a.statistic, kbvals, dataFunctionReturnType, UInt8)

  attack(convert(NonIncrementalAnalysis, a), attackfun, trs, range, keyByteOffsets, dataFunction, dataFunctionReturnType, kbvals, scoresAndOffsets)

end

function attack(a::NonIncrementalAnalysis, attackfun::Function, trs::Trace, range::Range, keyByteOffsets::Vector{Int}, dataFunction::Function, dataFunctionReturnType::DataType, kbvals::Vector, scoresAndOffsets)

  ((data, samples), eof) = @time readTraces(trs, range)

  if data == nothing || samples == nothing
    return
  end

  for kb in 1:length(keyByteOffsets)
    if hasPostProcessor(trs)
      kbsamples = samples[kb]
      kbdata = data[kb]
    else
      kbsamples = samples
      kbdata = reshape(data[:,kb], size(data)[1], 1)
    end

    cols = size(kbsamples)[2]
    # FIXME: need to pick something sane here
    maxCols = get(a.maxCols, 10000)

    for sr in 1:maxCols:cols
      srEnd = min(sr+maxCols-1, cols)
      @printf("%s on samples shape %s (range %s) and data shape %s\n", string(typeof(a).name.name), size(kbsamples), string(sr:srEnd), size(kbdata))
      if size(kbsamples)[2] == 0
        @printf("no samples!\n")
        scores = nothing
        continue
      end

      # run the attack
      @time C = attackfun(kbdata, kbsamples[:,sr:srEnd], [keyByteOffsets[kb]])

      # nop the nans
      C[isnan(C)] = 0

      # get the scores for all leakage functions
      updateScoresAndOffsets!(scoresAndOffsets, C, 1, kb, getNrLeakageFunctions(a), a.postProcess, length(kbvals))
    end
  end
end

# running an LRA attack (I know this is also a DPA attack, I know, but it's a completely different beast from correlation, mia, or difference of means)
function attack(a::LRA, trs::Trace, range::Range, keyByteOffsets::Vector{Int}, dataFunction::Function, dataFunctionReturnType::DataType, kbvals::Vector, scoresAndOffsets)
  attackfun = (data, samples, keyByteOffsets) -> lra(data, samples, keyByteOffsets, dataFunction, a.basisModel, kbvals)

  attack(convert(NonIncrementalAnalysis, a), attackfun, trs, range, keyByteOffsets, dataFunction, dataFunctionReturnType, kbvals, scoresAndOffsets)
end


function attack(a::IncrementalCPA, trs::Trace, range::Range, keyByteOffsets::Vector{Int}, dataFunction::Function, dataFunctionReturnType::DataType, kbvals::Vector, scoresAndOffsets)
  if isa(trs, DistributedTrace)
    @sync for w in workers()
      @spawnat w init(Main.trs.postProcInstance, keyByteOffsets, dataFunction, kbvals, a.leakageFunctions)
    end
  else
    init(trs.postProcInstance, keyByteOffsets, dataFunction, kbvals, a.leakageFunctions)
  end

  @time (C,eof) = readTraces(trs, range)

  for kb in 1:length(keyByteOffsets)
    updateScoresAndOffsets!(scoresAndOffsets, C, kb, kb, length(a.leakageFunctions), a.postProcess, length(kbvals))
  end
end

# does the attack & analysis per xxx traces, should be called from an scatask
function analysis(params::Attack, phase::Enum, trs::Trace, firstTrace::Int, numberOfTraces::Int, targetFunction::Function, targetFunctionType::Type, kbVals::Vector{UInt8}, keyByteOffsets::Vector{Int})
    local scoresAndOffsets

    if !isnull(params.updateInterval) && !hasPostProcessor(trs)
        @printf("WARNING: update interval only supported for traces with a post processor, option ignored\n")
        updateInterval = Nullable()
    end

    offset = firstTrace
    stepSize = min(numberOfTraces, get(params.updateInterval, numberOfTraces))

    scoresAndOffsets = allocateScoresAndOffsets(getNrLeakageFunctions(params.analysis), length(kbVals), length(keyByteOffsets))
    eof = false

    for offset in firstTrace:stepSize:numberOfTraces
      range = offset:(offset+min(stepSize, numberOfTraces - offset + 1)-1)

      if eof
        break
      end
      
      clearScoresAndOffsets!(scoresAndOffsets)

      attack(params.analysis, trs, range, keyByteOffsets, targetFunction, targetFunctionType, kbVals, scoresAndOffsets)

      # let somebody do something with the scores for these traces
      produce(INTERMEDIATESCORES, (scoresAndOffsets, getCounter(trs), length(keyByteOffsets), keyByteOffsets, !isnull(params.knownKey) ? getCorrectRoundKeyMaterial(params, phase) : Nullable()))
    end

    # reset the state of trace post processor (conditional averager)
    reset(trs)

    # return the final combined scores to scatask
    scores = getCombinedScores(scoresAndOffsets)

    return scores
end

@enum Direction FORWARD=1 BACKWARD=2
@enum Phase PHASE1 PHASE2 PHASE3 PHASE4 PHASE5 PHASE6
@enum Status FINISHED PHASERESULT INTERMEDIATESCORES INTERMEDIATESCORESANDOFFSETS INTERMEDIATECORRELATION

for s in instances(Direction); @eval export $(Symbol(s)); end
for s in instances(Phase); @eval export $(Symbol(s)); end
for s in instances(Status); @eval export $(Symbol(s)); end

# generic sca function, this one is called in all the unit tests and the main functions
function sca(trs::Trace, params::Attack, firstTrace::Int=1, numberOfTraces::Int=length(trs), printSubs::Bool=false, scoresCallBack::Nullable{Function}=Nullable{Function}())
  @printf("\nJlsca running in Julia version: %s, %d processes/%d workers\n\n", VERSION, nprocs(), nworkers())

  printParameters(params)

  local key
  local status = nothing
  local phaseInput = params.phaseInput

  if length(params.phases) == 0
    params.phases = getPhases(params)
  end

  if !isnull(params.outputkka) && !isnull(params.knownKey)
    # kkaFilename = @sprintf("%s.kka_%s.csv", trs.filename, toShortString(params))
    kkaFilename = get(params.outputkka)
    truncate(kkaFilename)
  end

  finished = false

  for phase in params.phases
    if finished
      break
    end

    @printf("\nphase: %s\n\n", phase)

    # function scatask is overloaded for the params type
    t::Task = @task scatask(trs, params, firstTrace, numberOfTraces, phase, phaseInput)

    try
      # iterate through whatever scatask is producing
      for (status, statusData) in t
        if status == FINISHED
          finished = true
          key = statusData
          if key != nothing
            @printf("recovered key: %s\n", bytes2hex(key))
            if !isnull(params.knownKey)
              @printf("knownkey match: %s\n", string(key == get(params.knownKey)))
            end
          end
        elseif status == INTERMEDIATESCORES
          (scoresAndOffsets, numberOfTraces2, dataWidth, keyOffsets, knownKey) = statusData
          printScores(scoresAndOffsets, dataWidth, keyOffsets, numberOfTraces2, (+), knownKey, printSubs,  5)

          if !isnull(params.outputkka) && !isnull(params.knownKey)
            add2kka(scoresAndOffsets, dataWidth, keyOffsets, numberOfTraces2, get(knownKey), kkaFilename)
          end

          if !isnull(scoresCallBack)
            get(scoresCallBack)(phase, params, scoresAndOffsets, dataWidth, keyOffsets, numberOfTraces2)
          end
        elseif status == PHASERESULT
          phaseInput = statusData
          if !isnull(phaseInput)
            @printf("next phase input: %s\n", bytes2hex(get(phaseInput)))
          end
        else
          @printf("WARNING: don't know how to handle %s produced by scatask for %s\n", string(status), string(params))
        end
      end
    catch e
      if t.exception != nothing
        # @printf("Task blew up: %s", t.exception)
        Base.show_backtrace(STDOUT, t.backtrace)
        @printf("\n")
      end
      rethrow(e)
    end
  end

  if !isnull(params.outputkka) && !isnull(params.knownKey)
    @printf("KKA output in %s\n", get(params.outputkka))
  end

  if status == FINISHED
    # tests rely on the recovered key being returned
    return key
  end
end


# fills the attack parameters with data from the file name
function getParameters(filename::AbstractString, direction::Direction)
  local params::Attack

  m = match(r"aes([0-9]+)_(..)_([^_]*)_([a-zA-Z0-9]*)", filename)
  if m != nothing
    if m.captures[2] == "sb"
      params = AesSboxAttack()
    elseif m.captures[2] == "mc"
      params = AesMCAttack()
    end
    params.keyLength::AesKeyLength = div(parse(m.captures[1]),8)
    modeStr = m.captures[3]
    if modeStr == "ciph"
      params.mode = CIPHER
    elseif modeStr == "invciph"
      params.mode = INVCIPHER
    elseif modeStr == "eqinvciph"
      params.mode = EQINVCIPHER
    end

    params.knownKey = hex2bytes(m.captures[4])
    params.keyByteOffsets = collect(1:16)
    params.direction = direction
    if direction == FORWARD
      params.dataOffset = 1
    else
      params.dataOffset = 17
    end
    return params
  end

  m = match(r"([t]{0,1}des[1-3]{0,1})_([^_]*)_([a-zA-Z0-9]*)", filename)
  if m != nothing
    params = DesSboxAttack()
    params.analysis = DPA()
    params.analysis.leakageFunctions = [bit0, bit1, bit2, bit3]
    modeStr = m.captures[1]
    if modeStr == "des"
      params.mode = DES
    elseif modeStr == "tdes1"
      params.mode = TDES1
    elseif modeStr == "tdes2"
      params.mode = TDES2
    elseif modeStr == "tdes3"
      params.mode = TDES3
    end

    params.encrypt = (m.captures[2] == "enc" ? true : false)

    params.knownKey = hex2bytes(m.captures[3])
    params.direction = direction
    if direction == FORWARD
      params.dataOffset = 1
    else
      params.dataOffset = 9
    end
    return params
  end

end
