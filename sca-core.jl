# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Dpa
using Lra
using Trs

export Attack,Analysis,LRA,DPA
export analysis,attack
export sca
export scatask
export Status
export printParameters,getParameters
export Direction,Phase
export getNumberOfCandidates

abstract Analysis

# two types of analysis methods: DPA and LRA
type DPA <: Analysis
  statistic::Function
  leakageFunctions::Vector{Function}
  postProcess::Vector{Function}

  function DPA()
    return new(cor, [hw], [abs])
  end
end

type LRA <: Analysis
  basisModel::Function
  postProcess::Vector{Function}

  function LRA(basisModel)
    return new(basisModel, [])
  end

  function LRA()
    return new(basisModelSingleBits, [])
  end
end

function printParameters(a::LRA)
  @printf("basismodel: %s\n", a.basisModel)
end

function printParameters(a::DPA)
  @printf("statistic:  %s\n", a.statistic)
  @printf("leakages:   %s\n", a.leakageFunctions)
end

abstract Attack

# currently supported: LRA and DPA

# (mostly) running a CPA attack, but is not called CPA because it's not necessarly using correlation. You can plug another function in the DPA type "statistic" field. But anyway, it's mostly CPA.
function attack(a::DPA, data, samples, keyByteOffsets::Vector{Int}, dataFunction::Function, dataFunctionReturnType::DataType=UInt8, kbvals=collect(UInt8, 0:255))
  @time C = dpa(data, samples, keyByteOffsets, dataFunction, a.leakageFunctions, a.statistic, kbvals, dataFunctionReturnType, UInt8)

  return (C, length(keyByteOffsets), length(a.leakageFunctions), length(kbvals))
end

# running an LRA attack (I know this is also a DPA attack, I know, but it's a completely different beast from correlation, mia, or difference of means)
function attack(a::LRA, data, samples, keyByteOffsets::Vector{Int}, dataFunction::Function, dataFunctionReturnType::DataType=UInt8, kbvals=collect(UInt8, 0:255))
  @time C = lra(data, samples, keyByteOffsets, dataFunction, a.basisModel, kbvals)

  return (C, length(keyByteOffsets), 1, length(kbvals))
end

# does the attack & analysis per xxx traces, should be called from an scatask
function analysis(params::Attack, phase::Enum, trs::Trace, firstTrace::Int, numberOfTraces::Int, targetFunction::Function, targetFunctionType::Type, kbVals::Vector{UInt8}, keyByteOffsets::Vector{Int})
    local scoresAndOffsets

    if !isnull(params.updateInterval) && !hasPostProcessor(trs)
        @printf("WARNING: update interval only supported for conditionally averaged traces, option ignored\n")
        updateInterval = Nullable()
    end

    offset = firstTrace
    stepSize = min(numberOfTraces, get(params.updateInterval, numberOfTraces))

    eof = false

    for offset in firstTrace:stepSize:numberOfTraces
      if eof
        break
      end

      # read traces
      (data, samples, eof) = @time readTraces(trs, offset, min(stepSize, numberOfTraces - offset + 1))

      if data == nothing || samples == nothing
        scores = nothing
        break
      end

      scoresAndOffsets = nothing

      if isa(samples[1], Array)
          length(samples) == length(keyByteOffsets) || throw(ErrorException("attack implementation broken"))

          for l in 1:length(keyByteOffsets)
            @printf("%s on samples shape %s and data shape %s\n", string(typeof(params.analysis).name.name), size(samples[l]), size(data[l]))
            if size(samples[l])[2] == 0
              @printf("no samples!\n")
              scores = nothing
              continue
            end

            # run the attack
            (C, nrKeyBytes, nrLeakageFunctions, nrKbVals) = attack(params.analysis, data[l], samples[l], [keyByteOffsets[l]], targetFunction, targetFunctionType, kbVals)

            # nop the nans
            C[isnan(C)] = 0

            if scoresAndOffsets == nothing
              scoresAndOffsets = allocateScoresAndOffsets(nrLeakageFunctions, length(kbVals), length(keyByteOffsets))
            end

            # get the scores for all leakage functions
            getScoresAndOffsets!(scoresAndOffsets, C, 1, l, nrLeakageFunctions, params.analysis.postProcess, nrKbVals)
          end
      else
        @printf("%s on %s samples shape %s and %s data shape %s\n", string(typeof(params.analysis).name.name), eltype(samples), size(samples), eltype(data), size(data))
        if size(samples)[2] == 0
          @printf("no samples!\n")
          scores = nothing
          break
        end

        # run the attack
        (C, nrKeyBytes, nrLeakageFunctions, nrKbVals) = attack(params.analysis, data, samples, keyByteOffsets, targetFunction, targetFunctionType, kbVals)

        # nop the nans
        C[isnan(C)] = 0

        if scoresAndOffsets == nothing
          scoresAndOffsets = allocateScoresAndOffsets(nrLeakageFunctions, length(kbVals), length(keyByteOffsets))
        end

        for l in 1:length(keyByteOffsets)
          # get the scores for all leakage functions
          getScoresAndOffsets!(scoresAndOffsets, C, l, l, nrLeakageFunctions, params.analysis.postProcess, nrKbVals)
        end
      end

      if scoresAndOffsets != nothing
        # let somebody do something with the scores for these traces
        produce(INTERMEDIATESCORES, (scoresAndOffsets, getCounter(trs), size(C)[1], length(keyByteOffsets), keyByteOffsets, !isnull(params.knownKey) ? getCorrectRoundKeyMaterial(params, phase) : Nullable()))
      end
    end

    # reset the state of trace post processor (conditional averager)
    reset(trs)

    if scoresAndOffsets != nothing
      # return the final combined scores to scatask
      scores = getCombinedScores(scoresAndOffsets)
    else
      throw(ErrorException("no samples"))
    end

    return scores
end

@enum Direction FORWARD=1 BACKWARD=2
@enum Phase PHASE1 PHASE2 PHASE3 PHASE4 PHASE5 PHASE6
@enum Status FINISHED PHASERESULT INTERMEDIATESCORES INTERMEDIATESCORESANDOFFSETS INTERMEDIATECORRELATION

# generic sca function, this one is called in all the unit tests and the main functions
function sca(trs::Trace, params::Attack, firstTrace=1, numberOfTraces=length(trs), printSubs=false)
  @printf("\nJlsca running in Julia version: %s\n\n", VERSION)

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
          (scoresAndOffsets, numberOfTraces2, numberOfSamples, dataWidth, keyOffsets, knownKey) = statusData
          printScores(scoresAndOffsets, dataWidth, keyOffsets, numberOfTraces2, numberOfSamples, (+), knownKey, false,  5)

          if !isnull(params.outputkka) && !isnull(params.knownKey)
            add2kka(scoresAndOffsets, dataWidth, keyOffsets, numberOfTraces2, numberOfSamples, get(knownKey), kkaFilename)
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
        @printf("Task blew up: %s", t.exception)
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
