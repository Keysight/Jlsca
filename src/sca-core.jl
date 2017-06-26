# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ..Trs
using ..Log

import ..Trs.reset

export Attack,Analysis,LRA,MIA,CPA,IncrementalCPA
export analysis,attack
export sca
export scatask
export Status
export printParameters,getParameters
export Direction,Phase
export getNumberOfCandidates

abstract type Analysis end
abstract type NonIncrementalAnalysis <: Analysis end

abstract type Target{In <:Integer, Out <: Integer} end

# three types of analysis methods: CPA and MIA and LRA 
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

abstract type Attack end

function computeScores(a::CPA, data::Matrix{In}, samples::AbstractArray{Float64}, keyByteOffsets::Vector{Int}, target::Target{In,Out}, kbvals::Vector{UInt8}) where {In,Out}
  (tr,tc) = size(samples)
  (dr,dc) = size(data)
  tr == dr || throw(DimensionMismatch())

  HL::Matrix{UInt8} = predict(data, keyByteOffsets, target, kbvals, a.leakages)
  C = cor(samples, HL)
  return C
end

function computeScores(a::MIA, data::Matrix{In}, samples::AbstractArray{Float64}, keyByteOffsets::Vector{Int}, target::Target{In,Out}, kbvals::Vector{UInt8}) where {In,Out}
  (tr,tc) = size(samples)
  (dr,dc) = size(data)
  tr == dr || throw(DimensionMismatch())

  HL::Matrix{UInt8} = predict(data, keyByteOffsets, target, kbvals, a.leakages)
  C = mia(samples, HL, a.sampleBuckets)
  return C
end

function computeScores(a::LRA, data::Matrix{In}, samples::AbstractArray{Float64}, keyByteOffsets::Vector{Int}, target::Target{In,Out}, kbvals::Vector{UInt8}) where {In,Out}
   C = lra(data, samples, keyByteOffsets, target, a.basisModel, kbvals)
  return C
end

function attack(a::NonIncrementalAnalysis, trs::Trace, range::Range, keyByteOffsets::Vector{Int}, target::Target{In,Out}, kbvals::Vector{UInt8}, scoresAndOffsets) where {In,Out}

  local kbsamples::Matrix{Float64}
  local kbdata::Matrix{In}

  (((data, samples), eof),elapsedtime,totalbytesallocated,garbagecollectiontime,alloccounters) = @timed readTraces(trs, range)

  Log.writecsv(a.logfile, elapsedtime)

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

    (rows,samplecols) = size(kbsamples)
    (rows,datacols) = size(kbdata)

    Log.writecsv(a.logfile, rows, samplecols, datacols * getNrLeakageFunctions(a) * length(kbvals))

    # FIXME: need to pick something sane here
    maxCols = get(a.maxCols, 10000)

    totalelapsedtime = 0.0

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
      (C,elapsedtime,totalbytesallocated,garbagecollectiontime,alloccounters) = @timed computeScores(a, kbdata, v, [keyByteOffsets[kb]], target, kbvals)

      totalelapsedtime += elapsedtime

      # nop the nans
      C[isnan.(C)] = 0

      # get the scores for all leakage functions
      updateScoresAndOffsets!(scoresAndOffsets, C, 1, kb, getNrLeakageFunctions(a), a.postProcess, length(kbvals))
    end

    Log.writecsv(a.logfile, totalelapsedtime)

  end
end

function attack(a::IncrementalCPA, trs::Trace, range::Range, keyByteOffsets::Vector{Int}, target::Target, kbvals::Vector{UInt8}, scoresAndOffsets)
  if isa(trs, DistributedTrace)
    @sync for w in workers()
      @spawnat w init(Main.trs.postProcInstance, keyByteOffsets, target, kbvals, a.leakages)
    end
  else
    init(trs.postProcInstance, keyByteOffsets, target, kbvals, a.leakages)
  end

  ((C,eof),elapsedtime,totalbytesallocated,garbagecollectiontime,alloccounters) = @timed readTraces(trs, range)

  rows = length(range)
  (samplecols,hypocols) = size(C) 

  Log.writecsv(a.logfile, elapsedtime)

  for kb in 1:length(keyByteOffsets)
    updateScoresAndOffsets!(scoresAndOffsets, C, kb, kb, length(a.leakages), a.postProcess, length(kbvals))

    Log.writecsv(a.logfile, rows, samplecols, hypocols)

    Log.writecsv(a.logfile, 0)    
  end
end

# does the attack & analysis per xxx traces, should be called from an scatask
function analysis(super::Task, params::Attack, phase::Enum, trs::Trace, firstTrace::Int, numberOfTraces::Int, target::Target, keyByteOffsets::Vector{Int})
    local scoresAndOffsets

    if !isnull(params.updateInterval) && !hasPostProcessor(trs)
        @printf("WARNING: update interval only supported for traces with a post processor, option ignored\n")
        updateInterval = Nullable()
    end

    offset = firstTrace
    stepSize = min(numberOfTraces, get(params.updateInterval, numberOfTraces))

    scoresAndOffsets = allocateScoresAndOffsets(getNrLeakageFunctions(params.analysis), nrKeyByteValues(params), length(keyByteOffsets))
    eof = false

    Log.writecsvheader(params.analysis.logfile, "#traces","#sec prep",map(x -> "#rows kb $x, #cols samples kb $x, #cols hypo kb $x, #secs kb $x", 1:length(keyByteOffsets))...)
    
    for offset in firstTrace:stepSize:numberOfTraces
      range = offset:(offset+min(stepSize, numberOfTraces - offset + 1)-1)

      if eof
        break
      end
      
      Log.writecsv(params.analysis.logfile, length(firstTrace:range[end]))

      clearScoresAndOffsets!(scoresAndOffsets)

      attack(params.analysis, trs, range, keyByteOffsets, target, keyByteValues(params), scoresAndOffsets)

      Log.writecsvnewline(params.analysis.logfile)

      # let somebody do something with the scores for these traces
      yieldto(super, (INTERMEDIATESCORES, (scoresAndOffsets, getCounter(trs), length(keyByteOffsets), keyByteOffsets, !isnull(params.knownKey) ? getCorrectRoundKeyMaterial(params, phase) : Nullable())))
    end

    # reset the state of trace post processor (conditional averager)
    reset(trs)

    # return the final combined scores to scatask
    scores = getCombinedScores(scoresAndOffsets)

    return scores
end

@enum Direction FORWARD=1 BACKWARD=2
@enum Phase PHASE1 PHASE2 PHASE3 PHASE4 PHASE5 PHASE6
@enum Status FINISHED PHASERESULT INTERMEDIATESCORES INTERMEDIATESCORESANDOFFSETS INTERMEDIATECORRELATION BREAK

for s in instances(Direction); @eval export $(Symbol(s)); end
for s in instances(Phase); @eval export $(Symbol(s)); end
for s in instances(Status); @eval export $(Symbol(s)); end

# generic sca function, this one is called in all the unit tests and the main functions
function sca(trs::Trace, params::Attack, firstTrace::Int=1, numberOfTraces::Int=length(trs), printSubs::Bool=false, scoresCallBack::Nullable{Function}=Nullable{Function}())
  @printf("\nJlsca running in Julia version: %s, %d processes/%d workers/%d threads per worker\n\n", VERSION, nprocs(), nworkers(), Threads.nthreads())

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

    ct = current_task()

    # create the scatask with some sugar to catch exceptions
    t = @task begin
       try
          scatask(ct, trs, params, firstTrace, numberOfTraces, phase, phaseInput)
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
      elseif status == BREAK
        break
      else
        @printf("WARNING: don't know how to handle %s produced by scatask for %s\n", string(status), string(params))
      end
    end
  end

  if !isnull(params.outputkka) && !isnull(params.knownKey)
    @printf("KKA output in %s\n", get(params.outputkka))
  end

  return key
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
    params.analysis = CPA()
    params.analysis.leakages = [Bit(i) for i in 0:3]
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
