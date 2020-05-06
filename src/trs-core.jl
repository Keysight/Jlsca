# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ProgressMeter

import Base.getindex, Base.setindex!, Base.iterate
import Base.reset

export readTraces,addSamplePass,popSamplePass,addDataPass,popDataPass,hasPostProcessor,reset,getCounter
export setindex!

export Pass

abstract type Pass end

export MetaData

mutable struct MetaData
  tracesReturned::Int
  passes::Vector{Pass}
  dataPasses::Vector{Pass}
  postProcInstance::Union{Missing,PostProcessor}
  colRange::Union{Missing,UnitRange}
  preColRange::Union{Missing,UnitRange}
  viewsdirty::Bool
  views::Vector{Union{Missing,UnitRange}}
  lengths::Vector{Int}
  types::Vector{AbstractVector}

  function MetaData()
    new(0, Vector{Pass}(undef,0), Vector{Pass}(undef,0), missing, missing, missing, true)
  end
end

export Traces

"""
Implementations of trace sets (InspectorTrace, SplitBinary) extend this type.
"""
abstract type Traces end

"""
Traces return instances of this type with getindex. The default is DefaultTrace
"""
abstract type Trace end

"""
A default trace has a data and a sample vector, and instances of DefaultTrace are accepted by setindex! and getindex for all Traces. Trace set implementations (i.e. types inheriting Traces) may specialize this, but then they need to implement getindex and setindex! to return and accept that specialized type, without breaking the order data,samples.
"""
struct DefaultTrace <: Trace
  data::AbstractVector
  samples::AbstractVector
end

getindex(t::DefaultTrace, i::Int) = (i == 1 ? t.data : i == 2 ? t.samples : throw(ArgumentError("only 1 (data) or 2 (samples) index supported")))

iterate(t::DefaultTrace, i::Int=1) = (i == 1 ? (t.data,2) : i == 2 ? (t.samples,3) : nothing)

export meta

meta(trs::Traces) = error("implement me for $(typeof(trs))")

import Base.length
export length

length(trs::Traces) = error("implement me for $(typeof(trs))")

export pass

pass(a::Pass, x::AbstractVector, idx::Int) = error("implement me for $(typeof(a))")
pass(a::Pass, x::AbstractVector, idx::Int, cols::UnitRange) = pass(a,x,idx)[cols] 

export inview

inview(a::Pass, outview::UnitRange, inlength::Int, intype::AbstractVector) = missing

export outlength

outlength(a::Pass, inlength::Int, intype::AbstractVector) = -1

export outtype

outtype(a::Pass, intype::AbstractVector) = Vector{Any}(undef,0)

mutable struct SimpleFunctionPass <: Pass 
  fn::Function
end

pass(a::SimpleFunctionPass, x::AbstractVector, idx::Int) = a.fn(x) 

export nrsamples

nrsamples(trs::Traces, post::Bool) = (updateViews(trs);meta(trs).lengths[post ? end : 1])
nrsamples(trs::Traces) = error("implement me for $(typeof(trs))")

export sampletype

sampletype(trs::Traces, post::Bool) = (updateViews(trs);meta(trs).types[post ? end : 1])
sampletype(trs::Traces) = error("implement me for $(typeof(trs))")

function updateViews(trs::Traces)
  m = meta(trs)
  if !m.viewsdirty
    return 
  end

  nrPasses = length(m.passes)
  lengths = zeros(Int,nrPasses+1)
  views = Vector{Union{Missing,UnitRange}}(undef,nrPasses+1)
  types = Vector{AbstractVector}(undef,nrPasses+1)

  fast = true

  if !ismissing(m.preColRange)
    lengths[1] = length(m.preColRange)
  else
    lengths[1] = nrsamples(trs)
  end

  types[1] = sampletype(trs)

  for i in eachindex(m.passes)
    p = m.passes[i]
    t = outtype(p,types[i])
    l = outlength(p,lengths[i],types[i])
    if l == -1
      fast = false
      break
    end
    lengths[i+1] = l
    types[i+1] = t
  end

  # @show fast

  if !fast 
    idx = 1
    zerolength = true
    while zerolength 
      if !ismissing(m.preColRange)
        samples = readSamples(trs, idx, m.preColRange)
      else
        samples = readSamples(trs, idx)
      end

      lengths[1] = length(samples)
      types[1] = Vector{eltype(samples)}(undef,0)

      for i in eachindex(m.passes)
        p = m.passes[i]
        samples = pass(p, samples, idx)
        if length(samples) != 0
          zerolength = false
        else
          zerolength = true
          break
        end
        lengths[i+1] = length(samples)
        types[i+1] = Vector{eltype(samples)}(undef,0)
      end

      if zerolength
        idx += 1
      end
    end
  end

  # @show lengths
  # @show types

  v = m.colRange
  views[nrPasses+1] = v
  for i in eachindex(m.passes)
    o = nrPasses-i+1
    p = m.passes[o]
    if !ismissing(v)
      v = inview(p,v,lengths[o],types[o])
    end
    views[i] = v
  end

  if !ismissing(m.preColRange)
    if !ismissing(views[1])
      views[1] = m.preColRange[views[1]]
    else
      views[1] = m.preColRange
    end
  end
  
  # @show views

  if !ismissing(m.colRange) && !ismissing(views[1]) 
    printstyled("Efficient trace sample reads!! Yay!\n", color=:magenta)
  end

  m.views = views
  m.lengths = lengths
  m.types = types
  m.viewsdirty = false
end

"""
Reads the data for a given trace, after running it through all the data passes, if any.
"""
function getData(trs::Traces, idx)
  data = readData(trs, idx)

  # run all the passes over the data
  for p in meta(trs).dataPasses
    data = pass(p,data,idx)
    if length(data) == 0
      break
    end
  end

  return data
end

"""
Reads the samples for a given trace, after running it through all the samples passes, if any.
"""
function getSamples(trs::Traces, idx)
  local samples
  m = meta(trs)

  updateViews(trs)

  v = m.views[1]
  if !ismissing(v)
    samples = readSamples(trs, idx, v)
  else
    samples = readSamples(trs, idx)
  end

  # run all the passes over the trace
  for i in eachindex(m.passes)
    p = m.passes[i]
    v = m.views[i+1]
    if !ismissing(v)
      samples = pass(p, samples, idx, v)
    else
      samples = pass(p, samples, idx)
    end
    if length(samples) == 0
      break
    end
  end

  return samples
end

function getindex(trs::Traces, idx)
  data = getData(trs, idx)
  samples = getSamples(trs, idx)
  return DefaultTrace(data, samples)
end

function setindex!(trs::Traces, t, idx::Int)
  writeData(trs, idx, t[1])
  writeSamples(trs, idx, t[2])
end

"""
Add a sample pass (as a function with one argument) to the list of passes for this trace set
"""
addSamplePass(trs::Traces, f::Function, prprnd=false) = addSamplePass(trs, SimpleFunctionPass(f), prprnd)

"""
Add a sample pass (as an instance of type Pass) to the list of passes for this trace set. Instances of Pass can keep a state; alignment would need this for examples.
"""
function addSamplePass(trs::Traces, p::Pass, prprnd=false)
  m = meta(trs)
  m.viewsdirty = true

  if prprnd == true
    m.passes = vcat(p, m.passes)
  else
    m.passes = vcat(m.passes, p)
  end
  return nothing
end

export setColumnRange

"""
  Column range *after* all the sample passses returned on read. This is called internally in `sca` to allow efficient column-wise DPA. If you're looking to efficiently limit the #samples read from disk see `setPreColumnRange`.
"""
function setColumnRange(trs::Traces, r::Union{Missing,UnitRange})
  m = meta(trs)
  m.viewsdirty = true
  m.colRange = r
end

export setPreColumnRange

"""
  Column range *before* all the sample passes. For example, if you have a large trace set with traces with many samples, and you only want to run the passes on the first million samples. 
"""
function setPreColumnRange(trs::Traces, r::Union{Missing,UnitRange})
  m = meta(trs)
  m.viewsdirty = true
  m.preColRange = r
end

"""
Removes a sample pass
"""
function popSamplePass(trs::Traces, fromStart=false)
  m = meta(trs)
  m.viewsdirty = true

  if fromStart
    m.passes = m.passes[2:end]
  else
    m.passes = m.passes[1:end-1]
  end
  return nothing
end

"""
Add a data pass (as a function with single argument)
"""
addDataPass(trs::Traces, f::Function, prprnd=false) = addDataPass(trs, SimpleFunctionPass(f), prprnd)

"""
Add a data pass (as an instance of type Pass) to the list of passes for this trace set. Instances of Pass can keep or read from state. I've used this for labeling traces after a clustering, where the label are stored in the Pass.
"""
function addDataPass(trs::Traces, f::Pass, prprnd=false)
  m = meta(trs)
  if prprnd == true
    m.dataPasses = vcat(f, m.dataPasses)
  else
    m.dataPasses = vcat(m.dataPasses, f)
  end
  return nothing
end

 
"""Pops a data pass"""
function popDataPass(trs::Traces, fromStart=false)
  m = meta(trs)
  if fromStart
    m.dataPasses = m.dataPasses[2:end]
  else
    m.dataPasses = m.dataPasses[1:end-1]
  end
  return nothing
end

"""Removes the data processor instance and sets the number of traces it fed into the post processor to 0."""
function reset(trs::Traces)
  m = meta(trs)
  if !ismissing(m.postProcInstance)
    reset(m.postProcInstance)
  end
  m.tracesReturned = 0
end

"""Returns the number of traces that were read"""
function getCounter(trs::Traces)
  return meta(trs).tracesReturned
end

"""Set a post processor"""
function setPostProcessor(trs::Traces, p::Union{Missing,Type{<: PostProcessor}})
  if ismissing(p)
    meta(trs).postProcInstance = missing
  else
    meta(trs).postProcInstance = p()
  end
end

export initPostProcessor

"""calls init on the post processor with variable arguments"""
function initPostProcessor(trs::Traces, args...)
  init(meta(trs).postProcInstance,args...)
end


"""Returns true when a post processor is set to this trace set"""
function hasPostProcessor(trs::Traces)
  return !ismissing(meta(trs).postProcInstance)
end

"""Read all traces, and return as (data,samples) tuple of matrices in case of no postprocessor, or whatever the postprocessor decides to return. For example, IncrementalCorrelation returns a correlation matrix, CondAvg returns a (data,samples) tuple where data is a vector of vectors, and samples is vector of matrices."""
function readTraces(trs::Traces, range::UnitRange)
  if isa(trs, DistributedTrace) || hasPostProcessor(trs)
    return readAndPostProcessTraces(trs, range)
  else
    return readNoPostProcessTraces(trs, range)
  end
end

# read traces without conditional averaging (but with all the data and sample passes), creates huge matrices, use with care
function readNoPostProcessTraces(trs::Traces, range::UnitRange)
  numberOfTraces = length(trs)
  readCount = 0
  allSamples = nothing
  allData = nothing
  eof = false
  local data, samples, dataLength, sampleLength

  traceLength = length(range)

  progress = Progress(traceLength-1, 1, "Processing traces .. ")

  for idx in range
    (data, samples) = trs[idx]

    if length(samples) == 0
      continue
    end

    if allSamples == nothing || allData == nothing
        # first time, so allocate
        sampleLength = length(samples)
        dataLength = length(data)
        if isa(samples, BitVector)
          # bit vectors are 8 times better than Vectors of bools since bit vectors are packed
          allSamples = BitVector(undef,sampleLength * traceLength)
        else
          allSamples = Vector{eltype(samples)}(undef,sampleLength * traceLength)
        end
        allData = Vector{eltype(data)}(undef,dataLength * traceLength)
    end

    allSamples[readCount*sampleLength+1:readCount*sampleLength+sampleLength] = samples
    allData[readCount*dataLength+1:readCount*dataLength+dataLength] = data

    # valid trace, bump read counter
    readCount += 1

    update!(progress, idx)
  end

  meta(trs).tracesReturned += readCount

  # resize & reshape that shit depending on the readCount
  resize!(allData, (dataLength*readCount))
  resize!(allSamples, (sampleLength*readCount))

  allData = permutedims(reshape(allData, (dataLength, readCount)))
  allSamples = permutedims(reshape(allSamples, (sampleLength, readCount)))

  return ((allData, allSamples), eof)
end

function getPostProcessorResult(trs::Traces)
  return get(meta(trs).postProcInstance)
end

@inline function add(c::PostProcessor, trs::Traces, idx::Int)
      data = getData(trs,idx)
      if length(data) == 0
        return
      end

      samples = getSamples(trs,idx)
      if length(samples) == 0
        return
      end

      add(c,samples,data,idx)
end

function add(c::PostProcessor, trs::Traces, localrange::Tuple, progressch)
  traceStart,traceStep,traceEnd = localrange
  rangestr = "trace range $(traceStart:traceStep:traceEnd)"
  m = meta(trs)
  print("Running \"$c\" on $rangestr, $(length(m.dataPasses)) data passes, $(length(m.passes)) sample passes\n")
  counter = 0
  t1 = time()
  # uncomment for hot loop profiling
  # Profile.clear_malloc_data()
  # Profile.start_timer()
  for idx in traceStart:traceStep:traceEnd
    add(c,trs,idx)

    counter += 1

    t2 = time()
    if t2 - t1 > 1.0
      t1 = time()
      put!(progressch,counter)
      counter = 0
    end
  end
  # uncomment for hot loop profiling
  # Profile.stop_timer()
  # Profile.print(maxdepth=20,combine=true)
  # exit()

  put!(progressch,counter)
  m.tracesReturned = getGlobCounter(c)
end

function readAndPostProcessTraces(trs2::Traces, globalrange::UnitRange)
  global progress
  traceLength = length(globalrange)

  progress = Progress(traceLength, 1, "Processing traces $globalrange ..")
  
  progressch = RemoteChannel(() -> Channel{Int}(0))

  if isa(trs2, DistributedTrace)
      ww = workers()
      futures = Vector{Future}(undef,length(ww))
      channels = [Channel{Any}(1) for w in 1:length(ww)]

      for w in eachindex(ww)
          futures[w] = @spawnat ww[w] begin
            localrange = getWorkerRange(trs2.worksplit,globalrange)
            localtrs = trs2.trsfn()
            add(meta(localtrs).postProcInstance, localtrs, localrange, progressch)
            myid()
          end
      end

      ct = current_task()
      for w in eachindex(ww)
        @async begin
          try
            put!(channels[w],fetch(futures[w]))
          catch e
            Base.throwto(ct, e)
          finally
            put!(progressch,0)
          end
        end
      end
  else
    ww = [1]
    channels = [Channel{Any}(1) for w in 1:length(ww)]
    localrange = globalrange[1],1,globalrange[end]
    ct = current_task()
    @async begin
      try
        add(meta(trs2).postProcInstance, trs2, localrange, progressch)
        put!(channels[1],true)
      catch e
        print(e)
        print("\n")
        print("\n")
        print("\n")
        print("\n")
        print("\n")
                      for (exc, bt) in Base.catch_stack()
                   showerror(stdout, exc, bt)
                   println()
               end

        Base.throwto(ct, e)
      finally
        put!(progressch,0)
      end
    end
  end

  cnt = 0
  done = false
  while !done
      cnt += take!(progressch)
      update!(progress,cnt)

      done = true

      for w in eachindex(ww)
          done &= isready(channels[w])
      end
  end

  # finish!(progress)

  ret = getPostProcessorResult(trs2)

  return (ret, true)
end

inIJulia() = isdefined(Main, :IJulia) && Main.IJulia.inited
