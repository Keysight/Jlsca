# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ProgressMeter

import Base.length, Base.getindex, Base.setindex!, Base.iterate
import Base.reset

export readTraces,addSamplePass,popSamplePass,addDataPass,popDataPass,hasPostProcessor,reset,getCounter,setPostProcessor
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

export pass

pass(a::Pass, x::AbstractVector, idx::Int) = error("implement me for $(typeof(a))")
pass(a::Pass, x::AbstractVector, idx::Int, cols::UnitRange) = pass(a,x,idx)[cols] 

export inview

inview(a::Pass, outview::UnitRange, inlength::Int, intype::AbstractVector) = Union{Missing}()

export outlength

outlength(a::Pass, inlength::Int, intype::AbstractVector) = -1

export outtype

outtype(a::Pass, intype::AbstractVector) = Vector{Any}(undef,0)

mutable struct SimpleFunctionPass <: Pass 
  fn::Function
end

pass(a::SimpleFunctionPass, x::AbstractVector, idx::Int) = a.fn(x) 

# overloading these to implement an iterator
# start(trs::Traces) = 1
# done(trs::Traces, idx) = pipe(trs) ? false : (idx > length(trs))
# next(trs::Traces, idx) = (trs[idx], idx+1)
# endof(trs::Traces) = length(trs)

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
    if !ismissing(m.preColRange)
      samples = readSamples(trs, idx, m.preColRange)
    else
      samples = readSamples(trs, idx)
    end

    lengths[1] = length(samples)

    for i in eachindex(m.passes)
      p = m.passes[i]
      samples = pass(p, samples, idx)
      lengths[i+1] = length(samples)
    end
  end

  # @show lengths

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
    if !ismissing(m.views[1])
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
function setPostProcessor(trs::Traces, p::PostProcessor)
  meta(trs).postProcInstance = p
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

  if !pipe(trs)
    progress = Progress(traceLength-1, 1, "Processing traces .. ")
  end

  for idx in range
    (data, samples) = trs[idx]

    if length(data) == 0 || length(samples) == 0
      continue
    end

    if allSamples == nothing || allData == nothing
        # first time, so allocate
        sampleLength = length(samples)
        dataLength = length(data)
        if isa(samples, BitVector)
          # bit vectors are 8 times better than Vectors of bools since bit vectors are packed
          allSamples = BitVector(sampleLength * traceLength)
        else
          allSamples = Vector{eltype(samples)}(undef,sampleLength * traceLength)
        end
        allData = Vector{eltype(data)}(undef,dataLength * traceLength)
    end

    allSamples[readCount*sampleLength+1:readCount*sampleLength+sampleLength] = samples
    allData[readCount*dataLength+1:readCount*dataLength+dataLength] = data

    # valid trace, bump read counter
    readCount += 1

    if !pipe(trs)
      update!(progress, idx)
    end
  end

  meta(trs).tracesReturned += readCount

  # resize & reshape that shit depending on the readCount
  resize!(allData, (dataLength*readCount))
  resize!(allSamples, (sampleLength*readCount))

  allData = reshape(allData, (dataLength, readCount))'
  allSamples = reshape(allSamples, (sampleLength, readCount))'

  return ((allData, allSamples), eof)
end

function updateProgress(x::Int)
  progress = Main.getProgress()
  if progress != nothing
    update!(progress, progress.counter + x)
  end
end

function readAndPostProcessTraces(trs2::Traces, range::UnitRange)
  traceLength = length(range)

  if isa(trs2, DistributedTrace)
    worksplit = @fetch meta(Main.trs).postProcInstance.worksplit
  else
    worksplit = meta(trs2).postProcInstance.worksplit
  end

  if !pipe(trs2)
    progress = Progress(traceLength, 1, @sprintf("Processing traces %s.. ", range))
  else
    progress = nothing
  end

  @everywhere getProgress()=$progress

  if isa(trs2, DistributedTrace)
    @sync begin
      for w in workers()
        @async begin
          @fetchfrom w begin
            add(meta(Main.trs).postProcInstance, Main.trs, range, updateProgress)
          end
        end
      end
    end
  else
    add(meta(trs2).postProcInstance, trs2, range, updateProgress)
  end

  if progress != nothing
    finish!(progress)
  end

  if isa(trs2, DistributedTrace)
    worker1copy = @fetchfrom workers()[1] meta(Main.trs).postProcInstance
    ret = get(worker1copy)
  else
    ret = get(meta(trs2).postProcInstance)
  end

  return (ret, true)

end

inIJulia() = isdefined(Main, :IJulia) && Main.IJulia.inited
