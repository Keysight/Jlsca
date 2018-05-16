# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ProgressMeter

import Base.length, Base.getindex, Base.setindex!
import Base.reset
import Base.start, Base.done, Base.next, Base.endof


export readTraces,addSamplePass,popSamplePass,addDataPass,popDataPass,hasPostProcessor,reset,getCounter,setPostProcessor
export start,done,next,endof,setindex!

export Pass

abstract type Pass end

export MetaData

type MetaData
  tracesReturned::Int
  passes::Vector{Pass}
  dataPasses::Vector{Pass}
  postProcInstance::Nullable{PostProcessor}
  colRange::Nullable{Range}
  preColRange::Nullable{Range}
  viewsdirty::Bool
  views::Vector{Nullable{Range}}
  lengths::Vector{Int}
  types::Vector{AbstractVector}

  function MetaData()
    new(0, Vector{Pass}(0), Vector{Pass}(0), Nullable(), Nullable(), Nullable(), true)
  end
end

export Trace

abstract type Trace end

export meta

meta(trs::Trace) = error("implement me for $(typeof(trs))")
export pass

pass(a::Pass, x::AbstractArray, idx::Int) = error("implement me for $(typeof(a))")
pass(a::Pass, x::AbstractArray, idx::Int, cols::Range) = pass(a,x,idx)[cols] 

export inview

inview(a::Pass, outview::Range, inlength::Int, intype::AbstractVector) = Nullable{Range}()

export outlength

outlength(a::Pass, inlength::Int, intype::AbstractVector) = -1

export outtype

outtype(a::Pass, intype::AbstractVector) = Vector{Any}(0)

type SimpleFunctionPass <: Pass 
  fn::Function
end

pass(a::SimpleFunctionPass, x::AbstractVector, idx::Int) = a.fn(x) 

# overloading these to implement an iterator
start(trs::Trace) = 1
done(trs::Trace, idx) = pipe(trs) ? false : (idx > length(trs))
next(trs::Trace, idx) = (trs[idx], idx+1)
endof(trs::Trace) = length(trs)

export nrsamples

nrsamples(trs::Trace, post::Bool) = (updateViews(trs);meta(trs).lengths[post ? end : 1])
nrsamples(trs::Trace) = error("implement me for $(typeof(trs))")

export sampletype

sampletype(trs::Trace, post::Bool) = (updateViews(trs);meta(trs).types[post ? end : 1])
sampletype(trs::Trace) = error("implement me for $(typeof(trs))")

function getData(trs::Trace, idx)
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

function updateViews(trs::Trace)
  m = meta(trs)
  if !m.viewsdirty
    return 
  end

  nrPasses = length(m.passes)
  lengths = zeros(Int,nrPasses+1)
  views = Vector{Nullable{Range}}(nrPasses+1)
  types = Vector{AbstractVector}(nrPasses+1)

  fast = true

  if !isnull(m.preColRange)
    lengths[1] = length(get(m.preColRange))
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
    if !isnull(m.preColRange)
      samples = readSamples(trs, idx, get(m.preColRange))
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
    if !isnull(v)
      v = inview(p,get(v),lengths[o],types[o])
    end
    views[i] = v
  end

  if !isnull(m.preColRange)
    if !isnull(m.views[1])
      views[1] = Nullable(get(m.preColRange)[get(views[1])])
    else
      views[1] = m.preColRange
    end
  end
  
  # @show views

  if !isnull(m.colRange) && !isnull(views[1]) 
    print_with_color(:magenta, "Efficient trace sample reads!! Yay!\n")
  end

  m.views = views
  m.lengths = lengths
  m.types = types
  m.viewsdirty = false
end

function getSamples(trs::Trace, idx)
  local samples
  m = meta(trs)

  updateViews(trs)

  v = m.views[1]
  if !isnull(v)
    samples = readSamples(trs, idx, get(v))
  else
    samples = readSamples(trs, idx)
  end

  # run all the passes over the trace
  for i in eachindex(m.passes)
    p = m.passes[i]
    v = m.views[i+1]
    if !isnull(v)
      samples = pass(p, samples, idx, get(v))
    else
      samples = pass(p, samples, idx)
    end
    if length(samples) == 0
      break
    end
  end

  return samples
end

# gets a single trace from a list of traces, runs all the data and sample passes, adds it through the post processor, and returns the result
function getindex(trs::Trace, idx)
  data = getData(trs, idx)
  local samples

  if length(data) > 0
    samples = getSamples(trs, idx)
  end

  if length(data) == 0 || length(samples) == 0
    samples = sampletype(trs)
    data = Vector{eltype(data)}(0)
  end

  return (data, samples)
end

function setindex!(trs::Trace, t::Tuple{Vector,Vector}, idx::Int)
  (data, samples) = t
  writeData(trs, idx, data)
  writeSamples(trs, idx, samples)
end

# add a sample pass (just a Function over a Vector{FLoat64}) to the list of passes for this trace set
addSamplePass(trs::Trace, f::Function, prprnd=false) = addSamplePass(trs, SimpleFunctionPass(f), prprnd)

# add a sample pass (just a Function over a Vector{FLoat64}) to the list of passes for this trace set
function addSamplePass(trs::Trace, p::Pass, prprnd=false)
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
function setColumnRange(trs::Trace, r::Nullable{Range})
  m = meta(trs)
  m.viewsdirty = true
  m.colRange = r
end

export setPreColumnRange

"""
  Column range *before* all the sample passes. For example, if you have a large trace set with traces with many samples, and you only want to run the passes on the first million samples. 
"""
function setPreColumnRange(trs::Trace, r::Nullable{Range})
  m = meta(trs)
  m.viewsdirty = true
  m.preColRange = r
end



# removes a sample pass
function popSamplePass(trs::Trace, fromStart=false)
  m = meta(trs)
  m.viewsdirty = true

  if fromStart
    m.passes = m.passes[2:end]
  else
    m.passes = m.passes[1:end-1]
  end
  return nothing
end

addDataPass(trs::Trace, f::Function, prprnd=false) = addDataPass(trs, SimpleFunctionPass(f), prprnd)

# add a data pass (just a Function over a Vector{x} where x is the type of the trace set)
function addDataPass(trs::Trace, f::Pass, prprnd=false)
  m = meta(trs)
  if prprnd == true
    m.dataPasses = vcat(f, m.dataPasses)
  else
    m.dataPasses = vcat(m.dataPasses, f)
  end
  return nothing
end

# removes a data pass
function popDataPass(trs::Trace, fromStart=false)
  m = meta(trs)
  if fromStart
    m.dataPasses = m.dataPasses[2:end]
  else
    m.dataPasses = m.dataPasses[1:end-1]
  end
  return nothing
end

# removes the data processor and sets the number of traces it fed into the post processor to 0.
function reset(trs::Trace)
  m = meta(trs)
  if !isnull(m.postProcInstance)
    reset(get(m.postProcInstance))
  end
  m.tracesReturned = 0
end

# returns the number of traces it fed into the post processor
function getCounter(trs::Trace)
  return meta(trs).tracesReturned
end

function setPostProcessor(trs::Trace, p::PostProcessor)
  meta(trs).postProcInstance = Nullable(p)
end

# returns true when a post processor is set to this trace set
function hasPostProcessor(trs::Trace)
  return !isnull(meta(trs).postProcInstance)
end

function readTraces(trs::Trace, range::Range)
  if isa(trs, DistributedTrace) || hasPostProcessor(trs)
    return readAndPostProcessTraces(trs, range)
  else
    return readNoPostProcessTraces(trs, range)
  end
end

# read traces without conditional averaging (but with all the data and sample passes), creates huge matrices, use with care
function readNoPostProcessTraces(trs::Trace, range::Range)
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
          allSamples = Vector{eltype(samples)}(sampleLength * traceLength)
        end
        allData = Vector{eltype(data)}(dataLength * traceLength)
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

function readAndPostProcessTraces(trs2::Trace, range::Range)

  traceLength = length(range)

  if isa(trs2, DistributedTrace)
    worksplit = @fetch get(meta(Main.trs).postProcInstance).worksplit
  else
    worksplit = get(meta(trs2).postProcInstance).worksplit
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
            add(get(meta(Main.trs).postProcInstance), Main.trs, range, updateProgress)
          end
        end
      end
    end
  else
    add(get(meta(trs2).postProcInstance), trs2, range, updateProgress)
  end

  if progress != nothing
    finish!(progress)
  end

  if isa(trs2, DistributedTrace)
    worker1copy = @fetchfrom workers()[1] get(meta(Main.trs).postProcInstance)
    ret = get(worker1copy)
  else
    ret = get(get(meta(trs2).postProcInstance))
  end

  return (ret, true)

end

inIJulia() = isdefined(Main, :IJulia) && Main.IJulia.inited
