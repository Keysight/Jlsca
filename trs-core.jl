# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

abstract Trace

import Base.length, Base.getindex, Base.setindex!
import Base.reset
using ProgressMeter
import Base.start, Base.done, Base.next


export Trace,readAllTraces,addSamplePass,popSamplePass,addDataPass,setPostProcessor,popDataPass,hasPostProcessor,reset,getCounter
export start,done,next,endof,setindex!

# overloading these to implement an iterator
start(trs::Trace) = 1
done(trs::Trace, idx) = pipe(trs) ? false : (idx > length(trs))
next(trs::Trace, idx) = (trs[idx], idx+1)
endof(trs::Trace) = length(trs)

# gets a single trace from a list of traces, runs all the data and sample passes, adds it through the post processor, and returns the result
function getindex(trs::Trace, idx)
  data = readData(trs, idx)
  samples = nothing

  # run all the passes over the data
  for fn in trs.dataPasses
    data = fn(data)
    if data == nothing
      (data, trace) = (nothing,nothing)
      break
    end
  end

  if data != nothing
    samples = readSamples(trs, idx)
    # run all the passes over the trace
    for fn in trs.passes
     samples = fn(samples)
     if samples == nothing
       (data,samples) = (nothing,nothing)
       break
     end
    end
  end

  return (data, samples)
end

function setindex!(trs::Trace, t::Tuple{Vector,Vector}, idx::Int)
  (data, samples) = t
  writeData(trs, idx, data)
  writeSamples(trs, idx, samples)
end


# add a sample pass (just a Function over a Vector{FLoat64}) to the list of passes for this trace set
function addSamplePass(trs::Trace, f::Function, prprnd=false)
  if prprnd == true
    trs.passes = vcat(f, trs.passes)
  else
    trs.passes = vcat(trs.passes, f)
  end
end

# removes a sample pass
function popSamplePass(trs::Trace, fromStart=false)
  if fromStart
    trs.passes = trs.passes[2:end]
  else
    trs.passes = trs.passes[1:end-1]
  end
end

# add a data pass (just a Function over a Vector{x} where x is the type of the trace set)
function addDataPass(trs::Trace, f::Function, prprnd=false)
  if prprnd == true
    trs.dataPasses = vcat(f, trs.dataPasses)
  else
    trs.dataPasses = vcat(trs.dataPasses, f)
  end
end

# removes a data pass
function popDataPass(trs::Trace, fromStart=false)
  if fromStart
    trs.dataPasses = trs.dataPasses[2:end]
  else
    trs.dataPasses = trs.dataPasses[1:end-1]
  end
end

# removes the data processor and sets the number of traces it fed into the post processor to 0.
function reset(trs::Trace)
  trs.postProcInstance = Union
  trs.tracesReturned = 0
end

# returns the number of traces it fed into the post processor
function getCounter(trs::Trace)
  return trs.tracesReturned
end

# set a post processor that aggregates all data and samples: think conditional averaging.
function setPostProcessor(trs::Trace, x, args...)
  trs.postProcType = x
  trs.postProcArguments = args
end

# returns true when a post processor is set to this trace set
function hasPostProcessor(trs::Trace)
  return trs.postProcType != Union
end

# read all the traces and return them or, more likely, the post processed result (i.e the conditionally averaged result)
function readAllTraces(trs::Trace, traceOffset=start(trs), traceLength=length(trs))
  numberOfTraces = length(trs)
  readCount = 0
  allSamples = nothing
  allData = nothing
  once = true
  eof = false
  local data, samples, dataLength, sampleLength

  if !pipe(trs)
    progress = Progress(traceLength-1, 1, "Reading traces.. ")
  end

  for idx in traceOffset:(traceOffset + traceLength - 1)
    try
      (data, samples) = trs[idx]
    catch e
      if isa(e, EOFError)
        @printf("EOF after reading %d traces ..\n", readCount)
        eof = true
        break
      else
        rethrow(e)
      end
    end

    # next trace if a pass ditched this trace
    if data == nothing || samples == nothing
      continue
    end

    # add it to post processing (i.e conditional averaging) if present
    if trs.postProcType != Union
      if trs.postProcInstance == Union
        if trs.postProcArguments != nothing
          trs.postProcInstance = trs.postProcType(length(data), length(samples), trs.postProcArguments...)
        else
          trs.postProcInstance = trs.postProcType(length(data), length(samples))
        end
      end
      add(trs.postProcInstance, data, samples, idx)
    end

    if once && verbose
      once = false
      @printf("Input traces (after %d data and %d sample passes):\n", length(trs.dataPasses), length(trs.passes))
      if !pipe(trs)
        @printf("traces:      %d:%d\n", traceOffset, traceOffset+traceLength-1)
      end
      @printf("#samples:    %d\n", length(samples))
      @printf("sample type: %s\n", eltype(samples))
      @printf("#data bytes: %d\n", length(data))
      @printf("post proc:   %s\n", trs.postProcType == Union ? "no" : string(trs.postProcType))
      @printf("\n")
    end

    if trs.postProcType == Union
      # no post processor

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
    end

    # valid trace, bump read counter
    readCount += 1

    if !pipe(trs)
      update!(progress, idx)
    end
  end

  trs.tracesReturned += readCount

  if trs.postProcType != Union
    # return the post processing result
    (allData, allSamples) = get(trs.postProcInstance)
  else
    # resize & reshape that shit depending on the readCount
    resize!(allData, (dataLength*readCount))
    resize!(allSamples, (sampleLength*readCount))

    allData = reshape(allData, (dataLength, readCount))'
    allSamples = reshape(allSamples, (sampleLength, readCount))'
  end

  return (allData, allSamples, eof)
end
