# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export InMemory

# simple wrapper around in-memory matrices
type InMemory{TS,TD} <: Trace
  samples::AbstractArray{TS,2}
  sampleType::Type
  data::AbstractArray{TD,2}
  numberOfTraces::Int
  passes
  dataPasses
  postProcInstance
  tracesReturned
  colRange::Nullable{Range}

  function InMemory(data::AbstractArray{TD,2}, samples::AbstractArray{TS,2}) where {TS,TD}
    nrTraces = size(samples)[1]
    @assert size(data)[1] == nrTraces
    new{TS,TD}(samples, TS, data, nrTraces, [], [], Union,0,Nullable{Range}())
  end
end

pipe(trs::InMemory) = false

length(trs::InMemory) = trs.numberOfTraces

function readData(trs::InMemory, idx)
  return vec(trs.data[idx,:])
end

function writeData(trs::InMemory, idx, data::Vector{UInt8})
  trs.data[idx,:] = data
end

function readSamples(trs::InMemory, idx)
  return vec(trs.samples[idx,:])
end

function writeSamples(trs::InMemory, idx::Int, samples::Vector)
  trs.samples[idx,:] = data
end
