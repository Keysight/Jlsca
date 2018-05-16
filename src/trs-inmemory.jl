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
  meta::MetaData

  function InMemory(data::AbstractArray{TD,2}, samples::AbstractArray{TS,2}) where {TS,TD}
    nrTraces = size(samples)[1]
    @assert size(data)[1] == nrTraces
    new{TS,TD}(samples', TS, data', nrTraces,MetaData())
  end
end

pipe(trs::InMemory) = false

length(trs::InMemory) = trs.numberOfTraces
nrsamples(trs::InMemory) = size(trs.samples)[1]
sampletype(trs::InMemory) = Vector{trs.sampleType}()
meta(trs::InMemory) = trs.meta

function readData(trs::InMemory, idx)
  return vec(trs.data[:,idx])
end

function writeData(trs::InMemory, idx, data::Vector{UInt8})
  trs.data[:,idx] = data
end

function readSamples(trs::InMemory, idx)
  return vec(trs.samples[:,idx])
end

function readSamples(trs::InMemory, idx, cols::Range)
  return vec(trs.samples[cols,idx])
end

function writeSamples(trs::InMemory, idx::Int, samples::Vector)
  trs.samples[:,idx] = data
end
