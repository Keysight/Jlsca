# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export RandomTrace

# simple wrapper around in-memory matrices
type RandomTrace <: Trace
  dataSpace
  sampleType
  nrSamples
  numberOfTraces::Int
  meta::MetaData

  function RandomTrace(nrTraces::Int, dataSpace::Int, sampleType::Type, nrSamples::Int) 
    new(dataSpace, sampleType, nrSamples,nrTraces,MetaData())
  end
end

pipe(trs::RandomTrace) = false

length(trs::RandomTrace) = trs.numberOfTraces
nrsamples(trs::RandomTrace) = trs.nrSamples
sampletype(trs::RandomTrace) = Vector{trs.sampleType}()
meta(trs::RandomTrace) = trs.meta

function readData(trs::RandomTrace, idx)
  return rand(UInt8,trs.dataSpace)
end

function readSamples(trs::RandomTrace, idx)
  return rand(trs.sampleType, trs.nrSamples)
end
