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
  passes
  dataPasses
  postProcInstance
  tracesReturned
  colRange::Nullable{Range}
  preColRange::Nullable{Range}
  viewsdirty::Bool
  views::Vector{Nullable{Range}}


  function RandomTrace(nrTraces::Int, dataSpace::Int, sampleType::Type, nrSamples::Int) 
    new(dataSpace, sampleType, nrSamples,nrTraces, [], [], Union,0,Nullable{Range}(),Nullable{Range}(),true)
  end
end

pipe(trs::RandomTrace) = false

length(trs::RandomTrace) = trs.numberOfTraces

function readData(trs::RandomTrace, idx)
  return rand(UInt8,trs.dataSpace)
end

function readSamples(trs::RandomTrace, idx)
  return rand(trs.sampleType, trs.nrSamples)
end
