# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export VirtuaTrace

mutable struct VirtuaTrace{TD,TS} <: Traces
    samples::Vector{AbstractVector{TS}}
    data::Vector{AbstractVector{TD}}
    nsamples::Int
    ndata::Int
    sampleswidth::Int
    datawidth::Int
    meta::MetaData

    function VirtuaTrace{TD,TS}(datawidth::Int,sampleswidth::Int) where {TD,TS}
        n = 100
        new{TD,TS}(Vector{AbstractVector{TS}}(undef,n),Vector{AbstractVector{TD}}(undef,n),0,0,sampleswidth,datawidth,MetaData())
    end

    # traces are in the columns
    function VirtuaTrace(data::AbstractArray{TD,2}, samples::AbstractArray{TS,2}) where {TD,TS}
        (datawidth,nydata) = size(data)
        (sampleswidth,nysamples) = size(samples)
        @assert nydata == nysamples
        a = VirtuaTrace{TD,TS}(datawidth,sampleswidth)
        for t in 1:nydata
            writeData(a,t,@view(data[:,t]))
            writeSamples(a,t,@view(samples[:,t]))
        end
        return a
    end    
end

import Base.show
show(io::IO, trs::VirtuaTrace) = print(io, "VirtuaTrace")
pipe(trs::VirtuaTrace) = false
length(trs::VirtuaTrace) = trs.ndata == trs.nsamples ? trs.nsamples : error("wrong state")
nrsamples(trs::VirtuaTrace) = trs.sampleswidth
sampletype(trs::VirtuaTrace{TD,TS}) where {TD,TS} = Vector{TS}()
meta(trs::VirtuaTrace) = trs.meta

# import Base.show
# import Base.length
# import Jlsca.Trs.nrsamples
# import Jlsca.Trs.sampletype
# import Jlsca.Trs.meta


function grow(trs::VirtuaTrace{TD,TS}, n=100) where {TD,TS}
    nsamples = length(trs.samples)
    ndata = length(trs.data)
    @assert ndata == nsamples
    samples = Vector{AbstractVector{TS}}(undef,nsamples + n)
    samples[1:nsamples] = trs.samples
    data = Vector{AbstractVector{TD}}(undef,ndata + n)
    data[1:ndata] = trs.data
    trs.samples = samples
    trs.data = data
end

# import Jlsca.Trs.readData
# import Jlsca.Trs.writeData
# import Jlsca.Trs.readSamples
# import Jlsca.Trs.writeSamples

readData(trs::VirtuaTrace, idx) = trs.data[idx]

function writeData(trs::VirtuaTrace{TD,TS}, idx, data::AbstractVector{TD}) where {TD,TS}
    if length(data) != trs.datawidth
        error("wrong length")
    end
    if !(1 < idx < length(trs.data))
        grow(trs)
    end
    trs.data[idx] = data
    trs.ndata = max(trs.ndata, idx) 
end

readSamples(trs::VirtuaTrace, idx) = trs.samples[idx]
readSamples(trs::VirtuaTrace, idx, cols::UnitRange) = @view(trs.samples[idx][cols])

function writeSamples(trs::VirtuaTrace{TD,TS}, idx::Int, samples::AbstractVector{TS}) where {TD,TS}
    if length(samples) != trs.sampleswidth
        error("wrong length")
    end

    if !(1 < idx < length(trs.samples))
        grow(trs)
    end
    trs.samples[idx] = samples
    trs.nsamples = max(trs.nsamples, idx) 
end
