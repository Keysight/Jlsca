# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export prepSKEA

"""
Takes the rank data from an SCA attack and converts into in a sorted
matrix of integer scores, and the key look up matrix, for a given 
phase. The factor argument is the multiplier for the rank data
scores. 

See ?SKEA on how to use this.
"""
function prepSKEA(results::RankData,factor::Int=100,phase::Int=1)
    factor = 100
    phase = 1
    nY = length(results.combinedScores[phase])
    nX = length(results.combinedScores[phase][1])
    scoresfloat = zeros(Float64, nX,nY)
    if nX <= typemax(UInt8)
        mytype = UInt8
    elseif  maxval <= typemax(UInt16)
        mytype = UInt16
    elseif  maxval <= typemax(UInt32)
        mytype = UInt32
    else
        mytype = UInt
    end
 
    keylookup = zeros(mytype, nX,nY)

    for y in 1:nY
        scores = vec(results.combinedScores[phase][y])
        sorted = sortperm(scores,rev=true)
        keylookup[:,y] = (sorted .- 1)
        scoresfloat[:,y] = scores[sorted]
    end

    scoresfloat .*= factor
    scoresfloat[:] = floor.(scoresfloat)

    scoresint = convert(Array{Int,2},scoresfloat)

    return scoresint,keylookup
end

function scorebounds(S::Array{T,2}) where {T <: Integer}
    nX,nY = size(S)
    cmin = zeros(T,nY+1)
    cmax = zeros(T,nY+1)
    nI = maximum(cmax) - minimum(cmin)
    ranges = zeros(T,nY+1)
    
    for c in 1:nY
        cmin[c] = sum(@view(S[nX,c:end]))
        cmax[c] = sum(@view(S[1,c:end]))
    end
    
    imin = Vector{Vector{Int}}(undef,nY)
    imax = Vector{Vector{Int}}(undef,nY)

    for c in 1:nY
        col = @view(S[:,c])
        imin[c] = zeros(Int,cmax[c])
        imax[c] = zeros(Int,cmax[c])
        for score in cmax[c]:-1:cmin[c]
            mmin = findfirst(x -> x + cmin[c+1] <= score,col)
            mmax = findlast(x -> x + cmax[c+1] >= score,col)
            imin[c][score] = mmin
            imax[c][score] = mmax
        end
    end
        
    return cmin,cmax,imin,imax
end

export SKEA

"""
Implementation of score based key enumeration as defined in https://eprint.iacr.org/2015/795.pdf wrapped into an iterator.

# Example

Example for an AES-128 trace set with input and output in the trace
data.

```
results = sca(trs,params)

somedata = getData(trs,1)
someinput = somedata[1:16]
someoutput = somedata[17:32]

scoresint,keylookup = prepSKEA(results,100)

skea = SKEA(scoresint)

count = 0

for k in skea
    count += 1
    recoveredkey = map(x -> keylookup[k[x],x], eachindex(k))
    if Cipher(someinput,KeyExpansion(recoveredkey,10,4)) == someoutput
        print("found key \$(bytes2hex(recoveredkey)) after \$count tries!\\n")
        break
    end
    if count > 1000
        print("Stopped looking after \$count tries")
        break
    end
end
```
"""
struct SKEA{T}
    S::Array{T,2}
    cmin::Vector{Int}
    cmax::Vector{Int}
    imin::Vector{Vector{Int}}
    imax::Vector{Vector{Int}}
    nX::Int
    m::Int
    
    function SKEA(S::Array{T,2}) where {T <: Integer}
        cmin,cmax,imin,imax = scorebounds(S)
        nX,m = size(S)
        new{T}(S,cmin,cmax,imin,imax,nX,m)
    end
end

export SKEAState

mutable struct SKEAState
    k::Vector{Int}
    s::Int
    cs::Int
    i::Int
    
    function SKEAState(skea::SKEA)
        k = zeros(Int,skea.m)
        s = skea.cmax[1]
        k[1] = skea.imin[1][s]
        cs = s
        i = 0
        new(k,s,cs,i)
    end
end

import Base.length

length(skea::SKEA) = skea.nX^skea.m

import Base.eltype

eltype(skea::SKEA) = Vector{Int}

import Base.iterate

function iterate(skea::SKEA, state=SKEAState(skea))
    k = state.k
    s = state.s
    cs = state.cs
    i = state.i
    
    S = skea.S
    cmin = skea.cmin
    cmax = skea.cmax
    imin = skea.imin
    imax = skea.imax
    nX = skea.nX
    m = skea.m
    
    if i < 0
        s -= 1
        k = zeros(Int,m)
        i = 0
        k[1] = imin[1][s]
        cs = s
    end

    if cmin[1] <= s <= cmax[1]
        while i < m - 1
            cs -= S[k[i+1],i+1]
            i += 1
            k[i+1] = imin[i+1][cs]
        end
        ret = k[:]
        while i >= 0 && k[i+1] >= imax[i+1][cs]
            i -= 1
            if i >= 0
                cs += S[k[i+1],i+1]
            end
        end
        if i >= 0
            k[i+1] += 1
        end
    else
        return nothing
    end
    
    state.k = k
    state.s = s
    state.cs = cs
    state.i = i
    
    return ret,state
end
