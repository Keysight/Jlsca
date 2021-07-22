# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse
#
# Implements algorithms from this fine Sandia paper:
# http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.214.8508&rep=rep1&type=pdf
# 
# Threaded, cached & tiled in IncrementalCovarianceTiled.

export IncrementalMeanVariance,IncrementalCovariance,IncrementalCovarianceTiled,add!,getVariance,getStdDev,getCov,getCorr

mutable struct IncrementalMeanVariance
  mean::Vector{Float64}
  var::Vector{Float64}
  n::Int

  function IncrementalMeanVariance(x::Int)
    new(zeros(Float64, x), zeros(Float64, x), 0)
  end

  function IncrementalMeanVariance(mean::Vector{Float64}, var::Vector{Float64})
    new(mean, var, 0)
  end
end

function add!(state::IncrementalMeanVariance, data::AbstractVector)
  state.n += 1
  @inbounds for x in eachindex(state.mean)
    y1 = data[x] - state.mean[x]
    state.mean[x] = state.mean[x] + y1 / state.n
    y2 = data[x] - state.mean[x]
    state.var[x] = state.var[x] + y1 * y2
  end
end

function add!(this::IncrementalMeanVariance, other::IncrementalMeanVariance)
  n = this.n + other.n
  delta = other.mean .- this.mean
  this.mean = this.mean .+ other.n * delta ./n
  this.var = this.var .+ other.var + this.n*other.n*delta.^2/n
  this.n = n
end

function getVariance(state::IncrementalMeanVariance)
  return 1/(state.n - 1) .* state.var
end

function getStdDev(state::IncrementalMeanVariance)
  return sqrt.(getVariance(state))
end

mutable struct IncrementalCovariance
  meanVarX::IncrementalMeanVariance
  meanVarY::IncrementalMeanVariance
  cov::Matrix{Float64}
  n::Int
  locked::Bool

  function IncrementalCovariance(numberOfX::Int, numberOfY::Int)
    IncrementalCovariance(IncrementalMeanVariance(numberOfX), IncrementalMeanVariance(numberOfY))
  end

  function IncrementalCovariance(meanVarX::IncrementalMeanVariance, meanVarY::IncrementalMeanVariance)
    IncrementalCovariance(meanVarX, meanVarY, zeros(Float64, (length(meanVarX.mean), length(meanVarY.mean))))
  end

  function IncrementalCovariance(meanVarX::IncrementalMeanVariance, meanVarY::IncrementalMeanVariance, cov::AbstractArray{Float64,2})
    new(meanVarX, meanVarY, cov, 0, false)
  end
end

# This a separate function and not inlined in add! so that it shall be optimized for 
# the specific type of argument cov.
@inline function updateCov!(cov::Matrix{Float64}, dataXn::Vector{Float64}, minX::Int, maxX::Int, dataYn::Vector{Float64}, minY::Int, maxY::Int, ndiv::Float64)
  for y in minY:maxY
    @inbounds dataYny = dataYn[y] * ndiv
    ypos = y-minY+1
    for x in minX:maxX
      @inbounds cov[x-minX+1,ypos] += dataXn[x]*dataYny
    end
  end  
end

@inline function add!(state::IncrementalCovariance, dataXn::AbstractVector, minX::Int, maxX::Int, dataYn::AbstractVector, minY::Int, maxY::Int)
 
  state.n += 1
  if state.locked
    ndiv = 1.0
  else
    n = state.n
    ndiv = (n-1)/n
  end

  updateCov!(state.cov, dataXn, minX, maxX, dataYn, minY, maxY, ndiv)
end

function add!(state::IncrementalCovariance, dataX::AbstractVector, dataY::AbstractVector, updateMeanX::Bool=true, updateMeanY::Bool=true)
  dataXn = dataX .- state.meanVarX.mean
  dataYn = dataY .- state.meanVarY.mean
  add!(state, dataXn, 1, length(dataX), dataYn, 1, length(dataY))

  if updateMeanX
    !state.locked || throw(ErrorException("mean and variance are locked so you can't update the mean!"))
    add!(state.meanVarX, dataX)
  end

  if updateMeanY
    !state.locked || throw(ErrorException("mean and variance are locked so you can't update the mean!"))
    add!(state.meanVarY, dataY)
  end
end

function add!(this::IncrementalCovariance, other::IncrementalCovariance, updateMeanX::Bool=true, updateMeanY::Bool=true)
  (covX,covY) = size(this.cov)

  add!(this, other, 1, 1, updateMeanX, updateMeanY)
end

function add!(this::IncrementalCovariance, other::IncrementalCovariance, minX::Int, minY::Int, updateMeanX::Bool=true, updateMeanY::Bool=true)
  !this.locked || throw(ErrorException("not supported in this state: mean and variance are locked"))
  deltaX = this.meanVarX.mean .- other.meanVarX.mean
  deltaY = this.meanVarY.mean .- other.meanVarY.mean
  n = this.n + other.n

  (covX,covY) = size(this.cov)

  @inbounds for y in 1:covY
    for x in 1:covX
      this.cov[x,y] = this.cov[x,y] .+ other.cov[x,y] + (this.n*other.n^2 + other.n*this.n^2) / n^2 .* deltaX[minX+x-1] .* deltaY[minY+y-1]
    end
  end

  this.n = this.n + other.n

  if updateMeanX
    add!(this.meanVarX, other.meanVarX)
  end

  if updateMeanY
    add!(this.meanVarY, other.meanVarY)
  end
end


function getCov(state::IncrementalCovariance)
  return 1/(state.n-1) .* state.cov
end

function getCorr(state::IncrementalCovariance)
  corr = similar(state.cov)

  xstddev = getStdDev(state.meanVarX)
  ystddev = getStdDev(state.meanVarY)

  for y in 1:size(corr)[2]
    for x in 1:size(corr)[1]
      corr[x,y] = 1/(state.n-1) * state.cov[x,y] / (xstddev[x] * ystddev[y])
    end
  end

  return corr
end

export lockandreset!

"""
Resets the co-variance matrix and counter to 0, but locks the mean and variance.
This means you can re-use this instance *if you are sure that the mean
variance will be the same for the subsequent run*! After you called this function *the 
mean and variance will not be updated* on subsequent add! operations. If you have no idea
what any of this means, create a new instance instead. Useful for when you want to compute 
different correlations by re-ordering rows of the same data, like in collision attacks. 
Call this function each time you want to compute correlation for a collision.
"""
function lockandreset!(this::IncrementalCovariance)
  fill!(this.cov,0.0)
  this.n = 0
  this.locked = true
end

const cachechunkmagic = 2^14

function mystrategy(nrX,nrY)
  tilesY = max(1,min(128,div(nrY,Threads.nthreads())))
  tilesX = max(1,div(cachechunkmagic,tilesY))
  cache = 32+16+16
  # @show (tilesX,tilesY,cache)
  return (tilesX,tilesY,cache)
end

mutable struct IncrementalCovarianceTiled
  numberOfX::Int
  numberOfY::Int
  tilesizeX::Int
  tilesizeY::Int
  nrTilesX::Int
  nrTilesY::Int
  meanVarX::IncrementalMeanVariance
  meanVarY::IncrementalMeanVariance
  covXY::Matrix{IncrementalCovariance}
  cacheXn::Vector{Vector{Float64}}
  cacheYn::Vector{Vector{Float64}}
  cacheCount::Int
  cacheMax::Int
  locked::Bool
  accesslock::ReentrantLock

  function IncrementalCovarianceTiled(numberOfX::Int, numberOfY::Int)
    meanVarX = IncrementalMeanVariance(numberOfX)
    meanVarY = IncrementalMeanVariance(numberOfY)

    tilesizeX, tilesizeY, caches = mystrategy(numberOfX,numberOfY)

    IncrementalCovarianceTiled(meanVarX, meanVarY, tilesizeX, tilesizeY, caches)
  end

  function IncrementalCovarianceTiled(numberOfX::Int, numberOfY::Int, tilesizeX::Int, tilesizeY::Int, caches::Int)
    meanVarX = IncrementalMeanVariance(numberOfX)
    meanVarY = IncrementalMeanVariance(numberOfY)

    IncrementalCovarianceTiled(meanVarX, meanVarY, tilesizeX, tilesizeY, caches)
  end

  function IncrementalCovarianceTiled(meanVarX::IncrementalMeanVariance, meanVarY::IncrementalMeanVariance, tilesizeX::Int=128, tilesizeY::Int=128, caches::Int=32*Threads.nthreads())
    numberOfX = length(meanVarX.mean)
    numberOfY = length(meanVarY.mean)
    nrTilesX = div(numberOfX+tilesizeX-1, tilesizeX)
    nrTilesY = div(numberOfY+tilesizeY-1, tilesizeY)
    covXY = Matrix{IncrementalCovariance}(undef,nrTilesX, nrTilesY)

    for y in 1:nrTilesY
      minY = (y-1)*tilesizeY+1
      maxY = min(tilesizeY, numberOfY-(y-1)*tilesizeY)

      for x in 1:nrTilesX
        minX = (x-1)*tilesizeX+1
        maxX = min(tilesizeX, numberOfX-(x-1)*tilesizeX)

        covXY[x,y] = IncrementalCovariance(meanVarX, meanVarY, zeros(Float64, maxX, maxY))
      end
    end

    cachesXn = Vector{Vector{Float64}}(undef,caches)
    cachesYn = Vector{Vector{Float64}}(undef,caches)
    for i in 1:caches
      cachesXn[i] = Vector{Float64}(undef,numberOfX)
      cachesYn[i] = Vector{Float64}(undef,numberOfY)
    end

    new(numberOfX, numberOfY, tilesizeX, tilesizeY, nrTilesX, nrTilesY, meanVarX, meanVarY, covXY, cachesXn, cachesYn, 0, caches, false, ReentrantLock())
  end
end

function dothreadwork(stateref::Ref{IncrementalCovarianceTiled}, x::Int, y::Int)
  state = stateref[]
  nrTilesX = state.nrTilesX
  tilesizeX = state.tilesizeX
  tilesizeY = state.tilesizeY
  numberOfX = state.numberOfX
  numberOfY = state.numberOfY

  minY = (y-1)*tilesizeY+1
  maxY = min(minY+tilesizeY-1, numberOfY)
  # for x in 1:nrTilesX
    minX = (x-1)*tilesizeX+1
    maxX = min(minX+tilesizeX-1, numberOfX)

    for t in 1:state.cacheCount
      dataXn = state.cacheXn[t]
      dataYn = state.cacheYn[t]

      add!(state.covXY[x,y], dataXn, minX, maxX, dataYn, minY, maxY)
    end
  # end
  return
end

function flushcache!(state::IncrementalCovarianceTiled)
  if state.cacheCount == 0
    return
  end

  stateref::Ref{IncrementalCovarianceTiled} = Ref{IncrementalCovarianceTiled}(state)

  n = state.nrTilesX * state.nrTilesY
  Threads.@threads for i in 0:n-1
      x = i % state.nrTilesX
      y = div(i,state.nrTilesX)
      dothreadwork(stateref,x+1,y+1)
  end
  # Threads.@threads for y in 1:state.nrTilesY
  #   dothreadwork(stateref,y)
  # end

  state.cacheCount = 0
  return
end

function storecache(cache::Vector{Float64}, data, datamean)
  @inbounds for i in eachindex(data)
    cache[i] = data[i] - datamean[i]
  end
end

function add!(state::IncrementalCovarianceTiled, dataX::AbstractVector, dataY::AbstractVector, updateMeanX::Bool=true, updateMeanY::Bool=true)
  lock(state.accesslock)
  try
    length(dataX) == state.numberOfX || throw(DomainError("dataX has wrong length"))
    length(dataY) == state.numberOfY || throw(DomainError("dataY has wrong length"))

    state.cacheCount += 1
    cacheCount = state.cacheCount
    storecache(state.cacheXn[cacheCount], dataX, state.meanVarX.mean)
    storecache(state.cacheYn[cacheCount], dataY, state.meanVarY.mean)

    if updateMeanX
      !state.locked || throw(ErrorException("mean and variance are locked so you can't update the mean!"))
      add!(state.meanVarX, dataX)
    end

    if updateMeanY
      !state.locked || throw(ErrorException("mean and variance are locked so you can't update the mean!"))
      add!(state.meanVarY, dataY)
    end

    if cacheCount < state.cacheMax
      return
    end

    flushcache!(state)
  finally
    unlock(state.accesslock)
  end
end

function add!(this::IncrementalCovarianceTiled, other::IncrementalCovarianceTiled, updateMeanX::Bool=true, updateMeanY::Bool=true)
  size(this.covXY) == size(other.covXY) || throw(DomainError("sizes of this and other should be equal")) 

  flushcache!(this)
  flushcache!(other)

  (nrTilesX,nrTilesY) = size(this.covXY)
  tilesizeX = this.tilesizeX
  tilesizeY = this.tilesizeY
  numberOfX = this.numberOfX
  numberOfY = this.numberOfY

  for y in 1:nrTilesY
    minY = (y-1)*tilesizeY+1
    for x in 1:nrTilesX
      minX = (x-1)*tilesizeX+1

      add!(this.covXY[x,y], other.covXY[x,y], minX, minY, false, false)
    end
  end

  if updateMeanX
    add!(this.meanVarX, other.meanVarX)
  end

  if updateMeanY
    add!(this.meanVarY, other.meanVarY)
  end

end

function getCov(state::IncrementalCovarianceTiled)
  flushcache!(state)
  cov = zeros(Float64, state.numberOfX, state.numberOfY)

  numberOfY = state.numberOfY
  numberOfX = state.numberOfX
  nrTilesX = size(state.covXY)[1]
  nrTilesY = size(state.covXY)[2]
  tilesizeY = state.tilesizeY
  tilesizeX = state.tilesizeX
  
  for y in 1:nrTilesY
    minY = (y-1)*tilesizeY+1
    maxY = minY + min(tilesizeY, numberOfY-(y-1)*tilesizeY) - 1

    for x in 1:nrTilesX
      minX = (x-1)*tilesizeX+1
      maxX = minX + min(tilesizeX, numberOfX-(x-1)*tilesizeX) - 1

      cov[minX:maxX,minY:maxY] = state.covXY[x,y].cov
    end
  end

  n = state.covXY[1,1].n
  cov .*= 1/(n-1)

  return cov
end

function getCorr(state::IncrementalCovarianceTiled)
  flushcache!(state)

  corr = Matrix{Float64}(undef,state.numberOfX, state.numberOfY)

  xstddev = getStdDev(state.meanVarX)
  ystddev = getStdDev(state.meanVarY)

  numberOfY = state.numberOfY
  numberOfX = state.numberOfX
  nrTilesX = size(state.covXY)[1]
  nrTilesY = size(state.covXY)[2]
  tilesizeY = state.tilesizeY
  tilesizeX = state.tilesizeX
  
  for y in 1:nrTilesY
    minY = (y-1)*tilesizeY+1
    maxY = minY + min(tilesizeY, numberOfY-(y-1)*tilesizeY) - 1

    for x in 1:nrTilesX
      minX = (x-1)*tilesizeX+1
      maxX = minX + min(tilesizeX, numberOfX-(x-1)*tilesizeX) - 1

      corr[minX:maxX,minY:maxY] = state.covXY[x,y].cov
    end
  end

  n = state.covXY[1,1].n

  for y in 1:size(corr)[2]
    for x in 1:size(corr)[1]
      corr[x,y] = 1/(n-1) * corr[x,y] / (xstddev[x] * ystddev[y])
    end
  end

  return corr
end

function lockandreset!(this::IncrementalCovarianceTiled)
  this.cacheCount == 0 || throw(ErrorException("wrong state: call getCorr first"))
  for i in this.covXY
    lockandreset!(i)
  end
end