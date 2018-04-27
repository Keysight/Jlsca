# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse
#
# Implements algorithms from this fine Sandia paper:
# http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.214.8508&rep=rep1&type=pdf
# 
# Threaded, cached & tiled in IncrementalCovarianceTiled.

export IncrementalMeanVariance,IncrementalCovariance,IncrementalCovarianceTiled,add!,getVariance,getStdDev,getCov,getCorr

type IncrementalMeanVariance
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

type IncrementalCovariance
  meanVarX::IncrementalMeanVariance
  meanVarY::IncrementalMeanVariance
  cov::Matrix{Float64}
  n::Int

  function IncrementalCovariance(numberOfX::Int, numberOfY::Int)
    IncrementalCovariance(IncrementalMeanVariance(numberOfX), IncrementalMeanVariance(numberOfY))
  end

  function IncrementalCovariance(meanVarX::IncrementalMeanVariance, meanVarY::IncrementalMeanVariance)
    IncrementalCovariance(meanVarX, meanVarY, zeros(Float64, (length(meanVarX.mean), length(meanVarY.mean))))
  end

  function IncrementalCovariance(meanVarX::IncrementalMeanVariance, meanVarY::IncrementalMeanVariance, cov::AbstractArray{Float64,2})
    new(meanVarX, meanVarY, cov, 0)
  end
end

function updateCovCacheFuckExample(cov::Matrix{Float64}, dataXn::AbstractVector, dataYn::AbstractVector, ndiv::Float64)
  for x in eachindex(dataXn)
    @inbounds dataXnx = dataXn[x] * ndiv
      for y in eachindex(dataYn)
      @inbounds cov[x,y] += dataYn[y]*dataXnx
    end
  end
end

# function updateCov!(cov::Matrix{Float64}, dataXn::AbstractVector, dataYn::AbstractVector, ndiv::Float64)
#   for y in eachindex(dataYn)
#     @inbounds dataYny = dataYn[y] * ndiv
#     for x in eachindex(dataXn)
#       @inbounds cov[x,y] += dataXn[x]*dataYny
#     end
#   end  
# end


# function add!(state::IncrementalCovariance, dataX::AbstractVector, dataY::AbstractVector, dataXn::AbstractVector=dataX.-state.meanVarX.mean, updateMeanX::Bool=true, dataYn::AbstractVector=dataY.-state.meanVarY.mean, updateMeanY::Bool=true)
#   @assert((length(dataX),length(dataY)) == size(state.cov))

#   state.n += 1
#   const n = state.n
#   const ndiv::Float64 = (n-1)/n

#   updateCov!(state.cov, dataXn, dataYn, ndiv)

#   if updateMeanX
#     add!(state.meanVarX, dataX, dataXn)
#   end

#   if updateMeanY
#     add!(state.meanVarY, dataY, dataYn)
#   end

# end

@inline function updateCov!(cov::Matrix{Float64}, dataXn::Vector{Float64}, dataYn::Vector{Float64}, ndiv::Float64)
  updateCov!(cov, dataXn, 1, length(dataXn), dataYn, 1, length(dataYn), ndiv)
end

function updateCov!(cov::Matrix{Float64}, dataXn::Vector{Float64}, minX::Int, maxX::Int, dataYn::Vector{Float64}, minY::Int, maxY::Int, ndiv::Float64)
  for y in minY:maxY
    @inbounds dataYny = dataYn[y] * ndiv
    ypos = y-minY+1
    for x in minX:maxX
      @inbounds cov[x-minX+1,ypos] += dataXn[x]*dataYny
    end
  end  
end

function add!(state::IncrementalCovariance, dataX::AbstractVector, dataY::AbstractVector, updateMeanX::Bool=true, updateMeanY::Bool=true)
  dataXn = dataX .- state.meanVarX.mean
  dataYn = dataY .- state.meanVarY.mean
  add!(state, dataX, 1, length(dataX), dataY, 1, length(dataY), dataXn, updateMeanX, dataYn, updateMeanY)

end

function add!(state::IncrementalCovariance, dataX::AbstractVector, minX::Int, maxX::Int, dataY::AbstractVector, minY::Int, maxY::Int, dataXn::AbstractVector=dataX.-state.meanVarX.mean, updateMeanX::Bool=true, dataYn::AbstractVector=dataY.-state.meanVarY.mean, updateMeanY::Bool=true)
  # @assert((length(dataX),length(dataY)) == size(state.cov))

  state.n += 1
  const n = state.n
  const ndiv::Float64 = (n-1)/n

  updateCov!(state.cov, dataXn, minX, maxX, dataYn, minY, maxY, ndiv)

  if updateMeanX
    add!(state.meanVarX, dataX)
  end

  if updateMeanY
    add!(state.meanVarY, dataY)
  end

end

function add!(this::IncrementalCovariance, other::IncrementalCovariance, updateMeanX::Bool=true, updateMeanY::Bool=true)
  const (covX,covY) = size(this.cov)

  add!(this, other, 1, 1, updateMeanX, updateMeanY)
end

function add!(this::IncrementalCovariance, other::IncrementalCovariance, minX::Int, minY::Int, updateMeanX::Bool=true, updateMeanY::Bool=true)
  deltaX = this.meanVarX.mean .- other.meanVarX.mean
  deltaY = this.meanVarY.mean .- other.meanVarY.mean
  n = this.n + other.n

  const (covX,covY) = size(this.cov)

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


const cachechunkmagic = 2^14

function mystrategy(nrX,nrY)
  tilesY = min(128,div(nrY,Threads.nthreads()))
  tilesX = div(cachechunkmagic,tilesY)
  cache = 32
  # @show (tilesX,tilesY,cache)
  return (tilesX,tilesY,cache)
end

type IncrementalCovarianceTiled
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
    covXY = Matrix{IncrementalCovariance}(nrTilesX, nrTilesY)

    # @printf("#threads %d, numberOfX %d, numberOfY %d, nrTilesX %d, nrTilesY %d\n", Threads.nthreads(), numberOfX, numberOfY, nrTilesX, nrTilesY)

    for y in 1:nrTilesY
      minY = (y-1)*tilesizeY+1
      maxY = min(tilesizeY, numberOfY-(y-1)*tilesizeY)

      for x in 1:nrTilesX
        minX = (x-1)*tilesizeX+1
        maxX = min(tilesizeX, numberOfX-(x-1)*tilesizeX)

        covXY[x,y] = IncrementalCovariance(meanVarX, meanVarY, zeros(Float64, maxX, maxY))
      end
    end

    cachesXn = Vector{Vector{Float64}}(caches)
    cachesYn = Vector{Vector{Float64}}(caches)
    for i in 1:caches
      cachesXn[i] = Vector{Float64}(numberOfX)
      cachesYn[i] = Vector{Float64}(numberOfY)
    end

    new(numberOfX, numberOfY, tilesizeX, tilesizeY, nrTilesX, nrTilesY, meanVarX, meanVarY, covXY, cachesXn, cachesYn, 0, caches)
  end
end

function dothreadwork(state::IncrementalCovarianceTiled, y::Int)
  const nrTilesX = state.nrTilesX
  const tilesizeX = state.tilesizeX
  const tilesizeY = state.tilesizeY
  const numberOfX = state.numberOfX
  const numberOfY = state.numberOfY

  minY = (y-1)*tilesizeY+1
  maxY = min(minY+tilesizeY-1, numberOfY)
  for x in 1:nrTilesX
    minX = (x-1)*tilesizeX+1
    maxX = min(minX+tilesizeX-1, numberOfX)

    for t in 1:state.cacheCount
      dataXn = state.cacheXn[t]
      dataYn = state.cacheYn[t]

      # add!(state.covXY[x,y], dataXn, minX, maxX, dataYn, minY, maxY, false,)

      state.covXY[x,y].n += 1
      const n = state.covXY[x,y].n
      const ndiv::Float64 = (n-1)/n

      updateCov!(state.covXY[x,y].cov, dataXn, minX, maxX, dataYn, minY, maxY, ndiv)
    end
  end
end

function flushcache!(state::IncrementalCovarianceTiled)
  if state.cacheCount == 0
    return
  end

  Threads.@threads for y in 1:state.nrTilesY
    dothreadwork(state,y)
  end

  state.cacheCount = 0
end

function storecache(cache::Vector{Float64}, data, datamean)
  @inbounds for i in eachindex(data)
    cache[i] = data[i] - datamean[i]
  end
end

function add!(state::IncrementalCovarianceTiled, dataX::AbstractVector, dataY::AbstractVector, updateMeanX::Bool=true, updateMeanY::Bool=true)
  @assert((length(dataX),length(dataY)) == (state.numberOfX,state.numberOfY))

  state.cacheCount += 1
  const cacheCount = state.cacheCount
  storecache(state.cacheXn[cacheCount], dataX, state.meanVarX.mean)
  storecache(state.cacheYn[cacheCount], dataY, state.meanVarY.mean)

  if updateMeanX
    add!(state.meanVarX, dataX)
  end

  if updateMeanY
    add!(state.meanVarY, dataY)
  end

  if cacheCount < state.cacheMax
    return
  end

  flushcache!(state)

end

function add!(this::IncrementalCovarianceTiled, other::IncrementalCovarianceTiled, updateMeanX::Bool=true, updateMeanY::Bool=true)
  @assert(length(this.covXY) == length(other.covXY))

  flushcache!(this)
  flushcache!(other)

  const (nrTilesX,nrTilesY) = size(this.covXY)
  const tilesizeX = this.tilesizeX
  const tilesizeY = this.tilesizeY
  const numberOfX = this.numberOfX
  const numberOfY = this.numberOfY

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


function getCov(state::IncrementalCovariance)
  return 1/(state.n-1) .* state.cov
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

function getCorr(state::IncrementalCovarianceTiled)
  flushcache!(state)

  corr = Matrix{Float64}(state.numberOfX, state.numberOfY)

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
