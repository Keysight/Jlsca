# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

using ProgressMeter
using Jlsca.Sca

# normal usage
function test1()
  x = rand(Float64, (100, 20))
  y = rand(Float64, (100, 20))

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovariance(meanVarX, meanVarY)

  for r in 1:size(x)[1]
    add!(covXY, x[r,:], y[r,:])
  end

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY)
  @test cor(x,y) ≈ getCorr(covXY)

end


# combining means
function testmeanadd()
  x = rand(Float64, (100, 20))
  y = rand(Float64, (200, 20))
  z = rand(Float64, (300, 20))

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  meanVarZ = IncrementalMeanVariance(size(y)[2])

  for r in 1:size(x)[1]
    add!(meanVarX, x[r,:])
  end

  for r in 1:size(y)[1]
    add!(meanVarY, y[r,:])
  end

  for r in 1:size(z)[1]
    add!(meanVarZ, z[r,:])
  end

  add!(meanVarX, meanVarY)
  add!(meanVarX, meanVarZ)

  xyz = vcat(x,y,z)

  for c in 1:size(xyz)[2]
    @test mean(xyz[:,c]) ≈ meanVarX.mean[c]
    @test var(xyz[:,c]) ≈ getVariance(meanVarX)[c]
  end
end

# normal usage, tiled
function test1tiled()
  x = rand(Float64, (100, 20))
  y = rand(Float64, (100, 20))

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovarianceTiled(meanVarX, meanVarY, 5, 5, 3)

  for r in 1:size(x)[1]
    add!(covXY, x[r,:], y[r,:])
  end

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY)
  @test cor(x,y) ≈ getCorr(covXY)

end

# normal usage, but mean of X computed outside the add!(covXY,..) function
function test1n()
  x = rand(Float64, (1000, 20))
  y = rand(Float64, (1000, 25))

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovariance(meanVarX, meanVarY)

  for r in 1:size(x)[1]
    xmean = x[r,:] .- meanVarX.mean
    ymean = y[r,:] .- meanVarY.mean
    add!(covXY, x[r,:], y[r,:], false, true)
    add!(meanVarX, x[r,:])
  end

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY)
  @test cor(x,y) ≈ getCorr(covXY)

end

# normal usage, but mean of X computed outside the add!(covXY,..) function
function test1ntiled()
  x = rand(Float64, (1000, 20))
  y = rand(Float64, (1000, 25))

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovarianceTiled(meanVarX, meanVarY,4,4,3)

  for r in 1:size(x)[1]
    xmean = x[r,:] .- meanVarX.mean
    ymean = y[r,:] .- meanVarY.mean
    add!(covXY, x[r,:], y[r,:], false, true)
    add!(meanVarX, x[r,:])
  end

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY)
  @test cor(x,y) ≈ getCorr(covXY)

end

# combining covariances
function test2()
  x = rand(Float64, (500, 200))
  y = rand(Float64, (500, 205))

  meanVarX1 = IncrementalMeanVariance(size(x)[2])
  meanVarY1 = IncrementalMeanVariance(size(y)[2])
  covXY1 = IncrementalCovariance(meanVarX1, meanVarY1)

  meanVarX2 = IncrementalMeanVariance(size(x)[2])
  meanVarY2 = IncrementalMeanVariance(size(y)[2])
  covXY2 = IncrementalCovariance(meanVarX2, meanVarY2)

  meanVarX3 = IncrementalMeanVariance(size(x)[2])
  meanVarY3 = IncrementalMeanVariance(size(y)[2])
  covXY3 = IncrementalCovariance(meanVarX3, meanVarY3)

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovariance(meanVarX, meanVarY)

  range1 = 1:50
  range2 = 51:200
  range3 = 201:500
  @printf("range1 %s, range2 %s, range3 %s\n", range1, range2, range3)

  for r in range1
    add!(covXY1, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  for r in range2
    add!(covXY2, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  for r in range3
    add!(covXY3, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  add!(covXY1, covXY2)
  add!(covXY1, covXY3)

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX1.mean[c] ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY1.mean[c] ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY1)[c]≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX1)[c] ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY1)
  @test cor(x,y) ≈ getCorr(covXY1)

  @test getCov(covXY) ≈ getCov(covXY1)
  @test getCorr(covXY) ≈ getCorr(covXY1)
end

# combining covariances
function test2tiled()
  x = rand(Float64, (500, 200))
  y = rand(Float64, (500, 205))

  meanVarX1 = IncrementalMeanVariance(size(x)[2])
  meanVarY1 = IncrementalMeanVariance(size(y)[2])
  covXY1 = IncrementalCovarianceTiled(meanVarX1, meanVarY1)

  meanVarX2 = IncrementalMeanVariance(size(x)[2])
  meanVarY2 = IncrementalMeanVariance(size(y)[2])
  covXY2 = IncrementalCovarianceTiled(meanVarX2, meanVarY2)

  meanVarX3 = IncrementalMeanVariance(size(x)[2])
  meanVarY3 = IncrementalMeanVariance(size(y)[2])
  covXY3 = IncrementalCovarianceTiled(meanVarX3, meanVarY3)

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovarianceTiled(meanVarX, meanVarY)

  range1 = 1:50
  range2 = 51:200
  range3 = 201:500
  @printf("range1 %s, range2 %s, range3 %s\n", range1, range2, range3)

  for r in range1
    add!(covXY1, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  for r in range2
    add!(covXY2, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  for r in range3
    add!(covXY3, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  add!(covXY1, covXY2)
  add!(covXY1, covXY3)

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX1.mean[c] ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY1.mean[c] ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY1)[c]≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX1)[c] ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY1)
  @test cor(x,y) ≈ getCorr(covXY1)

  @test getCov(covXY) ≈ getCov(covXY1)
  @test getCorr(covXY) ≈ getCorr(covXY1)
end


test1tiled()
test1ntiled()
test2tiled()

test1()
testmeanadd()
test1n()
test2()
