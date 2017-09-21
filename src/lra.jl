# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse, Ilya Kizhvatov

export lra

# LRA for a single data column
function lra(data::AbstractArray{In}, samples::AbstractArray{Float64}, t::Target{In,Out}, basisFunction::Function, keyChunkValues::Vector{UInt8}) where {In,Out}
    (rs, cs) = size(samples)

    SStot = sum((samples .- mean(samples, 1)) .^ 2, 1)'
    SSreg = zeros(Float64, (cs,length(keyChunkValues)))

    for k in keyChunkValues
        M = mapreduce(basisFunction, hcat, target.(t, data, k))'

        E = (M * inv(M' * M) * M' * samples - samples) .^ 2

        SSreg[:,k+1] = mapslices(sum, E, 1)
    end

    R2 = 1 .- SSreg ./ SStot

    return R2
end

