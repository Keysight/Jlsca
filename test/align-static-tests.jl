using Jlsca.Align
using Base.Test

function test1()
    cols = 50
    rows = 100
    data = rand(Float64, cols)
    dataM = Array{Float64}(rows,cols)
    window = 10:20
    reference = data[window]
    maxShift = 10
    shifts = Vector{Int}(rows)

    fftwalignstate = CorrelationAlignFFT(reference, window[1], maxShift)
    naivealignstate = CorrelationAlignNaive(reference, window[1], maxShift)

    for i in 1:rows
        shifts[i] = rand(1:maxShift)
        dataM[i,:] = circshift(data, shifts[i])
    end

    for i in 1:rows
        (shift,corval) = correlationAlign(dataM[i,:], fftwalignstate)
        @test shift == -shifts[i]
        @test corval ≈ 1
    end

    for i in 1:rows
        (shift,corval) = correlationAlign(dataM[i,:], naivealignstate)
        @test shift == -shifts[i]
        @test corval ≈ 1
    end

end

function speedtest1()
    cols = 5000
    rows = 20000
    data = rand(Float64, cols)
    window = 10:20
    reference = data[window]
    maxShift = 5000
    shifts = Vector{Int}(rows)

    fftwalignstate = CorrelationAlignFFT(reference, window[1], maxShift)

    for i in 1:rows
        correlationAlign(rand(Float64, cols), fftwalignstate)
    end

    return fftwalignstate
end

test1()
# @time speedtest1()
# @profile speedtest1()
# Profile.print(maxdepth=12,combine=true)
