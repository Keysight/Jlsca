# Snatched and adapted from https://github.com/JuliaParallel/MPI.jl/blob/master/test/runtests.jl

using Test

function runtests()
    # nprocs = clamp(Sys.CPU_CORES, 2, 4)
    nprocs = 3
    exename = joinpath(Sys.BINDIR, Base.julia_exename())
    testdir = dirname(@__FILE__)
    istest(f) = endswith(f, "-tests.jl") && f != "runtests.jl"
    testfiles = sort(filter(istest, readdir(testdir)))
    # @printf("testfiles: %s\n", testfiles)
    
    for f in testfiles
        if endswith(f, "parallel-tests.jl") 
            run(`$exename -p $nprocs --depwarn=error $(joinpath(testdir, f))`)
        else
            include(f)
        end
        Base.with_output_color(:green,stdout) do io
            println(io,"\tSUCCESS: $f\n")
        end
    end
end

runtests()
