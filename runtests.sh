#!/bin/bash

# AES cipher implementation tests
julia aes-tests.jl && \
# DES cipher implementation tests
julia des-tests.jl && \
# incremental statistics tests
julia incremental-statistics-tests.jl && \
# trs testing
julia trs-tests.jl && \
# trs conversion testing
julia trs-convert-tests.jl && \

# AES attack tests, all modes and directions. Can be called with -pX too.
julia -Lsca.jl attackaes-tests.jl && \
# DES attack tests, all modes and directions. Can be called with -pX too.
julia -Lsca.jl attackdes-tests.jl && \


# Parallelization tests for conditional averaging
julia -p3 -Lsca.jl conditional-average-tests.jl && \
# Parallelization tests for condition bitwise sample reduction
julia -p3 -Lsca.jl conditional-bitwisereduction-tests.jl && \
# Parallelization & vanilla correlation equivalence tests for incremental correlation statistics
julia -p3 -Lsca.jl incremental-correlation-tests.jl && \

# Example run of main function that performs vanilla correlation statistics on an input trace set (i.e. having the entire sample and hypothesis matrices present in memory)
julia -Lsca.jl main-noninc.jl destraces/tdes2_enc_9084b0087a1a1270587c146ccc60a252.trs && \
# Example run of main function that performs vanilla correlation statistics on conditionally averaged output
julia -p3 -Lsca.jl main-condavg.jl aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs && \
# Example run of main function that performs vanilla correlation statistics on bitwise sample reduced output
julia -p3 -Lsca.jl main-condred.jl destraces/des_enc_1c764a2af6e0322e.trs && \
# Example run of main function that performs vanilla correlation statistics on bitwise sample reduced output using Klemsa's leakage models for WB AESes, hardcoded for AES128 FORWARD input
julia -p3 -Lsca.jl main-condred-wbaes.jl aestraces/aes128_sb_ciph_0fec9ca47fb2f2fd4df14dcb93aa4967.trs && \
# Example run of main function that performs incremental correlation statistics on an input trace set
julia -p3 -Lsca.jl main-inccpa.jl aestraces/aes128_mc_invciph_da6339e783ee690017b8604aaeed3a6d.trs
