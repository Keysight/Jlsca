# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Ilya Kizhvatov

using Jlsca.Trs

using Base.Test

# test back and forth
# TODO: add test with different data types!
function testTrs2splitbin(cleanup::Bool = true)

    @printf("Running tests...\n")

    ### 1. Without bit compression
    
    # take file storing bits compressed and create uncompressed splitbin
    trs2splitbin("../testtraces/trs2splitbin_bitpacked.trs", 1, 32) 
    
    # re-create the compressed trs
    splitbin2trs("data_UInt8_17t.bin", 32, "samples_UInt8_17t.bin", 1024, UInt8, 17) 
        
    @test readstring(`cmp ../testtraces/trs2splitbin_bitpacked.trs output_UInt8_17t.trs`) == ""

    ### 2. With bit compression
    
    run(`mv samples_UInt8_17t.bin samples_UInt8_17t_original.bin`)
    run(`mv data_UInt8_17t.bin data_UInt8_17t_original.bin`)
    
    # take the uncompressed splitbin and create an uncompressed trs
    splitbin2trs("data_UInt8_17t_original.bin", 32, "samples_UInt8_17t_original.bin", 1024, UInt8, 17, false)
    
    # take the uncompressed trs and create uncompressed splitbin
    trs2splitbin("output_UInt8_17t_bitsasbytes.trs", 1, 32, false)
    
    @test readstring(`cmp samples_UInt8_17t.bin samples_UInt8_17t_original.bin`) == ""

    ### 3. Check versus original Daredevil split binary and trs

    trs2splitbin("../testtraces/trs2splitbin_bitsasbytes.trs", 1, 32, false)
    @test readstring(`cmp samples_UInt8_13t.bin ../testtraces/trs2splitbin_bitsasbytes.trace`) == ""

    if cleanup
        run(`rm data_UInt8_17t.bin data_UInt8_17t_original.bin`)
        run(`rm samples_UInt8_17t.bin samples_UInt8_17t_original.bin`)
        run(`rm output_UInt8_17t.trs output_UInt8_17t_bitsasbytes.trs`)
        run(`rm data_UInt8_13t.bin samples_UInt8_13t.bin`)
    end
end

# run the test if thi sfile is executed
testTrs2splitbin()
