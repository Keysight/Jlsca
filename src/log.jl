module Log

import Base.truncate
import Base.writecsv

export SimpleCSV,writecsv,writecsvheader

# don't use this for much data, it opens and closes a file for each write.
type SimpleCSV
    fname::Nullable{String}
    headerWritten::Bool
    needcomma::Bool

    function SimpleCSV(fname::String)
        SimpleCSV(Nullable(fname))
    end 

    function SimpleCSV(fname::Nullable{String}) 
        if !isnull(fname) 
            f = open(get(fname), "w")
            truncate(f, 0)
            close(f)
        end
        new(fname, false)
    end
end

function writecsvheader(csv::SimpleCSV, a::String...)
    if !csv.headerWritten
        csv.headerWritten = true
        writecsv(csv, a...)
        writecsvnewline(csv)        
    end
end

function writecsv(csv::SimpleCSV, a::Any...)
    if !isnull(csv.fname)
        f = open(get(csv.fname), "a+")
        for (i,v) in enumerate(a)
            if csv.needcomma
                csv.needcomma = false
                write(f, ",")
            end                
            write(f, string(v))
            if (1 <= i < length(a))
                write(f, ",")
            end
        end
        close(f)
        csv.needcomma = true
    end

end

function writecsvnewline(csv::SimpleCSV)
    if !isnull(csv.fname)
        csv.needcomma = false
        f = open(get(csv.fname), "a+")
        write(f, "\n")
        close(f)
    end

end

end