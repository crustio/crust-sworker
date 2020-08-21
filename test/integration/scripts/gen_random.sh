function generateNK()
{
    true > $filename
    local cap=$((val*1024))
    head -c $cap /dev/urandom > $filename
}

function generateNM()
{
    true > $filename
    local unit=$((1024*1024))
    for k in $(seq 1 $val); do
        head -c $unit /dev/urandom >> $filename
    done
}

function generateNG()
{
    true > $filename
    for k in $(seq 1 $val); do
        for i in {1..1024} ; do
            for j in {1..8}; do
                head -c 131072 /dev/urandom >> $filename
            done
        done
    done
}

############### main body ###############
basedir=$(cd `dirname $0`;pwd)
gdir=$basedir/big
volunm=$1
tag=${volunm##*[0-9]}
val=${volunm%[a-zA-Z]*}
filename=$2
str=""

[[ ! "$val" =~ [0-9]+ ]] && { echo "[ERROR] wrong param"; exit 1; }

if [ $tag = "k" ] || [ $tag = "K" ]; then
    generateNK
elif [ $tag = "m" ] || [ $tag = "M" ]; then
    generateNM
elif [ $tag = "g" ] || [ $tag = "G" ]; then
    generateNG
fi
