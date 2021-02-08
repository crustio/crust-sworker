function generateNK()
{
    true > $filepath
    local cap=$((val*1024))
    head -c $cap /dev/urandom > $filepath
}

function generateNM()
{
    true > $filepath
    local unit=$((1024*1024))
    for k in $(seq 1 $val); do
        head -c $unit /dev/urandom >> $filepath
    done
}

function generateNG()
{
    true > $filepath
    for k in $(seq 1 $val); do
        for i in {1..1024} ; do
            for j in {1..8}; do
                head -c 131072 /dev/urandom >> $filepath
            done
        done
    done
}

############### main body ###############
basedir=$(cd `dirname $0`;pwd)
volunm=$1
tag=${volunm##*[0-9]}
val=${volunm%[a-zA-Z]*}
filepath=$2
if [ ! -d "$(dirname $filepath)" ]; then
    echo "File path($filepath) directory not exist!"
    exit 1
fi
str=""

[[ ! "$val" =~ [0-9]+ ]] && { echo "[ERROR] wrong param"; exit 1; }

if [ $tag = "k" ] || [ $tag = "K" ]; then
    generateNK
elif [ $tag = "m" ] || [ $tag = "M" ]; then
    generateNM
elif [ $tag = "g" ] || [ $tag = "G" ]; then
    generateNG
fi
