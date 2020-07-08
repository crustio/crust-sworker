#! /usr/bin/env bash

coreNum=$(cat /proc/cpuinfo | grep processor | wc -l)
basedir=/opt/vendor/
crustdir=/opt/crust
crustteedir=$crustdir/crust-tee
crusttooldir=$crustdir/tools
TMPFILE=$basedir/tmp
ERRFILE=$basedir/err.log
boostdir=$crusttooldir/boost
onetbbdir=$crusttooldir/onetbb
boostpkg=$basedir/boost_1_70_0.tar.gz
onetbbpkg=$basedir/onetbb.tar
crustldfile="/etc/ld.so.conf.d/crust.conf"


mkdir -p $crusttooldir
# install boost

echo "installing boost"

tmpboostdir=$basedir/boost
mkdir -p $tmpboostdir
tar -xvf $boostpkg -C $tmpboostdir --strip-components=1 &>$ERRFILE
if [ $? -ne 0 ]; then
  echo "boost install failed"
  exit 1
fi

cd - &>/dev/null
# Build boost
cd $tmpboostdir
./bootstrap.sh &>$ERRFILE
if [ $? -ne 0 ]; then
  echo "boost install failed"
  exit 1
fi
./b2 install --prefix=$boostdir threading=multi -j$((coreNum*2)) &>$ERRFILE
if [ $? -eq  0 ]; then
  echo 'boost install success'
else
  echo "boost install failed!"
  exit 1
fi

rm -rf $tmpboostdir

echo "installing onetbb"
tmponetbbdir=$basedir/onetbb
mkdir -p $tmponetbbdir
cd $basedir
tar -xvf $onetbbpkg -C $tmponetbbdir --strip-components=1 &>$ERRFILE
if [ $? -ne 0 ]; then
  echo "tbb install failed"
  exit 1
fi
cd - &>/dev/null

cd $tmponetbbdir
make &>/dev/null
if [ $? -eq 0 ]; then
  echo "onetbb build success"
else
  echo "onetbb build failed"
  exit 1
fi

mkdir -p $onetbbdir
cp -r include $onetbbdir/include
cp -r `ls -d build/*/ | grep linux` $onetbbdir/lib
ln -s $onetbbdir/include/tbb /usr/local/include/tbb
echo "$onetbbdir/lib" >> $crustldfile
ldconfig
cd - &>/dev/null

if [ x"$tmponetbbdir" != x"/" ]; then
  rm -rf $tmponetbbdir
fi




