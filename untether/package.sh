#!/bin/sh

if [ $(id -u) != "0" ]; then
  echo Please run this with fakeroot or sudo.
  exit 1
fi

# copy files
rm -rf package/
rm -rf wtfis/
rm -rf untether.tar

mkdir -p package/DEBIAN
cp -a package-debian/* package/DEBIAN/

mkdir -p package/wtfis
cp untether package/wtfis/untether
mkdir -p package/usr/libexec
cp loadruncmd package/usr/libexec/loadruncmd
touch package/.installed_wtfis
chown -R 0:0 package

# make deb
PKG=`grep Package: package/DEBIAN/control |cut -d " " -f 2`
VER=`grep Version: package/DEBIAN/control |cut -d " " -f 2`
if [[ $1 == "app" ]]; then
  sudo dpkg-deb -z9 -Zgzip -b package ${PKG}_iphoneos-arm.deb
else
  sudo dpkg-deb -z9 -Zgzip -b package ${PKG}_${VER}_iphoneos-arm.deb
fi

#make tar
mkdir wtfis
cp untether wtfis/
cp loadruncmd wtfis/
chown -R 0:0 wtfis/
tar -cvf untether.tar wtfis/


