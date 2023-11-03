# wtfis

Untethered iOS 8.0-8.4.1 64-bit Jailbreak.

For support join LegacyJailbreak's [Discord Server](http://discord.legacyjailbreak.com/).

## Using

Just sideload the IPA from the [releases](https://github.com/TheRealClarity/wtfis/releases/) page.

Migration from older alpha releases isn't supported. Please use Cydia Eraser.

wtfis has been thoroughly tested, but as all jailbreaks, there's a risk of a bootloop. I assume no responsibility for any damage caused to your device.
Check the [disclaimer](https://github.com/TheRealClarity/codename_wtfis/blob/main/lol.txt) for more info.

## Building

After cloning, be sure to run `git submodule update --init --recursive` in order to initialize all submodules.

Requires Procursus ldid, dpkg, tar and fakeroot (sudo instead of fakeroot at least on Sonoma since it doesn't work there).  
This will build fine on recent XCode versions, but in that case you'll need to copy libarclite.a from XCode 11 to your XCode install.

After that, just type `make`.

## Exploits/Techniques

- Kernel Exploit: [sock_port_2_legacy](https://github.com/kok3shidoll/sock_port_2_legacy) - [Dora](https://github.com/kok3shidoll)
- Untether: [daibutsu](https://github.com/kok3shidoll/daibutsu) - [Dora](https://github.com/kok3shidoll)
- KASLR Leak: [Trident Info Leak](https://github.com/Siguza/PhoenixNonce/blob/65bb98fd6e23d08fa73aabcf675c76108858a1a1/PhoenixNonce/exploit64.m#L447) - [Siguza](https://github.com/Siguza) and [Tihmstar](https://github.com/tihmstar)
- kcall: [Siguza](https://github.com/Siguza) and [CoolStar](https://github.com/coolstar)
- kppless techniques: [Dora](https://github.com/kok3shidoll/) and [Xerub](https://github.com/xerub/)
- Post Exploitation: [qwertyoruiop](https://github.com/kpwn), FriedAppleTeam and Pangu

## Credits

- [Dora](https://github.com/kok3shidoll/) for the invaluable support, several contributions
- [Cryptiiiic](https://github.com/Cryptiiiic), [Captinc](https://github.com/captinc), [amarioguy](https://github.com/amarioguy) for invaluable support and contributions
- [jakeajames](https://github.com/jakeajames) and Ned Williamson for [sock_port](https://github.com/jakeajames/sock_port)  
- [Siguza](https://github.com/Siguza) and [Tihmstar](https://github.com/tihmstar) for [PhoenixNonce](https://github.com/Siguza/PhoenixNonce)
- [qwertyoruiop](https://github.com/kpwn) for [Yalu841](https://github.com/kpwn/yalu)
- [Xerub](https://github.com/xerub/) for [extra_recipe](https://github.com/xerub/extra_recipe/tree/kppless)
- [WhitetailAni](https://github.com/whitetailani), dotnick and Frog for testing
- _Et al._
