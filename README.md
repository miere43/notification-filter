SKSE plugin that allows hiding notifications based on customizable rules.

More information can be found at [Nexus Mods mod page](https://www.nexusmods.com/skyrimspecialedition/mods/67925).

## Requirements
* [CMake](https://cmake.org/)
	* Add this to your `PATH`
* [The Elder Scrolls V: Skyrim Special Edition](https://store.steampowered.com/app/489830)
	* Supports game version 1.6.640 (Anniversary Edition) and 1.5.97 (Special Edition)
* [Vcpkg](https://github.com/microsoft/vcpkg)
	* Add the environment variable `VCPKG_ROOT` with the value as the path to the folder containing vcpkg
* [Visual Studio Community 2022](https://visualstudio.microsoft.com/)
	* Desktop development with C++

## Building
```
git clone https://github.com/miere43/notification-filter
cd notification-filter
vcpkg install --triplet=x64-windows-static-md
```
Open `notification-filter` folder in Visual Studio 2022 and build.

## Tips
* `test` folder contains plugin that can be used to test Papyrus notifications.
* `scripts` folder contains shortcuts to open INI file, log file, copy Release DLL into MO2 folder.

## Credits
- [CharmedBaryon](https://github.com/CharmedBaryon) for [CommonLibSSE NG](https://github.com/CharmedBaryon/CommonLibSSE-NG)
- [powerofthree](https://www.nexusmods.com/skyrimspecialedition/users/2148728) for [CommonLibSSE:dev](https://github.com/powerof3/CommonLibSSE)
- [Ryan](https://github.com/Ryan-rsm-McKenzie) for [CommonLibSSE](https://github.com/Ryan-rsm-McKenzie/CommonLibSSE)
- [meh321](https://www.nexusmods.com/skyrimspecialedition/users/2964753) for [Address Library for SKSE Plugins](https://www.nexusmods.com/skyrimspecialedition/mods/32444) 

## License

[MIT](LICENSE)
