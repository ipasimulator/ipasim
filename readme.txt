UnicornPort
-----------

### Target platform

Target platform of qemu inside unicorn (target is the emulated platform) is hard coded to be arm right now.
But it shouldn't be hard to change it.
It is hard coded in .vcxproj file - Additional Include Directories contains target-arm directory.
It is also hard coded in config-target.h file.
Also, some other than arm-related files and folders were excluded from the project.
Or for multiple target platforms, there could be separate projects for each platform linked to one main project
- as it is done in unicorn/msvc (in the most recent unicorn's source code).

TODO: temporarily added tcg/i386 to Additional Include Directories, remove it after adding tci!
