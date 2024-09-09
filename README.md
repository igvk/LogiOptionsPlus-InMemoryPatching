**Solution for Logi Options+ for those who would like smooth mouse wheel scrolling to work not only in browsers but also in other programs (the list can be customized).**

Logitech mice have special mode of operation that allows high resolution mouse wheel events,
meaning that the scrolling wheel step is not limited to values +/-120, but it can be any arbitrary integer number, allowing for pixel-perfect scrolling.
Unfortunately, they hardcoded this feature to be enabled only in 4 browser applications.

This small software in-memory patch enables high-resolution scrolling for arbitrary applications.
Works with Logi Options+ on Windows.

StackOverflow discussion: https://stackoverflow.com/questions/65161652/receiving-high-precision-wm-mousewheel-events-with-logitech-mouse-on-windows-10/

To enable high-resolution scrolling mode for the mouse wheel, follow these steps:

1. Place the `version.dll` file from the archive into the program's directory (`C:\Program Files\LogiOptionsPlus`).
2. Create a text file called `wheel_apps_list.txt` in `%AppData%\logioptionsplus` (for example, `C:\Users\User\AppData\Roaming\logioptionsplus\wheel_apps_list.txt`).
In this file, list the program file names (without paths) where you want the smooth scrolling feature enabled, one per line.
You can use the `*` and `?` symbols as wildcards. To exclude a program from the list, prefix its name with a minus sign (`-`).
3. Restart the Logi Options+ Agent background program (for example, you can do this via Task Manager by closing all `logioptionsplus_*` processes, and they will restart automatically).
4. When Logi Options+ is updated, the file `version.dll` is deleted by the installer, so you will need to re-add this file into the program's directory.

Example of ``wheel_apps_list.txt``:
``` 
notepad*
winword.exe
excel.exe
-iexplore.exe
``` 

[Sample list of apps in source tree](logiopt-version/wheel_apps_list.txt)
