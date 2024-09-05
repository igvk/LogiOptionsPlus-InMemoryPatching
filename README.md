**Solution for Logi Options+ for those who would like smooth mouse wheel scrolling to work not only in browsers but also in other programs (the list can be customized).**

To enable high-resolution mode for the mouse wheel, you need to:

1. Place the file from the archive into the program's directory (`C:\Program Files\LogiOptionsPlus`).
2. Create a text file called `wheel_apps_list.txt` in `%AppData%\logioptionsplus` (for example, `C:\Users\User\AppData\Roaming\logioptionsplus\wheel_apps_list.txt`). In this file, list the programs (without paths) in which to allow the functionality, one per line. You can use the `*` and `?` symbols, and a line starting with a minus sign (`-`) will exclude a program from the list.
3. Restart the Logi Options+ Agent background program (for example, you can do this via Task Manager by closing all `logioptionsplus_*` processes, and they will restart automatically).
4. When Logi Options+ is updated, the file `version.dll` is deleted by the installer, so you will need to place it back into the program folder again.
