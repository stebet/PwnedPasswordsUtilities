# Convert the pwned password file to a binary file
Run the program by using for example ```dotnet run "pwned-passwords-ordered-2.0.txt" -optimize "pwned-passwords-ordered-2.0.bin"```.

This will create a file converting each ```hash:count``` entry into a 24 byte entry where the first 20 bytes are the SHA1 hash and the next 4 bytes are the signed integer count of the number of times the hash has appeared.

So every entry is guaranteed to be 24 bytes, and the hashes are all ordered so the file can be binary searched for a specific password.

As a matter of fact, that can be tested by running ```dotnet run "pwned-passwords-ordered-2.0.bin" -check Passw0rd``` against the binary file. Feel free to edit the source code and improve the program.
