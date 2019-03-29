# findLoop


`findLoop` uses [DynamoRIO](https://dynamorio.org/) to find code blocks executed more than `ITER_LIMIT` times (`ITER_LIMIT` is defined inside the project)

Based on produced data the project generates [`IDA Python`](https://github.com/idapython/src) script, which sets breakpoints at addresses executed more than `ITER_LIMIT` times.

The project can be used to find possible encryption/decryption and compression/decompression code snippets.

#### Possible Targets: 
Crackmes, malware samples, etc.

### BUILD:
The project assumes that `C:\\dynamorio` points to the [DynamoRIO folder](https://github.com/DynamoRIO/dynamorio/releases).


### [DEMO](https://www.youtube.com/watch?v=01gqgAaL7Eo):
[![maxresdefault](https://user-images.githubusercontent.com/16405698/55261416-cfe9f600-5262-11e9-99a5-014473bfdbcd.jpg)](https://www.youtube.com/watch?v=01gqgAaL7Eo)
