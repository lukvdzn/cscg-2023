### ID: torukmagto

# Faulty Parser

## Approach
A simple python flask website is deployed, where one can upload a zip 
containing a folder hierarchy which is parsed and transpiled to python code by the 
_esoteric programming language_ [Folders](https://github.com/SinaKhalili/Folders.py).
If the folder structure is valid, the website appends the output of the 
code execution to the web document.
The aim is to generate a set of instructions which appends the `flag.txt` content
to the website. 

Luckily for us, _Folders_ does not properly verify and escape the contents
of a string when using the `print` command, as seen in the source code
([transpile_print](https://github.com/SinaKhalili/Folders.py/blob/0bec545685da48f832d10a931291b92683fa3846/folders/folders.py#L412)).
The payload can therefore be
easily encoded into a `print` parameter:
```python
PAYLOAD = "\"); f=open('/flag.txt','r'); print(f.readline()); f.close()#"
```

The script [generate_folders_commands.py](./generate_folders_commands.py)
generates `print(PAYLOAD)` as a folder structure. The zip 
[exploit.zip](./exploit.zip) comprises an upload-ready file.

## Flag
``CSCG{f0ld3r_5tructur3s_unl34sh3d_0n_th3_CTF_w0rld}``