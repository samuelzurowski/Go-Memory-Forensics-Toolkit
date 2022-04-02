# Golang Memory Analysis Repo

## Hunting for a Go Process

To do this the plugin `go.go_hunt` is utilized. There are two ways to run this plugin. The first manner requires no flags and the second way uses the `--regex` flag. The reason their is a flag is sometimes the *buildinfo* information could potentially be obfuscated. However, the regex method has a higher chance of false positives. regex should only be used if structures aren't being parsed properly.

The most basic usage of `go_hunt`:
```bash
vol.py -r pretty -f <memory_image> go.go_hunt 
```

Searching using specific PIDs:
```bash
vol.py -r pretty -f <memory_image> go.go_hunt --pid [PID [PID ...]]
```

Using regex. Can be used in conjunction with --pid:
```bash
vol.py -r pretty -f <memory_image> go.go_hunt --regex 
```

Sample Output:
```bash
vol.py -r pretty  -s ~/Documents/symbols/ -p . -f memory_dumps/leaky.vmem go.go_hunt
Volatility 3 Framework 2.0.2
Formatting...0.00               PDB scanning finished                          
  |    PID |  COMM | GO_VERSION | VIRTUAL OFFSET
* | 225632 | leaky |   go1.17.6 |       0x511000
```