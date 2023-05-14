# Go Memory Forensics Toolkit

[Go](https://go.dev/) is a popular program language used because of its portability and ease of usage. However, in the recent years there has been a 2000% increase of new malware written in Go \[[1](https://www.zdnet.com/article/go-malware-is-now-common-having-been-adopted-by-both-apts-and-e-crime-groups/)\]. Therefore, this toolkit was written to be able to analyze memory dumps for finding golang processes and information that can be used to determine more information about malware.

# Created by Samuel Zurowski

## Hunting for a Go Process

To do this the plugin `linux.go_hunt` is utilized. There are two ways to run this plugin. The first manner requires no flags and the second way uses the `--regex` flag. The reason for this flag is sometimes the *buildinfo* information could potentially be obfuscated or data may not be loaded by the executable. However, the regex method has a higher chance of false positives. Regex should only be used if structures aren't being parsed properly. So for older versions of golang the structure is slighty different which will enable you to grab that information. Mainly Golang 1.17+ is supported. 


The most basic usage of `go_hunt` for linux:
```bash
vol.py -r pretty -f <memory_image> linux.go_hunt 
```

Searching using specific PIDs:
```bash
vol.py -r pretty -f <memory_image> linux.go_hunt --pid [PID [PID ...]]
```

Using regex. Can be used in conjunction with `--pid`:
```bash
vol.py -r pretty -f <memory_image> linux.go_hunt --regex 
```

Sample Output:
```bash
vol.py -r pretty -f <memory_image> linux.go_hunt
Volatility 3 Framework 2.0.2
Formatting...0.00               PDB scanning finished                          
  |    PID |  COMM | GO_VERSION | VIRTUAL OFFSET
* | 225632 | leaky |   go1.17.6 |       0x511000
```


## Getting the Golang BuildID
The Golang Build ID is stammped into the elf file. Which is a hash of the inputs to the action that produced the packages or the binary. It also cotains the the content ID which is the hash of the action output namely the archive itself. 

The BuildID can also be pulled if you have access the go binary using:
```
go tool buildid [-w] file
```

String format of BuildID: `actionID(binary)/actionID(main.a)/contentID(main.a)/contentID(binary)`

The basic usage of `go_build` linux plugin:

```bash
vol.py -r pretty -f <memory_image> linux.go_build 
Volatility 3 Framework 2.3.0
Formatting...0.00               Stacking attempts finished                 
  |                                                                         Go Build ID | VIRTUAL OFFSET
* | vr1DhtPYsLeabzHtro3k/4XAaSgrEG49cymA9tBh5/K8jR0ruPG13Fz9Sjzw7d/ayqlaSsnLEpjhlQ-itp1 | 0x9379c570d35c
```

### Sources 
> - \[1\] [Go malware is now common, having been adopted by both APTs and e-crime groups ](https://www.zdnet.com/article/go-malware-is-now-common-having-been-adopted-by-both-apts-and-e-crime-groups/)
