from typing import List, Callable, Any
import logging, struct
from numpy import require

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners, intel
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
from volatility3.plugins import yarascan
import re
import yara

from volatility3.framework.symbols.linux.extensions import task_struct



YARA_GO = {
    "opcodes":
       'rule go_bytes { \
        strings:  \
            $magic_bytes_lookup16 = {(FF FF FF FA | FA FF FF FF) 00 00 01 08}  \
            $magic_bytes_12 = {(FF FF FF FB | FB FF FF FF) 00 00 01 08} \
        condition: $magic_bytes_lookup16 or $magic_bytes_12 \
    }'
}

"""
type moduledata struct {
	pcHeader     *pcHeader
	funcnametab  []byte
	cutab        []uint32
	filetab      []byte
	pctab        []byte
	pclntable    []byte
	ftab         []functab
	findfunctab  uintptr
	minpc, maxpc uintptr

	text, etext           uintptr
	noptrdata, enoptrdata uintptr
	data, edata           uintptr
	bss, ebss             uintptr
	noptrbss, enoptrbss   uintptr
	end, gcdata, gcbss    uintptr
	types, etypes         uintptr
	rodata                uintptr
	gofunc                uintptr // go.func.*

	textsectmap []textsect
	typelinks   []int32 // offsets from types
	itablinks   []*itab

	ptab []ptabEntry

	pluginpath string
	pkghashes  []modulehash

	modulename   string
	modulehashes []modulehash

	hasmain uint8 // 1 if module contains the main function, 0 otherwise

	gcdatamask, gcbssmask bitvector

	typemap map[typeOff]*_type // offset to *_rtype in previous module

	bad bool // module failed to load and should be ignored

	next *moduledata
}
"""

# TODO change all infos to the proper name for production to debug =)
# https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/symbols/linux/extensions/__init__.py
golog = logging.getLogger(__name__)

class GoArtifacts(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    _32BIT = False

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name='kernel', 
                description='Linux kernel',
                architectures=['Intel32', "Intel64"]
            ),
            requirements.ListRequirement(
                name = 'pid', 
                element_type=int,
                description="Process PIDS.",
                optional=False
            ),
            requirements.BooleanRequirement(name='static',
                description="Attempts to find static strings",
                default=False,
                optional=True
            ),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0))
        ]

    @classmethod
    def proc_filter_pid(cls, pid_name_list: List[int] = None) -> Callable[[Any], bool]:
        """Constructs a filter function for process Names.
        Args:
            pid_name_list: List of process names that are acceptable (or None if all are acceptable)
        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        
        filter_list = [x for x in pid_name_list if x is not None]

        if filter_list:
            def filter_func(x):
                # get the string from the comm for the process name
                return x.pid not in filter_list

            return filter_func
        else:
            return lambda _: False # this means no filter

    def run(self):
        golog.info("Plugin is now Starting to Run!")

        filter_func = self.proc_filter_pid(self.config.get('pid'))

        list_procs = pslist.PsList.list_tasks(
            self.context,
            self.config['kernel'],
            filter_func=filter_func
        )
        

        static_mode = self.config.get('static')

        if static_mode:
            return renderers.TreeGrid(
                [
                    ("PID", int),
                    ("COMM", str),
                    ("Function", str)

                ],
                generator=self._generator(list_procs)
            )
        
        else:
            return renderers.TreeGrid(
                [
                    ("PID", int),
                    ("COMM", str),
                    ("GoVer PTR", format_hints.Hex),
                    ("MOD_INFO PTR", format_hints.Hex),
                    ("PCHEADER PTR", format_hints.Hex),
                    ("GO_Version", str)

                ],
                generator=self._generator(list_procs)
            )

    def _check_32bit(self, task: task_struct, proc_layer: intel) -> bool:

        for vma in task.mm.get_mmap_iter():

            vma_name = vma.get_name(self.context, task)
            
            # pulled from vols elf plugin determine if 32 or 64bit process
            hdr = proc_layer.read(vma.vm_start, 4, pad=True)

            if hdr[0] == 0x7f:
                if not hdr[1] & 1: # if the first bit is not 1 that means its 32 bit.
                    return True

        return False


    def check_go_version(self, pointer_size, endian, go_build_data: bytes, proc_layer) -> str:
        golog.debug(f"VER: {go_build_data}")
        # get string of go version
        go_ver_ptr = struct.unpack(f"{endian}Q",go_build_data[:pointer_size])[0]
        go_versioninfo_data = proc_layer.read(go_ver_ptr, 0xff)
        data_index = re.search(rb'go[0-9]+\.[0-9]+\.[0-9]+',go_versioninfo_data).end()
        golog.debug(f"Version info: {go_versioninfo_data}")
        
        return go_versioninfo_data[:data_index].decode()


    def last_static_str(self, str_arr):
        """Simple function that finds the last static string."""
        counter = 0
        for s in str_arr:
            for i in range(len(s)):
                if s[i] not in range(32,126):
                    return counter
            counter += 1
        return len(str_arr)

    def enum_task_struct(self, task: task_struct, proc_layer: intel.Intel, static_mode: bool) -> str:

        golog.debug(f"PROC ID: {task.pid}")

        vma_regions = []
        for vma in task.mm.get_mmap_iter():
            vm_start = vma.vm_start
            vm_end   = vma.vm_end

            vma_regions.append((vm_start, vm_end-vm_start))

        runtime_buildver_addr = 0
        runtime_modinfo_addr = 0

        # exit(0)
        # """
        # const (
        #     go12magic  = 0xfffffffb
        #     go116magic = 0xfffffffa
        #     go118magic = 0xfffffff0
        # )
        # """
        
        rules = yara.compile(sources=YARA_GO)
        golog.debug("Scanning yara.")
        for offset, rule_name, name, value in proc_layer.scan(
                self.context,
                scanner=yarascan.YaraScanner(rules=rules),
                sections=vma_regions
        ):
            if name == "$magic_bytes_12":
                break

            golog.debug(f"Offset {offset}")
            data = proc_layer.read(offset, 0xff)

            magic_bytes = data[:4]

            # 5 and 6 are padding
            padding = data[4:6]

            ptr_size = data[7]

            quantum = data[8]

            # size of function symbol table
            nfunctab = struct.unpack("<Q",data[8:16])[0]
            
            func_offset = struct.unpack("<Q", data[16:24])[0]


            # this is where symbols starts
            cu_offset = struct.unpack("<Q", data[24:32])[0]

            filetab_offset = struct.unpack("<Q", data[32:40])[0]
            
            # pc tab offset to filetab variable
            pctab_offset = struct.unpack("<Q", data[40:48])[0]

            pcln_offset = struct.unpack("<Q", data[48:56])[0]

            #// functabFieldSize returns the size in bytes of a single functab field.
            #func (t *LineTable) functabFieldSize() int {
            #    if t.version >= ver118 {
            #        return 4
            #    }
            #    return int(t.ptrsize)
            #}

            # TODO: handle case for go.18>
            functabsize = (nfunctab*2 + 1) * 8

            lower, length = [(lower, upper) for (lower,upper) in vma_regions if lower <= offset <= lower+upper][0]


            cached_names_offset = offset+cu_offset
            golog.debug(f"cached offset {cached_names_offset}")

            read_size = length - (offset - lower) 

            cu_data = proc_layer.read(cached_names_offset, read_size, pad=True)

            cu_data = re.sub(rb"\xc2\xb7", b'.', cu_data)

            cu_data = cu_data.split(b'\x00')
            cu_data = [i for i in cu_data if i]

            idx = self.last_static_str(cu_data)
            golog.debug(f"CU_IDX: {idx}")
            golog.debug(cu_data[:10])


            if static_mode:

                if idx == 0:
                    return 0x0, 0x0, 0x0, "", [x.decode('utf-8') for x in cu_data]
                
                return 0x0, 0x0, 0x0, "", [x.decode('utf-8') for x in cu_data[:idx]]

            


            golog.debug(f"Pointersize: {ptr_size}")
            golog.debug(f"Instruction size: {quantum}")
            golog.debug(f"Padding {padding}")
            golog.debug(f"nfunc: {hex(nfunctab)}")
            golog.debug(f"func_offset: {hex(func_offset)}")
            golog.debug(f"cuoffset {cu_offset}")
            golog.debug(f"filetab_offset {filetab_offset}")
            golog.debug(f"pctab_offset {pctab_offset}")
            golog.debug(f"pcln_offset {pcln_offset}")
            golog.debug(f"Function tab size: {functabsize}")
            golog.debug(f"MAGIC_BYTES: {magic_bytes}")
            

        static_strings = []

        golog.debug("parsing buildinfo now.\n")
        for offset in proc_layer.scan(
            context=self.context,
            scanner=scanners.BytesScanner(b"\xff Go buildinf:"),
            sections=vma_regions
        ):

            golog.debug(f"OFFSET: {hex(offset)}")
            data = proc_layer.read(offset, 0xff)

            pointer_size = struct.unpack("<H", data[14:16])[0]

            endianess = data[15] & 2

            endian = ""
            if endianess == 0:
                golog.info("Little-endian program.")
                endian = "<"
            else:
                endian = ">"

            golog.info(f"offset: {hex(offset)}")
            golog.debug(f"Start_data: {data}")

            runtime_buildver_addr = struct.unpack(f"{endian}Q", data[16:16+pointer_size])[0]
            runtime_modinfo_addr = struct.unpack(f"{endian}Q", data[16+pointer_size:16+(pointer_size*2)])[0]

            golog.debug(f"Pointer size: {pointer_size}")
            golog.debug(f"runtime.buildversion ptr: {hex(runtime_buildver_addr)}")
            golog.debug(f"runtime.modinfo ptr: {hex(runtime_modinfo_addr)}")

            # go buildver
            go_build_data = proc_layer.read(runtime_buildver_addr, 0xff)
            go_version = self.check_go_version(pointer_size, endian, go_build_data, proc_layer)


            
            # get data and attempt to read pcheader
            mod_data = proc_layer.read(runtime_modinfo_addr, 0xff)
            pc_header_addr = struct.unpack(f"{endian}Q", mod_data[:pointer_size])[0]

            pc_header_len = struct.unpack(f"{endian}Q", mod_data[pointer_size:pointer_size*2])[0]
            golog.debug(f"HEADER_LEN: {hex(pc_header_len)}")
            golog.debug(f"MOD_DATA: {mod_data}")
            

            # pcheader table data
            pcheader = proc_layer.read(pc_header_addr, pc_header_len)
            golog.debug(f"PCHEADER: {pcheader}")
            if "go1.13" in go_version:
                sub_data = re.sub(rb"dep\t", b'', pcheader)
                sub_data = re.sub(rb"path\t", b'', sub_data)
                sub_data = re.sub(rb"\t", b' ', sub_data)
                sub_data = re.sub(rb"mod\t", b'', sub_data).split(b'\n')[1:-1]
                
                golog.debug(sub_data)
                static_strings = [x.decode('utf-8').lstrip() for x in sub_data]





        return runtime_buildver_addr, runtime_modinfo_addr, pc_header_addr, go_version, static_strings


    def _generator(self, tasks):
        static_mode = self.config.get('static')
        for task in tasks:
            if not task.mm:
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]
            golog.debug(proc_layer_name)

            is_32bit = self._check_32bit(task, proc_layer)
            golog.debug(f"Process: is 32-bit mode: {is_32bit}")


            pid = task.pid
            comm = utility.array_to_string(task.comm)
            golog.debug(f"PID:{pid} COMM:{comm}")

            vma_regions = []
            for vma in task.mm.get_mmap_iter():
                vm_start = vma.vm_start
                vm_end   = vma.vm_end
                vma_regions.append((vm_start, vm_end))



            buildver, modinfo, pcheader, go_version, static_strings = self.enum_task_struct(task, proc_layer, static_mode)

            if static_mode:
                for string in static_strings:
                    yield (0, (task.pid, comm, string.strip()))
                return

            yield (0, (task.pid, comm, format_hints.Hex(buildver), format_hints.Hex(modinfo), format_hints.Hex(pcheader), go_version))

                