from typing import List, Callable, Any, Tuple
import logging, struct, binascii

from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners, intel
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

from volatility3.framework.symbols.linux.extensions import task_struct


golog = logging.getLogger(__name__)



class GoHunt(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

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
                optional=True
            ),
            requirements.BooleanRequirement(name='regex',
                description="Attempt to find a go version with regex.",
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

        filter_func = self.proc_filter_pid(
            self.config.get('pid')
        )

        list_procs = pslist.PsList.list_tasks(
            self.context,
            self.config['kernel'],
            filter_func=filter_func
        )
        
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("COMM", str),
                ("GO_VERSION", str),
                ("VIRTUAL OFFSET", format_hints.Hex)
            ],
            generator=self._generator(list_procs)
        )

    def check_go_version(self, pointer_size, endian, go_build_data: bytes, proc_layer) -> str:
        golog.debug(f"VER: {go_build_data}")
        # get string of go version
        go_ver_ptr = struct.unpack(f"{endian}Q",go_build_data[:pointer_size])[0]
        go_versioninfo_data = proc_layer.read(go_ver_ptr, 0xff)
        golog.debug(f"Version info: {go_versioninfo_data}")
        
        return go_versioninfo_data.split(b'\x00')[0].decode() # the go version is null terminated so this works.

    def enum_task_struct(self, task: task_struct, proc_layer: intel.Intel, use_regex: bool) -> str:
        
        golog.debug(f"PROC ID: {task.pid}")

        # get all the VMA regions to search through.
        vma_regions = []
        for vma in task.mm.get_mmap_iter():
            vm_start = vma.vm_start
            vm_end   = vma.vm_end

            vma_regions.append((vm_start, vm_end-vm_start))



        golog.debug("parsing buildinfo now.\n")

        if use_regex:
            # this mode just looks for the go build id using regex.
            for offset in proc_layer.scan(
                context=self.context,
                scanner=scanners.RegExScanner(rb"go[0-9]+\.[0-9]+\.[0-9]+[^.\s]+"),
                sections=vma_regions
            ):

                data = proc_layer.read(offset, 0xff, pad=True)

                data_index = data.find(b'\x00')

                golog.debug(data[:data_index].strip())

                metadata = data[:data_index].decode()

                yield metadata, offset

            return

        # this is how the go version can be found.
        for offset in proc_layer.scan(
            context=self.context,
            scanner=scanners.BytesScanner(b"\xff Go buildinf:"),
            sections=vma_regions
        ):

            data = proc_layer.read(offset, 0xff)

            pointer_size = struct.unpack("<H", data[14:16])[0]
            golog.info(f"Pointer size: {pointer_size}")

            if pointer_size != 8 and pointer_size != 4:
                # case we find the data in a VMA region but not parseable
                # in most cases this is due to a copy of it. But realistically it is not the information 
                # some would want to look for.
                yield "INVALID_STRUCTURE", offset
                continue

            endianess = data[15] & 2

            endian = ""
            if endianess == 0:
                golog.info("Little-endian program.")
                endian = "<"
            else:
                endian = ">"

            golog.info(f"offset: {hex(offset)}")
            golog.debug(f"Start_data: {data}")
            golog.debug(f"len: {len(data[16+pointer_size:16+(pointer_size*2)])}")
            runtime_buildver_addr = struct.unpack(f"{endian}Q", data[16:16+pointer_size])[0]
            runtime_modinfo_addr = struct.unpack(f"{endian}Q", data[16+pointer_size:16+(pointer_size*2)])[0]

            golog.debug(f"Pointer size: {pointer_size}")
            golog.debug(f"runtime.buildversion ptr: {hex(runtime_buildver_addr)}")
            golog.debug(f"runtime.modinfo ptr: {hex(runtime_modinfo_addr)}")

            # go buildver
            go_build_data = proc_layer.read(runtime_buildver_addr, 0xff)
            go_version = self.check_go_version(pointer_size, endian, go_build_data, proc_layer)

            yield go_version, offset



    def _generator(self, tasks):
        use_regex = self.config.get('regex')

        for task in tasks:
            if not task.mm:
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]
            golog.debug(proc_layer_name)


            pid = task.pid
            comm = utility.array_to_string(task.comm)
            golog.debug(f"PID:{pid} COMM:{comm}")

            for go_version, offset in self.enum_task_struct(task, proc_layer, use_regex):
                yield (0, (task.pid, comm, go_version, format_hints.Hex(offset)))
                