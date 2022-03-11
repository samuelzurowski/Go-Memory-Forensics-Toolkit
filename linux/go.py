from typing import List, Callable, Any, Tuple
import logging, struct, binascii
from magic import version

from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners, intel
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
from volatility3.framework.symbols import linux

from volatility3.framework.symbols.linux.extensions import task_struct
from volatility3.plugins import yarascan

from volatility3.framework import exceptions
import yara

# TODO change all infos to the proper name for production to debug =)
# https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/symbols/linux/extensions/__init__.py
golog = logging.getLogger(__name__)

class Go(interfaces.plugins.PluginInterface):
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
                optional=True
            ),
            requirements.ListRequirement(
                name='procName',
                element_type=str,
                description='Proc name',
                optional=True
            )
        ]

    @classmethod
    def proc_name_filter(cls, pid_name_list: List[str] = None) -> Callable[[Any], bool]:
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
                return utility.array_to_string(x.comm) not in filter_list

            return filter_func
        else:
            return lambda _: False # this means no filter

    def run(self):
        golog.info("Plugin is now Starting to Run!")

        filter_func = self.proc_name_filter(
            self.config.get('procName')
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
                ("GO_VERSION", str)

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


    def get_go_metadata(self, scanner: interfaces.layers.ScannerInterface, proc_layer: intel.Intel, sections: List[Tuple]) -> str:
        hit_counter = 0
        metadata = ""

        for offset in proc_layer.scan(
            context=self.context,
            scanner=scanner,
            sections=sections
        ):

            data = proc_layer.read(offset, 0xff, pad=True)

            data_index = data.find(b'\x00')

            if data_index > 0:
                golog.debug(data[:data_index].strip())

                metadata = data[:data_index].decode()
                hit_counter += 1
            
            if hit_counter > 2:
                return ""
        
        if hit_counter < 2:
            return metadata

        return ""

    def enum_task_struct(self, task: task_struct, proc_layer: intel.Intel) -> str:

        golog.info(f"PROC ID: {task.pid}")

        vma_regions = []
        for vma in task.mm.get_mmap_iter():
            vm_start = vma.vm_start
            vm_end   = vma.vm_end

            vma_regions.append((vm_start, vm_end-vm_start))

        go_version = self.get_go_metadata(
            scanner=scanners.RegExScanner(rb"go[0-9]+\.[0-9]+\.[0-9]+[^.\s]+"),
            proc_layer=proc_layer,
            sections=vma_regions
        )

        # if go_version != "":
        #     for offset in proc_layer.scan(
        #         context=self.context,
        #         scanner=scanners.RegExScanner(rb"[A-Za-z\/_.0-9]+.go"),
        #         sections=vma_regions
        #     ):

        #         data = proc_layer.read(offset, 0xff)
        #         golog.debug(data.decode(errors='ignore'))


        return go_version


    def _generator(self, tasks):
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

            go_version = self.enum_task_struct(task, proc_layer)

            if go_version == "":
                continue

            yield (0, (task.pid, comm, go_version))

                