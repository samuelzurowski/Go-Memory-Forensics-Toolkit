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
            )
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
                ("OFFSET", format_hints.Hex)
            ],
            generator=self._generator(list_procs)
        )
    def get_go_metadata(self, scanner: interfaces.layers.ScannerInterface, proc_layer: intel.Intel, sections: List[Tuple]):
        hit_counter = 0
        metadata = ""
        hit_addrs = []

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
                hit_addrs.append(offset)
            
            if hit_counter > 2:
                return "", []

        return metadata, hit_addrs

    def enum_task_struct(self, task: task_struct, proc_layer: intel.Intel) -> str:
        
        golog.debug(f"PROC ID: {task.pid}")

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


            pid = task.pid
            comm = utility.array_to_string(task.comm)
            golog.debug(f"PID:{pid} COMM:{comm}")

            go_version, offsets = self.enum_task_struct(task, proc_layer)

            for offset in offsets:

                yield (0, (task.pid, comm, go_version, format_hints.Hex(offset)))

                