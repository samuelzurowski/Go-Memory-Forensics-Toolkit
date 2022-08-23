from posixpath import split
from typing import List, Callable, Any, Tuple
import logging, struct, binascii, re

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
            # requirements.BooleanRequirement(name='regex',
            #     description="Attempt to find a go version with regex.",
            #     default=False,
            #     optional=True
            # ),
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 1, 0))
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
                ("Go Build ID", str),
                ("VIRTUAL OFFSET", format_hints.Hex)
            ],
            generator=self._generator(list_procs)
        )


    def enum_task_struct(self, task: task_struct, proc_layer: intel.Intel, use_regex: bool) -> str:
        
        golog.debug(f"PROC ID: {task.pid}")

        go_build_id = ""
        # get all the VMA regions to search through.

        for offset in proc_layer.scan(
            context=self.context,
            scanner=scanners.BytesScanner(b"Go build ID: \"")
            # sections=vma_regions
        ):
            golog.debug(f'Build info addr: {hex(offset)}')
            data = proc_layer.read(offset, 0xff).decode()

            go_build_id = data.split("\"")[1]
            golog.debug(go_build_id)



            yield go_build_id, offset



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



            for go_build, offset in self.enum_task_struct(task, proc_layer, use_regex):

                """
                // 1. The action ID half allows installed packages and binaries to serve as
                // one-element cache entries. If we intend to build math.a with a given
                // set of inputs summarized in the action ID, and the installed math.a already
                // has that action ID, we can reuse the installed math.a instead of rebuilding it.

                // 2. The content ID half allows the easy preparation of action IDs for steps
                // that consume a particular package or binary. The content hash of every
                // input file for a given action must be included in the action ID hash.
                // Storing the content ID in the build ID lets us read it from the file with
                // minimal I/O, instead of reading and hashing the entire file.
                // This is especially effective since packages and binaries are typically
                // the largest inputs to an action.

                //	actionID(binary)/actionID(main.a)/contentID(main.a)/contentID(binary)
                """

                yield (0, (go_build, format_hints.Hex(offset)))
            break