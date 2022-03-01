from asyncio.proactor_events import constants
from typing import List

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
import logging


# TODO change all infos to the proper name for production to debug =)
golog = logging.getLogger(__name__)

class Go(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    _32BIT = False
    _ARCH = "intel"

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

    def run(self):
        golog.info("Plugin is now Starting to Run!")

        filter_func = pslist.PsList.create_pid_filter(
            self.config.get('pid', None)
        )

        list_procs = pslist.PsList.list_tasks(
            self.context,
            self.config['kernel'],
            filter_func=filter_func
        )
        
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),

                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                ("Flags", str),
                ("PgOff", format_hints.Hex), 
                ("Major", int), 
                ("Minor", int), 
                ("Inode", int),
                ("File Path", str),

            ],
            generator=self._generator(list_procs)
        )



    def _check_arch(self, task):
        vmlinux = self.context.modules[self.config['kernel']]
        if self.context.symbol_space.get_type(vmlinux.symbol_table_name + constants.BANG + "pointer").size == 4:
            self._is32bit = True
        




    def _generator(self, tasks):
        PROC_NAME = self.config.get('procName')
        for task in tasks:
            golog.info(task)

            if not task.mm:
                continue

            process_name = utility.array_to_string(task.comm)

            if PROC_NAME is not None:
                if process_name not in PROC_NAME:
                    continue
                
            pid = task.pid
            # This code is pulled from https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/linux/proc.py
            # Used inline because less dependencies & wanted to modify usage.
            for vma in task.mm.get_mmap_iter():
                golog.info(vma)

                flags = vma.get_protection()
                page_offset = vma.get_page_offset()
                major = 0
                minor = 0
                inode = 0

                if vma.vm_file != 0:
                    dentry = vma.vm_file.get_dentry()
                    if dentry != 0:
                        inode_object = dentry.d_inode
                        major = inode_object.i_sb.major
                        minor = inode_object.i_sb.minor
                        inode = inode_object.i_ino

                if not self._32BIT:
                    self._ARCH = "intel64"

                path = vma.get_name(self.context, task)

                
                yield (0, (pid, process_name, 
                        format_hints.Hex(vma.vm_start), 
                        format_hints.Hex(vma.vm_end), flags,
                        format_hints.Hex(page_offset), 
                        major, minor, inode, path
                        )
                    )