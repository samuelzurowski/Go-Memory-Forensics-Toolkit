from typing import List, Callable, Any, Tuple
import logging, struct, binascii

from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners, intel
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, vadinfo

from volatility3.framework.symbols.windows.extensions import EPROCESS


golog = logging.getLogger(__name__)



class GoHunt(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    _32BIT = False

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name='kernel', 
                description='Windows kernel',
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
            requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.PluginRequirement(name='vadinfo', plugin=vadinfo.VadInfo, version=(2, 0, 0))
        ]

    def check_go_version(self, pointer_size, endian, go_build_data: bytes, proc_layer) -> str:
        golog.debug(f"VER: {go_build_data}")
        # get string of go version
        go_ver_ptr = struct.unpack(f"{endian}Q",go_build_data[:pointer_size])[0]

        if not go_ver_ptr:
            return "VERSION_NUM_NOT_FOUND"
        go_versioninfo_data = proc_layer.read(go_ver_ptr, 0xff)
        golog.debug(f"Version info: {go_versioninfo_data}")
        
        return go_versioninfo_data.split(b'\x00')[0].decode()



    def run(self):
        golog.info("Plugin is now Starting to Run!")
        kernel = self.context.modules[self.config['kernel']]
        

        list_procs = pslist.PsList.list_processes(
            self.context,
            kernel.layer_name,
            kernel.symbol_table_name,
            filter_func=pslist.PsList.create_pid_filter(self.config.get('pid', None))
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


    def _generator(self, procs):
        use_regex = self.config.get('regex')
        for proc in procs:
          

            proc_layer_name = proc.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]
            golog.debug(proc_layer_name)


            pid = proc.UniqueProcessId
            process_name = utility.array_to_string(proc.ImageFileName)
            golog.debug(f"PID:{pid} Name:{process_name}")
            

                        #     yield (0, (proc.UniqueProcessId, process_name, format_hints.Hex(vad.vol.offset),
                        #    format_hints.Hex(vad.get_start()), format_hints.Hex(vad.get_end()), vad.get_tag(),
                        #    vad.get_protection(
                        #        self.protect_values(self.context, kernel.layer_name, kernel.symbol_table_name),
                        #        winnt_protections), vad.get_commit_charge(), vad.get_private_memory(),
                        #    format_hints.Hex(vad.get_parent()), vad.get_file_name(), file_output))

            vad_regions = []
            for vad in vadinfo.VadInfo.list_vads(proc): 
                vad_start = vad.get_start()
                vad_end = vad.get_end()
                vad_regions.append((vad_start, vad_end-vad_start))
                # golog.debug(f"\tStart:{vad_start} End: {vad_end}")

            for offset in proc_layer.scan(
                context=self.context,
                scanner=scanners.BytesScanner(b"\xff Go buildinf:"),
                sections=vad_regions
            ):
                phy_addr, layer_name = proc_layer.translate(offset)
                golog.info(f"PHY: {hex(phy_addr)}")
                data = proc_layer.read(offset, 0xfff)

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
                runtime_buildver_addr = struct.unpack(f"{endian}Q", data[16:16+pointer_size])[0]
                runtime_modinfo_addr = struct.unpack(f"{endian}Q", data[16+pointer_size:16+(pointer_size*2)])[0]

                golog.debug(f"Pointer size: {pointer_size}")
                golog.debug(f"runtime.buildversion ptr: {hex(runtime_buildver_addr)}")
                golog.debug(f"runtime.modinfo ptr: {hex(runtime_modinfo_addr)}")

                # go buildver
                go_build_data = proc_layer.read(runtime_buildver_addr, 0xff, pad=True)
                golog.debug(go_build_data)
                go_version = self.check_go_version(pointer_size, endian, go_build_data, proc_layer)
                yield (0, (pid, process_name, go_version, format_hints.Hex(offset)))
            #for go_version, offset in self.enum_task_struct(task, proc_layer, use_regex):
               # yield (0, (task.pid, comm, go_version, format_hints.Hex(offset)))
                